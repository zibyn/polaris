package management_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/zibyn/polaris/internal/oidcstore"
)

func jwk(t *testing.T, key any, kid string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKey{Key: key, KeyID: kid})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func jwks(keys ...map[string]any) map[string]any {
	return map[string]any{"keys": append([]map[string]any{}, keys...)}
}

// TestSwitchClientAuthnMethod covers 客户端认证方式 and Application 公钥
// (ADR 0023): keys are registered first, apart from the method; switching to
// private_key_jwt drops the secret, switching back issues a new one.
func TestSwitchClientAuthnMethod(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	e.call("PUT", owner, apiPath(track), map[string]any{"name": "Track"}, nil)
	var created struct {
		Application struct{ ClientID, TokenAuthMethod string }
		Secret      string
	}
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "m2m", "settings": m2mSettings(track)}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	if created.Application.TokenAuthMethod != "client_secret_basic" {
		t.Errorf("a new Application authenticates with %q", created.Application.TokenAuthMethod)
	}
	path := "/applications/" + created.Application.ClientID
	switchTo := func(method string, out any) int {
		return e.call("POST", owner, path+"/auth-method", map[string]any{"method": method}, out)
	}
	withJWKS := func(set any) map[string]any {
		s := m2mSettings(track)
		s["jwks"] = set
		return s
	}
	type app struct {
		TokenAuthMethod string
		JWKS            struct{ Keys []map[string]any }
	}
	read := func() app {
		var a app
		if code := e.get(owner, path, &a); code != 200 {
			t.Fatalf("read: %d", code)
		}
		return a
	}
	secretWorks := func(secret string) bool {
		var hash string
		_ = e.pool.QueryRow(t.Context(), "SELECT COALESCE(encode(secret_hash, 'hex'), '') FROM applications WHERE client_id = $1", created.Application.ClientID).Scan(&hash)
		return oidcstore.VerifyClientSecret(t.Context(), hash, secret) == nil
	}

	// No key registered yet.
	if code := switchTo("private_key_jwt", nil); code != 409 {
		t.Errorf("switch without a key: %d, want 409", code)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point: too small
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	six := []map[string]any{}
	for i := range 6 {
		six = append(six, jwk(t, ecKey.Public(), fmt.Sprint(i)))
	}
	for name, set := range map[string]any{
		"not a JWKS":      "nope",
		"no keys member":  map[string]any{},
		"a private key":   jwks(jwk(t, rsaKey, "k1")),
		"no kid":          jwks(jwk(t, rsaKey.Public(), "")),
		"a repeated kid":  jwks(jwk(t, rsaKey.Public(), "k1"), jwk(t, ecKey.Public(), "k1")),
		"RSA 1024":        jwks(jwk(t, small.Public(), "k1")),
		"EC P-384":        jwks(jwk(t, p384.Public(), "k1")),
		"a symmetric key": jwks(jwk(t, []byte("a-shared-key-of-thirty-two-bytes"), "k1")),
		"six keys":        map[string]any{"keys": six},
	} {
		if code := e.call("PUT", owner, path, withJWKS(set), nil); code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}

	// Registering keys switches nothing.
	if code := e.call("PUT", owner, path, withJWKS(jwks(jwk(t, rsaKey.Public(), "k1"), jwk(t, ecKey.Public(), "k2"))), nil); code != 204 {
		t.Fatalf("register keys: %d", code)
	}
	if a := read(); a.TokenAuthMethod != "client_secret_basic" || len(a.JWKS.Keys) != 2 || a.JWKS.Keys[1]["kid"] != "k2" {
		t.Errorf("after registering: %+v", a)
	}
	if !secretWorks(created.Secret) {
		t.Errorf("registering keys broke the secret")
	}
	// Settings saved without jwks keep the keys.
	if code := e.call("PUT", owner, path, m2mSettings(track), nil); code != 204 || len(read().JWKS.Keys) != 2 {
		t.Errorf("save without jwks: %d %+v", code, read())
	}

	// To private_key_jwt: the secret is gone, and cannot be reset.
	var out map[string]any
	if code := switchTo("private_key_jwt", &out); code != 200 || out["secret"] != nil {
		t.Fatalf("switch to private_key_jwt: %d %v", code, out)
	}
	if read().TokenAuthMethod != "private_key_jwt" || secretWorks(created.Secret) {
		t.Errorf("after switching, the secret still works or the method did not change: %+v", read())
	}
	if code := e.call("POST", owner, path+"/secret", nil, nil); code != 409 {
		t.Errorf("reset the secret under private_key_jwt: %d, want 409", code)
	}
	// Its keys cannot be emptied while they are its only way in.
	if code := e.call("PUT", owner, path, withJWKS(jwks()), nil); code != 422 {
		t.Errorf("empty the keys under private_key_jwt: %d, want 422", code)
	}

	// Back to client_secret_basic: a new secret, shown once, that works; the
	// keys stay.
	var back struct{ Secret string }
	if code := switchTo("client_secret_basic", &back); code != 200 || back.Secret == "" {
		t.Fatalf("switch back: %d %+v", code, back)
	}
	if a := read(); a.TokenAuthMethod != "client_secret_basic" || len(a.JWKS.Keys) != 2 || !secretWorks(back.Secret) {
		t.Errorf("after switching back: %+v", a)
	}
	// Now the keys may be emptied.
	if code := e.call("PUT", owner, path, withJWKS(jwks()), nil); code != 204 || len(read().JWKS.Keys) != 0 {
		t.Errorf("empty the keys: %d", code)
	}

	// Public and built-in Applications have no say.
	var pub struct {
		Application struct{ ClientID, TokenAuthMethod string }
	}
	pubSettings := map[string]any{"name": "App", "redirectUris": []string{"com.example:/cb"}, "postLogoutRedirectUris": []string{},
		"refreshTokens": true, "appleAppIds": []string{}, "androidApps": []any{}}
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "public", "settings": pubSettings}, &pub); code != 200 || pub.Application.TokenAuthMethod != "none" {
		t.Fatalf("create public: %d %+v", code, pub)
	}
	for _, id := range []string{pub.Application.ClientID, "polaris-console"} {
		if code := e.call("POST", owner, "/applications/"+id+"/auth-method", map[string]any{"method": "client_secret_basic"}, nil); code != 409 {
			t.Errorf("switch %s: %d, want 409", id, code)
		}
	}
	pubSettings["jwks"] = jwks(jwk(t, ecKey.Public(), "k1"))
	if code := e.call("PUT", owner, "/applications/"+pub.Application.ClientID, pubSettings, nil); code != 422 {
		t.Errorf("keys on a public Application: %d, want 422", code)
	}
}
