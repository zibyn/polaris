package polaris_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	api      = "https://api.example.com"
	clientID = "web-app"
)

// fakeOP serves discovery and a JWKS, and signs tokens shaped like Polaris's
// (docs/spec/protocol.md, 令牌 and Back-Channel Logout).
type fakeOP struct {
	*httptest.Server
	mu  sync.Mutex
	key jose.JSONWebKey // current signing key
}

func newKey(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: k, KeyID: kid, Algorithm: "RS256", Use: "sig"}
}

func startFakeOP(t *testing.T) *fakeOP {
	op := &fakeOP{key: newKey(t, "k1")}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                op.URL,
			"jwks_uri":                              op.URL + "/jwks",
			"authorization_endpoint":                op.URL + "/authorize",
			"token_endpoint":                        op.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		op.mu.Lock()
		defer op.mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{op.key.Public()}})
	})
	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)
	return op
}

// rotate replaces the signing key; the JWKS then serves only the new one.
func (op *fakeOP) rotate(t *testing.T) {
	k := newKey(t, "k2")
	op.mu.Lock()
	op.key = k
	op.mu.Unlock()
}

func (op *fakeOP) sign(t *testing.T, typ string, claims map[string]any, key *jose.JSONWebKey) string {
	t.Helper()
	if key == nil {
		op.mu.Lock()
		k := op.key
		op.mu.Unlock()
		key = &k
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: *key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// accessToken signs an at+jwt for api; set overrides or removes (nil) claims.
func (op *fakeOP) accessToken(t *testing.T, set map[string]any) string {
	now := time.Now().Unix()
	c := map[string]any{
		"iss": op.URL, "aud": api, "sub": "user-1", "client_id": clientID,
		"iat": now, "exp": now + 600, "entitlements": []string{"orders:read"},
	}
	typ := "at+jwt"
	for k, v := range set {
		if k == "typ" {
			typ = v.(string)
			continue
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return op.sign(t, typ, c, nil)
}

// logoutToken signs a logout+jwt for clientID; set overrides or removes (nil) claims.
func (op *fakeOP) logoutToken(t *testing.T, set map[string]any) string {
	now := time.Now().Unix()
	c := map[string]any{
		"iss": op.URL, "aud": clientID, "sub": "user-1", "sid": "sess-1",
		"iat": now, "exp": now + 120, "jti": "j1",
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	typ := "logout+jwt"
	for k, v := range set {
		if k == "typ" {
			typ = v.(string)
			continue
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return op.sign(t, typ, c, nil)
}
