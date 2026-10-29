package login_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zibyn/polaris/internal/oidcstore"
)

// usePrivateKeyJWT registers pub under kid as the Application's only key and
// switches it to private_key_jwt, the way the Management API leaves it: no
// secret.
func (e *env) usePrivateKeyJWT(client, kid string, pub crypto.PublicKey) {
	e.t.Helper()
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Use: "sig"}}})
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE applications SET jwks = $2, token_auth_method = 'private_key_jwt', secret_hash = NULL WHERE client_id = $1`,
		client, jwks); err != nil {
		e.t.Fatal(err)
	}
}

// assertion is a client assertion (RFC 7523) for the token endpoint.
func (e *env) assertion(client, kid string, alg jose.SignatureAlgorithm, key any) string {
	e.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		e.t.Fatal(err)
	}
	now := time.Now()
	s, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: client, Subject: client, Audience: jwt.Audience{e.issuer + "/token"},
		ID: rand.Text(), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
	}).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func withAssertion(form url.Values, assertion string) url.Values {
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return form
}

func wantInvalidClient(t *testing.T, what string, resp *http.Response, body string) {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &e)
	if resp.StatusCode != 401 || e.Error != "invalid_client" {
		t.Errorf("%s: %d %s", what, resp.StatusCode, body)
	}
}

// An M2M Application switched to private_key_jwt gets its token with an
// assertion signed by a registered key; its old secret no longer works
// (ADR 0023).
func TestClientCredentialsWithPrivateKeyJWT(t *testing.T) {
	e := start(t)
	const trackAPI = "https://track.example"
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO apis (identifier, name) VALUES ($1, 'Track')`, trackAPI); err != nil {
		t.Fatal(err)
	}
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "batch", Name: "对账任务", Type: "m2m", Secret: "m2m-secret", DefaultAPI: trackAPI,
	}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e.usePrivateKeyJWT("batch", "k1", key.Public())
	cc := func() url.Values { return url.Values{"grant_type": {"client_credentials"}, "client_id": {"batch"}} }

	resp, body := e.do("POST", "/token", withAssertion(cc(), e.assertion("batch", "k1", jose.RS256, key)))
	var tok tokens
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil || tok.AccessToken == "" {
		t.Fatalf("private_key_jwt: %d %s", resp.StatusCode, body)
	}
	if at := e.claims(tok.AccessToken); at["sub"] != "batch" || at["aud"] != trackAPI {
		t.Errorf("claims: %v", at)
	}

	u, _ := url.Parse(e.issuer)
	u.User = url.UserPassword("batch", "m2m-secret")
	u.Path = "/token"
	resp, body = e.do("POST", u.String(), cc())
	wantInvalidClient(t, "the old secret", resp, body)

	// A kid not registered, and algorithms other than RS256 and ES256.
	resp, body = e.do("POST", "/token", withAssertion(cc(), e.assertion("batch", "other", jose.RS256, key)))
	wantInvalidClient(t, "unknown kid", resp, body)
	resp, body = e.do("POST", "/token", withAssertion(cc(), e.assertion("batch", "k1", jose.PS256, key)))
	wantInvalidClient(t, "PS256", resp, body)
	resp, body = e.do("POST", "/token", withAssertion(cc(), e.assertion("batch", "k1", jose.HS256, []byte("a-shared-key-of-thirty-two-bytes!"))))
	wantInvalidClient(t, "HS256", resp, body)

	// The same assertion is good once.
	a := e.assertion("batch", "k1", jose.RS256, key)
	if resp, body := e.do("POST", "/token", withAssertion(cc(), a)); resp.StatusCode != 200 {
		t.Fatalf("fresh assertion: %d %s", resp.StatusCode, body)
	}
	resp, body = e.do("POST", "/token", withAssertion(cc(), a))
	wantInvalidClient(t, "a replayed assertion", resp, body)
}

// A Web Application switched to private_key_jwt redeems its authorization
// code with an ES256 assertion.
func TestAuthCodeWithPrivateKeyJWT(t *testing.T) {
	e := start(t)
	const web = "https://web.example/cb"
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "web", Name: "Web", Secret: "web-secret", RedirectURIs: []string{web},
	}); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.usePrivateKeyJWT("web", "ec", key.Public())
	e.bootstrap("owner", "password1")

	_, page := e.authorizeAs("web", web, "")
	resp, _ := e.submit(page, "owner", "password1")
	resp, body := e.do("POST", "/token", withAssertion(url.Values{
		"grant_type": {"authorization_code"}, "code": {e.code(resp)}, "redirect_uri": {web},
		"client_id": {"web"}, "code_verifier": {verifier},
	}, e.assertion("web", "ec", jose.ES256, key)))
	var tok tokens
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil || tok.IDToken == "" {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	if id := e.claims(tok.IDToken); id["aud"] != "web" {
		t.Errorf("id token: %v", id)
	}
}

func TestDiscoveryAdvertisesPrivateKeyJWT(t *testing.T) {
	e := start(t)
	_, body := e.do("GET", "/.well-known/openid-configuration", nil)
	var meta struct {
		Methods []string `json:"token_endpoint_auth_methods_supported"`
		Algs    []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	}
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(meta.Methods, "private_key_jwt") || !slices.Contains(meta.Methods, "client_secret_basic") ||
		!slices.Equal(meta.Algs, []string{"RS256", "ES256"}) {
		t.Errorf("discovery: %s", body)
	}
}
