// Package oidctest runs an OIDC upstream in the test's process, standing in
// for an upstream such as Google or Microsoft: it answers discovery, the
// JWKS and a token endpoint, signing the id_token its fields ask for.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zibyn/polaris/internal/provider"
)

// sub is the user the fake signs everyone in as.
const sub = "u1"

// CheckSignIn fails t unless a callback against the fake ended the way the
// case expected: sub signed in, or the token was refused.
func CheckSignIn(t *testing.T, id provider.Identity, err error, signIn bool) {
	t.Helper()
	switch {
	case err != nil && signIn:
		t.Fatalf("refused: %v", err)
	case err == nil && !signIn:
		t.Fatalf("accepted: %+v", id)
	case err == nil && id.Subject != sub:
		t.Fatalf("subject: %+v", id)
	}
}

// Issuer is a fake upstream. Set its fields between requests, before the
// request that should see the change.
type Issuer struct {
	// URL is where it listens: point the Provider type's endpoint variable
	// at it.
	URL string
	// Reported is the issuer its discovery and id_tokens name. It defaults
	// to URL, and is set apart from it where an upstream names itself
	// something else (Microsoft's common reports a tenant template).
	Reported string
	// Claims are the id_token's, over the iss, sub, aud, exp, iat and nonce
	// Start fills in.
	Claims map[string]any
	// Drop are claims to leave out of the id_token.
	Drop []string
}

// Start runs a fake Issuer for the client "cid" (secret "shh"), which
// exchanges the code "good" with the PKCE verifier "verifier" and refuses
// anything else.
func Start(t *testing.T) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	up := &Issuer{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": up.issuer(), "authorization_endpoint": up.URL + "/auth",
				"token_endpoint": up.URL + "/token", "jwks_uri": up.URL + "/jwks",
			})
		case r.URL.Path == "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		case r.URL.Path == "/token":
			id, secret, _ := r.BasicAuth()
			if id != "cid" || secret != "shh" || r.PostFormValue("code_verifier") != "verifier" || r.PostFormValue("code") != "good" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, nil)
			tok, _ := jwt.Signed(signer).Claims(up.idToken()).Serialize()
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": tok, "access_token": "x", "token_type": "Bearer"})
		}
	}))
	t.Cleanup(ts.Close)
	up.URL = ts.URL
	return up
}

// issuer is what the upstream names itself.
func (u *Issuer) issuer() string {
	if u.Reported != "" {
		return u.Reported
	}
	return u.URL
}

// idToken is the claims the token endpoint signs.
func (u *Issuer) idToken() map[string]any {
	c := map[string]any{"iss": u.issuer(), "sub": sub, "aud": "cid",
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": "n"}
	for k, v := range u.Claims {
		c[k] = v
	}
	for _, k := range u.Drop {
		delete(c, k)
	}
	return c
}
