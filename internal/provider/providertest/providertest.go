// Package providertest runs an OpenID Provider in the test's process,
// standing in for an upstream such as Google.
package providertest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zibyn/polaris/internal/oidc/goidc"
	oidcop "github.com/zibyn/polaris/internal/oidc/provider"
)

// Upstream signs whoever the browser is in as Sub, with no questions asked.
// Set its fields between requests.
type Upstream struct {
	Issuer string
	Sub    string
	// AuthTime, when set, is the id_token's auth_time (Unix seconds).
	AuthTime int64
	// Last is what the latest authorization request asked for.
	Last goidc.AuthorizationParameters
}

// Start runs an Upstream with the client "upstream" (secret "shh") that may
// redirect to redirectURI.
func Start(t *testing.T, redirectURI string) *Upstream {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	up := &Upstream{Issuer: "http://" + ts.Listener.Addr().String(), Sub: "google-user-1"}
	op, err := oidcop.New(
		oidcop.Config{
			Issuer: up.Issuer,
			JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
				return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}, nil
			},
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
		},
		oidcop.WithStaticClients(&goidc.Client{ID: "upstream", Secret: "shh", ClientMeta: goidc.ClientMeta{
			RedirectURIs: []string{redirectURI}, TokenAuthnMethod: goidc.AuthnMethodSecretBasic,
			GrantTypes: []goidc.GrantType{goidc.GrantAuthorizationCode}, ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			ScopeIDs: "openid",
		}}),
		oidcop.WithScopes(goidc.ScopeOpenID),
		oidcop.WithSecretBasicAuthn(),
		oidcop.WithIDTokenClaims(func(context.Context, *goidc.Grant) map[string]any {
			if up.AuthTime == 0 {
				return map[string]any{}
			}
			return map[string]any{goidc.ClaimAuthTime: up.AuthTime}
		}),
		oidcop.WithAuthCodeGrant(
			oidcop.AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			oidcop.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}, oidcop.WithPKCERequired()),
			oidcop.WithAuthPolicies(goidc.NewPolicy("anyone",
				func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { return true },
				func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					up.Last = as.AuthorizationParameters
					as.Subject, as.GrantedScopes = up.Sub, as.Scopes
					return goidc.StatusSuccess, nil
				})),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = op.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return up
}
