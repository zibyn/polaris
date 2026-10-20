package google_test

import (
	"context"
	"net/url"
	"slices"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/google"
	"github.com/zibyn/polaris/internal/provider/oidc/oidctest"
)

// TestGoogleAsksForCredentialsOnly: the issuer and the brand are in the
// type, so the admin only brings the client's credentials.
func TestGoogleAsksForCredentialsOnly(t *testing.T) {
	var keys []string
	for _, f := range provider.GetType("google").Fields {
		keys = append(keys, f.Key)
	}
	if !slices.Equal(keys, []string{"client_id", "client_secret"}) {
		t.Errorf("fields: %v", keys)
	}
}

// TestGoogleTakesEitherIssuerForm: Google documents both forms for the
// id_token's iss, and nothing else is Google.
func TestGoogleTakesEitherIssuerForm(t *testing.T) {
	for name, tc := range map[string]struct {
		reported func(issuer string) string
		signIn   bool
	}{
		"the issuer it points at":          {reported: func(issuer string) string { return issuer }, signIn: true},
		"schemeless, as Google also sends": {reported: func(string) string { return "accounts.google.com" }, signIn: true},
		"somewhere else":                   {reported: func(string) string { return "https://evil.example" }},
	} {
		t.Run(name, func(t *testing.T) {
			up := oidctest.Start(t)
			google.Issuer = up.URL // stands in for https://accounts.google.com
			t.Cleanup(func() { google.Issuer = "https://accounts.google.com" })
			up.Reported = tc.reported(up.URL)
			p, err := provider.GetType("google").New(map[string]string{"client_id": "cid", "client_secret": "shh"})
			if err != nil {
				t.Fatal(err)
			}
			id, err := p.Callback(context.Background(), url.Values{"code": {"good"}}, "https://auth.example/cb", "n", "verifier")
			oidctest.CheckSignIn(t, id, err, tc.signIn)
		})
	}
}
