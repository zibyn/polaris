package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/provider"
	_ "github.com/zibyn/polaris/internal/provider/oidc"
	"github.com/zibyn/polaris/internal/provider/oidc/oidctest"
)

func newUpstream(t *testing.T, iss string) provider.Redirect {
	t.Helper()
	p, err := provider.GetType("oidc").New(map[string]string{"issuer": iss, "client_id": "cid", "client_secret": "shh"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuthURLAsksForOpenIDOnlyWithPKCE(t *testing.T) {
	up := oidctest.Start(t)
	to, err := newUpstream(t, up.URL).AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	q := u.Query()
	sum := sha256.Sum256([]byte("verifier"))
	if !strings.HasPrefix(to, up.URL+"/auth?") || q.Get("scope") != "openid" || q.Get("state") != "st" || q.Get("nonce") != "n" ||
		q.Get("client_id") != "cid" || q.Get("redirect_uri") != "https://auth.example/cb" || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("auth URL: %s", to)
	}
}

func TestDiscoveryMustBeTheConfiguredIssuer(t *testing.T) {
	up := oidctest.Start(t)
	up.Reported = "https://evil.example"
	if _, err := newUpstream(t, up.URL).AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier"); err == nil {
		t.Fatal("took the endpoints of another issuer")
	}
}

func TestCallbackChecksTheIDToken(t *testing.T) {
	for name, tc := range map[string]struct {
		claims map[string]any
		drop   []string
		params url.Values
		signIn bool
	}{
		"good":           {signIn: true},
		"wrong issuer":   {claims: map[string]any{"iss": "https://evil.example"}},
		"wrong audience": {claims: map[string]any{"aud": "other"}},
		"expired":        {claims: map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}},
		"no exp":         {drop: []string{"exp"}},
		"wrong nonce":    {claims: map[string]any{"nonce": "other"}},
		"azp not us":     {claims: map[string]any{"aud": []string{"cid", "other"}, "azp": "other"}},
		"bad code":       {params: url.Values{"code": {"bad"}}},
		"error":          {params: url.Values{"error": {"access_denied"}}},
		"another issuer": {params: url.Values{"code": {"good"}, "iss": {"https://evil.example"}}},
	} {
		t.Run(name, func(t *testing.T) {
			up := oidctest.Start(t) // discovery is remembered per issuer: one fake per case
			up.Claims, up.Drop = tc.claims, tc.drop
			params := tc.params
			if params == nil {
				params = url.Values{"code": {"good"}}
			}
			id, err := newUpstream(t, up.URL).Callback(context.Background(), params, "https://auth.example/cb", "n", "verifier")
			oidctest.CheckSignIn(t, id, err, tc.signIn)
		})
	}
}
