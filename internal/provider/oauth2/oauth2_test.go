package oauth2_test

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	_ "github.com/zibyn/polaris/internal/provider/oauth2"
	"github.com/zibyn/polaris/internal/provider/oauth2/oauth2test"
)

// newOAuth2 builds a generic OAuth2 Provider at the fake, with config as
// overrides of the fake's own.
func newOAuth2(t *testing.T, f *oauth2test.Fake, config map[string]string) provider.Redirect {
	t.Helper()
	c := f.Config()
	for k, v := range config {
		c[k] = v
	}
	p, err := provider.GetType("oauth2").New(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// signIn is the User signing the browser in at the Provider: AuthURL, then
// the fake's authorization endpoint, then the callback it sent it back to.
func signIn(t *testing.T, f *oauth2test.Fake, p provider.Redirect) (provider.Identity, error) {
	t.Helper()
	authURL, err := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	return p.Callback(context.Background(), f.SignIn(authURL), "https://auth.example/cb", "n", "verifier")
}

// The upstream is asked for a code with PKCE and state, and nothing it does
// not have: no nonce, no prompt, no max_age (ADR 0013).
func TestOAuth2AsksForACode(t *testing.T) {
	f := oauth2test.Start(t)
	p := newOAuth2(t, f, nil)
	authURL, err := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("authURL %q: %v", authURL, err)
	}
	q := u.Query()
	if u.Path != "/authorize" || q.Get("response_type") != "code" || q.Get("client_id") != oauth2test.ClientID ||
		q.Get("redirect_uri") != "https://auth.example/cb" || q.Get("state") != "st" ||
		q.Get("scope") != "read:user" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Has("nonce") || q.Has("prompt") || q.Has("max_age") {
		t.Errorf("authorization request: %s", authURL)
	}
}

// Who signed in is the user ID field of userinfo, as a string: GitHub's id
// is a number, and it keeps every digit.
func TestOAuth2SubjectIsTheUserIDField(t *testing.T) {
	for name, tc := range map[string]struct {
		userinfo map[string]any
		subject  string
	}{
		"a number, as GitHub's id is": {userinfo: map[string]any{"id": 42, "login": "octocat"}, subject: "42"},
		"a string":                    {userinfo: map[string]any{"id": "u-42"}, subject: "u-42"},
		"a number too big for a float64": {
			userinfo: map[string]any{"id": int64(9007199254740993)}, subject: "9007199254740993"},
	} {
		t.Run(name, func(t *testing.T) {
			f := oauth2test.Start(t)
			f.Userinfo = tc.userinfo
			id, err := signIn(t, f, newOAuth2(t, f, nil))
			if err != nil {
				t.Fatal(err)
			}
			if id.Subject != tc.subject || !id.AuthTime.IsZero() || id.Token != "" {
				t.Errorf("signed in as %+v, want subject %q", id, tc.subject)
			}
		})
	}
}

// Both requests the upstream is given say JSON: GitHub answers form-encoded
// otherwise.
func TestOAuth2AsksForJSON(t *testing.T) {
	f := oauth2test.Start(t)
	if _, err := signIn(t, f, newOAuth2(t, f, nil)); err != nil {
		t.Fatal(err)
	}
	if f.TokenAccept != "application/json" || f.UserinfoAccept != "application/json" {
		t.Errorf("Accept headers: token %q, userinfo %q", f.TokenAccept, f.UserinfoAccept)
	}
	if !strings.HasPrefix(f.Bearer, "Bearer ") || f.TokenForm.Get("client_secret") != oauth2test.ClientSecret {
		t.Errorf("token form %v with %q", f.TokenForm, f.Bearer)
	}
}

// The user ID field is the only anchor: one the upstream does not have fails
// the login rather than falling back to another field (ADR 0013).
func TestOAuth2RefusesAMissingUserIDField(t *testing.T) {
	f := oauth2test.Start(t)
	_, err := signIn(t, f, newOAuth2(t, f, map[string]string{"user_id_field": "uid"}))
	if err == nil || !strings.Contains(err.Error(), `"uid"`) {
		t.Errorf("missing uid field: %v", err)
	}

	// A field that is not an ID: userinfo has it, but it says nothing about
	// who signed in.
	f.Userinfo = map[string]any{"id": 42, "admin": true}
	_, err = signIn(t, f, newOAuth2(t, f, map[string]string{"user_id_field": "admin"}))
	if err == nil || !strings.Contains(err.Error(), `"admin"`) {
		t.Errorf("non-ID field: %v", err)
	}
}

// A field that does change upstream: the External Identity follows it, so a
// User who renames becomes somebody else. Nothing to stop that but the
// field the admin picked, which is why the form warns.
func TestOAuth2FollowsAFieldThatChanges(t *testing.T) {
	f := oauth2test.Start(t)
	p := newOAuth2(t, f, map[string]string{"user_id_field": "login"})
	id, err := signIn(t, f, p)
	if err != nil {
		t.Fatal(err)
	}
	f.Userinfo = map[string]any{"id": 42, "login": "octocat2"}
	again, err := signIn(t, f, p)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "octocat" || again.Subject != "octocat2" || id.Subject == again.Subject {
		t.Errorf("subjects %q then %q", id.Subject, again.Subject)
	}
}

// A refused token endpoint, or a callback the upstream sent an error back
// in, signs nobody in.
func TestOAuth2RefusesUpstreamFailures(t *testing.T) {
	f := oauth2test.Start(t)
	f.FailToken = true
	if _, err := signIn(t, f, newOAuth2(t, f, nil)); err == nil {
		t.Error("accepted a refused token")
	}

	f = oauth2test.Start(t)
	f.FailUserinfo = true
	if _, err := signIn(t, f, newOAuth2(t, f, nil)); err == nil {
		t.Error("accepted refused userinfo")
	}

	f = oauth2test.Start(t)
	p := newOAuth2(t, f, nil)
	authURL, err := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	params := f.SignIn(authURL)
	params.Set("error", "access_denied")
	if _, err := p.Callback(context.Background(), params, "https://auth.example/cb", "n", "verifier"); err == nil {
		t.Error("accepted an error callback")
	}
}

// The registered type names the settings the admin brings.
func TestOAuth2TypeFields(t *testing.T) {
	keys := []string{}
	for _, f := range provider.GetType("oauth2").Fields {
		keys = append(keys, f.Key)
	}
	want := []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "scope",
		"client_id", "client_secret", "user_id_field"}
	if !slices.Equal(keys, want) {
		t.Errorf("fields: %v", keys)
	}
}
