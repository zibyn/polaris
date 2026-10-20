package login_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/provider/github"
	"github.com/zibyn/polaris/internal/provider/oauth2/oauth2test"
)

// addGitHub adds a fake GitHub as the Provider "github": GitHub's endpoints
// are written into the type, so a test moves them.
func (e *env) addGitHub() *oauth2test.Fake {
	e.t.Helper()
	f := oauth2test.Start(e.t)
	endpoint, api := github.Endpoint, github.API
	github.Endpoint, github.API = f.URL, f.API
	e.t.Cleanup(func() { github.Endpoint, github.API = endpoint, api })
	if err := e.providers().Create(context.Background(), "github", "github", "GitHub",
		map[string]string{"client_id": oauth2test.ClientID, "client_secret": oauth2test.ClientSecret}); err != nil {
		e.t.Fatal(err)
	}
	return f
}

// Signing in with GitHub on the hosted page: no id_token to check, the
// userinfo the access token opens says who it is (ADR 0013).
func TestSignInWithGitHub(t *testing.T) {
	e := start(t)
	f := e.addGitHub()

	_, page := e.authorize("")
	if !strings.Contains(page, "使用 GitHub 登录") {
		t.Fatalf("no GitHub button:\n%s", page)
	}
	resp, _ := e.signInWith(page, "github")
	sub := e.idToken(e.code(resp))["sub"].(string)
	if f.Bearer == "" {
		t.Error("userinfo was asked without the access token")
	}

	// The same GitHub account again, from another browser: the same User.
	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.signInWith(page, "github")
	if again := e.idToken(e.code(resp))["sub"]; again != sub {
		t.Errorf("second login: %v, want sub %s", again, sub)
	}

	// Another GitHub account: another User.
	f.Userinfo = map[string]any{"id": 43, "login": "someone-else"}
	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.signInWith(page, "github")
	if again := e.idToken(e.code(resp))["sub"]; again == sub {
		t.Errorf("another GitHub account signed in as %s", sub)
	}
}
