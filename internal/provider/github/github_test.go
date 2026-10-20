package github_test

import (
	"context"
	"net/url"
	"slices"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/github"
	"github.com/zibyn/polaris/internal/provider/oauth2/oauth2test"
)

// fakeGitHub points the GitHub type at a fake upstream: GitHub's endpoints
// are written into the type, so a test moves them.
func fakeGitHub(t *testing.T) *oauth2test.Fake {
	t.Helper()
	f := oauth2test.Start(t)
	endpoint, api := github.Endpoint, github.API
	github.Endpoint, github.API = f.URL, f.API
	t.Cleanup(func() { github.Endpoint, github.API = endpoint, api })
	return f
}

func newGitHub(t *testing.T, config map[string]string) provider.Redirect {
	t.Helper()
	p, err := provider.GetType("github").New(config)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The admin brings a client ID and secret; everything else is written in.
func TestGitHubTypeAsksForClientCredentials(t *testing.T) {
	keys := []string{}
	for _, f := range provider.GetType("github").Fields {
		keys = append(keys, f.Key)
	}
	if !slices.Equal(keys, []string{"client_id", "client_secret"}) {
		t.Errorf("fields: %v", keys)
	}
}

// GitHub's endpoints and scope are the type's, whatever the admin set.
func TestGitHubUsesItsOwnEndpoints(t *testing.T) {
	fakeGitHub(t)
	p := newGitHub(t, map[string]string{"client_id": "cid", "client_secret": "shh"})
	authURL, err := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/login/oauth/authorize" || u.Query().Get("scope") != "read:user" {
		t.Errorf("authorization request: %s", authURL)
	}
}

// GitHub's login is the user's to change whenever they like, so the
// External Identity is the numeric id (ADR 0013).
func TestGitHubSubjectIsTheNumericID(t *testing.T) {
	f := fakeGitHub(t)
	f.Userinfo = map[string]any{"id": 42, "login": "octocat", "name": "The Octocat"}
	p := newGitHub(t, map[string]string{"client_id": "cid", "client_secret": "shh"})
	authURL, err := p.AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Callback(context.Background(), f.SignIn(authURL), "https://auth.example/cb", "n", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "42" {
		t.Errorf("signed in as %+v", id)
	}
	if f.TokenForm.Get("client_id") != "cid" || f.Bearer == "" {
		t.Errorf("token form %v, userinfo %q", f.TokenForm, f.Bearer)
	}
}
