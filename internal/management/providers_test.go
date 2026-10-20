package management_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/provider"
	_ "github.com/zibyn/polaris/internal/provider/oidc"
)

type providerField struct {
	Key               string
	Secret, Immutable bool
}

type providers struct {
	Types []struct {
		Key    string
		Fields []providerField
	}
	Providers []providerInfo
}

type providerInfo struct {
	ID, Type, Name string
	Enabled        bool
	Config         map[string]string
	Secrets        map[string]time.Time
	CallbackURL    string
	Bound          int
	OnlyLoginPath  int
}

func (e *env) providers(token string) providers {
	e.t.Helper()
	var got providers
	if code := e.get(token, "/providers", &got); code != 200 {
		e.t.Fatalf("providers: %d", code)
	}
	return got
}

func google(config map[string]string) map[string]any {
	c := map[string]string{"issuer": "https://accounts.google.com", "client_id": "cid", "client_secret": "csecret"}
	for k, v := range config {
		c[k] = v
	}
	return map[string]any{"id": "google", "type": "oidc", "name": "Google", "config": c}
}

func TestAdminAddsAndEditsProvider(t *testing.T) {
	e := start(t)
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)

	got := e.providers(ro)
	i := slices.IndexFunc(got.Types, func(ty struct {
		Key    string
		Fields []providerField
	}) bool {
		return ty.Key == "oidc"
	})
	if len(got.Providers) != 0 || i < 0 || !slices.Equal(got.Types[i].Fields, []providerField{
		{"issuer", false, true}, {"client_id", false, false}, {"client_secret", true, false},
	}) {
		t.Fatalf("before: %+v", got)
	}

	if code := e.call("POST", ro, "/providers", google(nil), nil); code != 403 {
		t.Errorf("readonly adds: %d, want 403", code)
	}
	for name, body := range map[string]map[string]any{
		"bad id":       {"id": "Google!", "type": "oidc", "name": "G", "config": map[string]string{"issuer": "https://a.example", "client_id": "c", "client_secret": "s"}},
		"no secret":    google(map[string]string{"client_secret": ""}),
		"bad issuer":   google(map[string]string{"issuer": "not a url"}),
		"unknown type": {"id": "x", "type": "nope", "name": "X", "config": map[string]string{}},
	} {
		if code := e.call("POST", owner, "/providers", body, nil); code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}
	if code := e.call("POST", owner, "/providers", google(nil), nil); code != 204 {
		t.Fatalf("add: %d", code)
	}
	if code := e.call("POST", owner, "/providers", google(nil), nil); code != 409 {
		t.Errorf("same id again: %d, want 409", code)
	}

	got = e.providers(ro)
	if len(got.Providers) != 1 {
		t.Fatalf("after add: %+v", got.Providers)
	}
	p := got.Providers[0]
	if p.ID != "google" || p.Type != "oidc" || p.Name != "Google" || !p.Enabled ||
		p.Config["issuer"] != "https://accounts.google.com" || p.Config["client_id"] != "cid" ||
		p.Config["client_secret"] != "" || p.Secrets["client_secret"].IsZero() ||
		p.CallbackURL != e.issuer+"/login/providers/google/callback" {
		t.Errorf("listed: %+v", p)
	}

	// The name and client_id change; an empty secret keeps the stored one.
	edit := map[string]any{"name": "Google 账号", "config": map[string]string{"issuer": "https://accounts.google.com", "client_id": "cid2"}}
	if code := e.call("PUT", owner, "/providers/google", edit, nil); code != 204 {
		t.Fatalf("edit: %d", code)
	}
	p = e.providers(ro).Providers[0]
	if p.Name != "Google 账号" || p.Config["client_id"] != "cid2" || p.Secrets["client_secret"].IsZero() {
		t.Errorf("edited: %+v", p)
	}
	// The issuer anchors the External Identities, so it never changes.
	edit["config"] = map[string]string{"issuer": "https://evil.example", "client_id": "cid2"}
	if code := e.call("PUT", owner, "/providers/google", edit, nil); code != 422 {
		t.Errorf("issuer changed: %d, want 422", code)
	}
	if code := e.call("PUT", owner, "/providers/nope", edit, nil); code != 404 {
		t.Errorf("unknown provider: %d, want 404", code)
	}

	var audit struct{ Events []struct{ Event string } }
	e.get(owner, "/audit", &audit)
	var events []string
	for _, ev := range audit.Events {
		events = append(events, ev.Event)
	}
	if !slices.Contains(events, "create-provider") || !slices.Contains(events, "update-provider") {
		t.Errorf("audit: %v", events)
	}
}

func TestProviderWithBindingsCanOnlyBeDisabled(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	for _, id := range []string{"google", "corp"} {
		body := google(nil)
		body["id"] = id
		if code := e.call("POST", owner, "/providers", body, nil); code != 204 {
			t.Fatalf("add %s: %d", id, code)
		}
	}
	// ALICE has a phone too, BOB only Google, CAROL Google and corp.
	e.user("ALICE", nil, "phone:+8613800001111")
	e.user("BOB", nil)
	e.user("CAROL", nil)
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO external_identities (provider, subject, user_id) VALUES
		('google', 'a', 'ALICE'), ('google', 'b', 'BOB'), ('google', 'c', 'CAROL'), ('corp', 'c', 'CAROL')`); err != nil {
		t.Fatal(err)
	}
	byID := func() map[string]providerInfo {
		m := map[string]providerInfo{}
		for _, p := range e.providers(owner).Providers {
			m[p.ID] = p
		}
		return m
	}
	if p := byID()["google"]; p.Bound != 3 || p.OnlyLoginPath != 1 {
		t.Errorf("google counts: %+v", p)
	}
	if p := byID()["corp"]; p.Bound != 1 || p.OnlyLoginPath != 0 {
		t.Errorf("corp counts: %+v", p)
	}
	// A disabled Provider is no other way to sign in.
	if code := e.call("POST", owner, "/providers/corp/disable", nil, nil); code != 204 {
		t.Fatalf("disable corp: %d", code)
	}
	if p := byID()["google"]; p.Bound != 3 || p.OnlyLoginPath != 2 {
		t.Errorf("google counts with corp disabled: %+v", p)
	}
	if code := e.call("POST", owner, "/providers/corp/enable", nil, nil); code != 204 {
		t.Fatalf("enable corp: %d", code)
	}

	if code := e.call("DELETE", owner, "/providers/google", nil, nil); code != 409 {
		t.Errorf("delete bound: %d, want 409", code)
	}
	if code := e.call("POST", owner, "/providers/google/disable", nil, nil); code != 204 {
		t.Fatalf("disable: %d", code)
	}
	if p := byID()["google"]; p.Enabled {
		t.Errorf("still enabled: %+v", p)
	}
	if code := e.call("POST", owner, "/providers/google/enable", nil, nil); code != 204 || !byID()["google"].Enabled {
		t.Errorf("enable: %d", code)
	}

	if _, err := e.pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ('ALICE', 'BOB', 'CAROL')`); err != nil {
		t.Fatal(err)
	}
	if code := e.call("DELETE", owner, "/providers/google", nil, nil); code != 204 {
		t.Errorf("delete unbound: %d", code)
	}
	if _, ok := byID()["google"]; ok {
		t.Error("google still listed")
	}
	if code := e.call("DELETE", owner, "/providers/google", nil, nil); code != 404 {
		t.Errorf("delete again: %d, want 404", code)
	}

	var audit struct{ Events []struct{ Event string } }
	e.get(owner, "/audit", &audit)
	var events []string
	for _, ev := range audit.Events {
		events = append(events, ev.Event)
	}
	for _, want := range []string{"disable-provider", "delete-provider"} {
		if !slices.Contains(events, want) {
			t.Errorf("audit lacks %s: %v", want, events)
		}
	}
}

// unlinking is a Provider type that revokes on unbinding, as Apple does:
// it records the tokens it was given and fails on "fail".
type unlinking struct{}

var unlinked []string

func (unlinking) AuthURL(context.Context, string, string, string, string) (string, error) {
	return "", nil
}

func (unlinking) Callback(context.Context, url.Values, string, string, string) (provider.Identity, error) {
	return provider.Identity{}, nil
}

func (unlinking) Unlink(_ context.Context, token string) error {
	unlinked = append(unlinked, token)
	if token == "fail" {
		return errors.New("upstream said no")
	}
	return nil
}

func init() {
	provider.Register(provider.Type{Key: "unlinking", Name: "Unlinking",
		New: func(map[string]string) (provider.Redirect, error) { return unlinking{}, nil }})
}

type externalIdentity struct {
	Provider, Name string
	CreatedAt      time.Time
}

func TestAdminUnbindsExternalIdentity(t *testing.T) {
	e := start(t)
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)
	if code := e.call("POST", owner, "/providers", google(nil), nil); code != 204 {
		t.Fatalf("add google: %d", code)
	}
	if code := e.call("POST", owner, "/providers", map[string]any{"id": "apple", "type": "unlinking", "name": "Apple", "config": map[string]string{}}, nil); code != 204 {
		t.Fatalf("add apple: %d", code)
	}
	// ALICE has a phone too, BOB only Google, CAROL Google and Apple.
	e.user("ALICE", nil, "phone:+8613800001111")
	e.user("BOB", nil)
	e.user("CAROL", nil)
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sealed := func(subject, token string) []byte {
		b, err := keyring.Seal([]byte(token), []byte("external_identity:apple:"+subject))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO external_identities (provider, subject, user_id, token) VALUES
		('google', 'a', 'ALICE', NULL), ('google', 'b', 'BOB', NULL), ('google', 'c', 'CAROL', NULL),
		('apple', 'a', 'ALICE', $1), ('apple', 'c', 'CAROL', $2)`, sealed("a", "fail"), sealed("c", "refresh-c")); err != nil {
		t.Fatal(err)
	}
	list := func(sub string) []externalIdentity {
		var got struct{ ExternalIdentities []externalIdentity }
		if code := e.get(ro, "/users/"+sub+"/external-identities", &got); code != 200 {
			t.Fatalf("list %s: %d", sub, code)
		}
		return got.ExternalIdentities
	}
	if got := list("CAROL"); len(got) != 2 || got[0].Provider != "google" || got[0].Name != "Google" ||
		got[1].Provider != "apple" || got[1].Name != "Apple" || got[0].CreatedAt.IsZero() {
		t.Errorf("CAROL's: %+v", got)
	}

	if code := e.call("DELETE", ro, "/users/CAROL/external-identities/google", nil, nil); code != 403 {
		t.Errorf("readonly unbinds: %d, want 403", code)
	}
	if code := e.call("DELETE", owner, "/users/BOB/external-identities/google", nil, nil); code != 409 {
		t.Errorf("BOB's last login path: %d, want 409", code)
	}
	if len(list("BOB")) != 1 {
		t.Error("BOB lost Google")
	}
	if code := e.call("DELETE", owner, "/users/BOB/external-identities/apple", nil, nil); code != 404 {
		t.Errorf("not bound: %d, want 404", code)
	}

	// CAROL keeps Google; Apple is told to revoke her token.
	unlinked = nil
	if code := e.call("DELETE", owner, "/users/CAROL/external-identities/apple", nil, nil); code != 204 {
		t.Fatalf("unbind CAROL's Apple: %d", code)
	}
	if got := list("CAROL"); len(got) != 1 || got[0].Provider != "google" {
		t.Errorf("CAROL after: %+v", got)
	}
	if !slices.Equal(unlinked, []string{"refresh-c"}) {
		t.Errorf("unlinked: %v", unlinked)
	}
	if ev := e.audited("external_identity.removed"); ev.Sub != "CAROL" || ev.Detail["provider"] != "apple" || ev.Detail["by"] != e.owner {
		t.Errorf("audit: %+v", ev)
	}

	// Revoking fails: the binding goes all the same, and the failure is audited.
	if code := e.call("DELETE", owner, "/users/ALICE/external-identities/apple", nil, nil); code != 204 {
		t.Fatalf("unbind ALICE's Apple: %d", code)
	}
	if ev := e.audited("provider.unlink_failed"); ev.Sub != "ALICE" || ev.Detail["provider"] != "apple" {
		t.Errorf("unlink failure audit: %+v", ev)
	}
	if code := e.call("DELETE", owner, "/users/ALICE/external-identities/google", nil, nil); code != 204 {
		t.Errorf("ALICE still has her phone: %d", code)
	}
	if len(list("ALICE")) != 0 {
		t.Error("ALICE still bound")
	}
}

func TestUnbindingAnAdminNeedsAdminRolesAssign(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	if code := e.call("POST", owner, "/providers", google(nil), nil); code != 204 {
		t.Fatalf("add google: %d", code)
	}
	e.user("ADMIN", []string{"admin"}, "phone:+8613800001111")
	e.user("OPS", []string{"readonly"}, "phone:+8613800002222")
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO external_identities (provider, subject, user_id) VALUES ('google', 'o', 'OPS')`); err != nil {
		t.Fatal(err)
	}
	if code := e.call("DELETE", e.token("ADMIN", nil), "/users/OPS/external-identities/google", nil, nil); code != 403 {
		t.Errorf("admin unbinds an admin: %d, want 403", code)
	}
	if code := e.call("DELETE", owner, "/users/OPS/external-identities/google", nil, nil); code != 204 {
		t.Errorf("owner unbinds an admin: %d", code)
	}
}

// Deleting a User tells each of their Providers that asks, as 注销 does.
func TestAdminDeletingUserRevokes(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	if code := e.call("POST", owner, "/providers", map[string]any{"id": "apple", "type": "unlinking", "name": "Apple", "config": map[string]string{}}, nil); code != 204 {
		t.Fatalf("add apple: %d", code)
	}
	e.user("CAROL", nil)
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keyring.Seal([]byte("refresh-c"), []byte("external_identity:apple:c"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO external_identities (provider, subject, user_id, token) VALUES ('apple', 'c', 'CAROL', $1)`, sealed); err != nil {
		t.Fatal(err)
	}
	unlinked = nil
	if code := e.call("DELETE", owner, "/users/CAROL", nil, nil); code != 204 {
		t.Fatalf("delete CAROL: %d", code)
	}
	if !slices.Equal(unlinked, []string{"refresh-c"}) {
		t.Errorf("unlinked: %v", unlinked)
	}
}
