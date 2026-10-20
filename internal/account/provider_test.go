package account_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
	_ "github.com/zibyn/polaris/internal/provider/oauth2"
	"github.com/zibyn/polaris/internal/provider/oauth2/oauth2test"
	_ "github.com/zibyn/polaris/internal/provider/oidc"
	"github.com/zibyn/polaris/internal/provider/providertest"
)

// addGoogle adds an in-process upstream as the Provider "google".
func (e *env) addGoogle() *providertest.Upstream {
	e.t.Helper()
	up := providertest.Start(e.t, provider.CallbackURL(e.issuer, "google"))
	if err := provider.NewStore(e.pool, e.keyring).Create(context.Background(), "google", "oidc", "Google",
		map[string]string{"issuer": up.Issuer, "client_id": "upstream", "client_secret": "shh"}); err != nil {
		e.t.Fatal(err)
	}
	return up
}

// addOAuth2 adds an in-process OAuth2 upstream as the Provider "oauth2".
func (e *env) addOAuth2() *oauth2test.Fake {
	e.t.Helper()
	f := oauth2test.Start(e.t)
	if err := provider.NewStore(e.pool, e.keyring).Create(context.Background(), "oauth2", "oauth2", "OAuth2", f.Config()); err != nil {
		e.t.Fatal(err)
	}
	return f
}

// redirect asks the Account API to send the browser to a Provider, follows
// the browser of tok's Session there and back, and returns where it lands in
// the account center: its query says how it went.
func (e *env) redirect(tok, path string) url.Values {
	e.t.Helper()
	return e.redirectIn(tok, tok, path)
}

// redirectIn is redirect in the browser of browserTok's Session ("" for a
// browser signed in nowhere).
func (e *env) redirectIn(tok, browserTok, path string) url.Values {
	e.t.Helper()
	var out struct {
		URL string `json:"url"`
	}
	if c := e.call("POST", tok, path, nil, &out); c != 200 {
		e.t.Fatalf("POST %s: %d", path, c)
	}
	jar, _ := cookiejar.New(nil)
	var landed *url.URL
	browser := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == "/account" {
			landed = r.URL
			return http.ErrUseLastResponse
		}
		// The test server is plain HTTP: no jar sends a __Host- cookie.
		if c := e.cookies[browserTok]; c != "" && strings.HasPrefix(r.URL.String(), e.issuer) {
			r.Header.Set("Cookie", "__Host-session="+c)
		}
		return nil
	}}
	resp, err := browser.Get(out.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	_ = resp.Body.Close()
	if landed == nil {
		e.t.Fatalf("browser stopped at %s with %d", resp.Request.URL, resp.StatusCode)
	}
	return landed.Query()
}

type externalIdentities struct {
	ExternalIdentities []struct {
		Provider string    `json:"provider"`
		Name     string    `json:"name"`
		BoundAt  time.Time `json:"boundAt"`
	} `json:"externalIdentities"`
	Providers []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"providers"`
}

func (e *env) bound(tok string) externalIdentities {
	e.t.Helper()
	var got externalIdentities
	if c := e.call("GET", tok, "/v1/account/me", nil, &got); c != 200 {
		e.t.Fatalf("me: %d", c)
	}
	return got
}

// Binding goes to the Provider after a recent authentication and comes
// back with the External Identity bound.
func TestBindExternalIdentity(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.addGoogle()

	got := e.bound(e.signIn("ALICE", time.Hour))
	if len(got.ExternalIdentities) != 0 || len(got.Providers) != 1 || got.Providers[0].Name != "Google" {
		t.Fatalf("before: %+v", got)
	}
	if c := e.call("POST", e.signIn("ALICE", time.Hour), "/v1/account/providers/google/bind", nil, nil); c != 403 {
		t.Errorf("bind without reauthentication: %d", c)
	}
	tok := e.signIn("ALICE", 0)
	if q := e.redirect(tok, "/v1/account/providers/google/bind"); q.Get("bound") != "google" || q.Has("error") {
		t.Errorf("landed with %v", q)
	}
	got = e.bound(tok)
	if len(got.ExternalIdentities) != 1 || got.ExternalIdentities[0].Provider != "google" ||
		got.ExternalIdentities[0].Name != "Google" || time.Since(got.ExternalIdentities[0].BoundAt) > time.Minute {
		t.Errorf("after: %+v", got)
	}
	e.audited(t, "external_identity.added", 1)
}

// revoking is a Provider type that is told of unbindings, like Apple: it
// records the tokens, and fails while its config says so.
type revoking struct{ fail string }

var revoked = make(chan string, 10)

func (r revoking) AuthURL(context.Context, string, string, string, string) (string, error) {
	return "", errors.New("not here")
}

func (r revoking) Callback(context.Context, url.Values, string, string, string) (provider.Identity, error) {
	return provider.Identity{}, errors.New("not here")
}

func (r revoking) Unlink(_ context.Context, token string) error {
	if r.fail != "" {
		return errors.New(r.fail)
	}
	revoked <- token
	return nil
}

func init() {
	provider.Register(provider.Type{Key: "revoking", Name: "Revoking",
		Fields: []provider.ConfigField{{Field: channel.Field{Key: "fail", Label: "Fail", Type: "text", Optional: true}}},
		New:    func(c map[string]string) (provider.Redirect, error) { return revoking{c["fail"]}, nil }})
}

// Unbinding leaves the User a way to sign in, and tells a Provider that
// asks; its failing to revoke is audited and the unbinding stands.
func TestUnbindExternalIdentity(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	e.user("ALICE", "phone:+8613800138000")
	e.addGoogle()
	providers := provider.NewStore(e.pool, e.keyring)
	if err := providers.Create(ctx, "apple", "revoking", "Apple", map[string]string{}); err != nil {
		t.Fatal(err)
	}
	tok := e.signIn("ALICE", 0)
	e.redirect(tok, "/v1/account/providers/google/bind")
	sealed, err := e.keyring.Seal([]byte("refresh-1"), []byte("external_identity:apple:apple-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO external_identities (provider, subject, user_id, token)
		VALUES ('apple', 'apple-1', 'ALICE', $1)`, sealed); err != nil {
		t.Fatal(err)
	}

	if c := e.call("DELETE", e.signIn("ALICE", time.Hour), "/v1/account/providers/google", nil, nil); c != 403 {
		t.Errorf("unbind without reauthentication: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("unbind the phone: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/providers/google", nil, nil); c != 204 {
		t.Fatalf("unbind Google: %d", c)
	}
	e.audited(t, "external_identity.removed", 1)
	if c := e.call("DELETE", tok, "/v1/account/providers/google", nil, nil); c != 422 {
		t.Errorf("unbind Google again: %d", c)
	}

	// Apple is the last way to sign in.
	if c := e.call("DELETE", tok, "/v1/account/providers/apple", nil, nil); c != 422 {
		t.Errorf("unbind the last: %d", c)
	}
	if got := e.bound(tok); len(got.ExternalIdentities) != 1 || got.ExternalIdentities[0].Name != "Apple" {
		t.Errorf("left: %+v", got)
	}
	if len(revoked) != 0 {
		t.Errorf("revoked %q", <-revoked)
	}

	e.user("BOB", "phone:+8613900139000")
	if _, err := e.pool.Exec(ctx, `UPDATE external_identities SET user_id = 'BOB'`); err != nil {
		t.Fatal(err)
	}
	if c := e.call("DELETE", e.signIn("BOB", 0), "/v1/account/providers/apple", nil, nil); c != 204 || len(revoked) != 1 || <-revoked != "refresh-1" {
		t.Errorf("unbind Apple: %d", c)
	}

	// Disabled and failing to revoke. (One kept no token: nothing to revoke.)
	sealed, err = e.keyring.Seal([]byte("refresh-2"), []byte("external_identity:apple:apple-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO external_identities (provider, subject, user_id, token) VALUES ('apple', 'apple-2', 'BOB', $1)`, sealed); err != nil {
		t.Fatal(err)
	}
	if err := providers.Update(ctx, "apple", "Apple", map[string]string{"fail": "apple is down"}); err != nil {
		t.Fatal(err)
	}
	if err := providers.SetEnabled(ctx, "apple", false); err != nil {
		t.Fatal(err)
	}
	if c := e.call("DELETE", e.signIn("BOB", 0), "/v1/account/providers/apple", nil, nil); c != 204 {
		t.Errorf("unbind Apple failing to revoke: %d", c)
	}
	var detail string
	if err := e.pool.QueryRow(ctx, `SELECT detail->>'error' FROM audit_log WHERE event = 'provider.unlink_failed' AND sub = 'BOB'`).Scan(&detail); err != nil || detail != "apple is down" {
		t.Errorf("revoke failure audited: %q %v", detail, err)
	}
}

// An External Identity at a disabled Provider signs nobody in: it is no
// way to sign in that removing the last other one could leave.
func TestDisabledProviderIsNoLoginPath(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.addGoogle()
	tok := e.signIn("ALICE", 0)
	if q := e.redirect(tok, "/v1/account/providers/google/bind"); q.Get("bound") != "google" {
		t.Fatalf("bind: %v", q)
	}
	if err := provider.NewStore(e.pool, e.keyring).SetEnabled(context.Background(), "google", false); err != nil {
		t.Fatal(err)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 422 {
		t.Errorf("remove the phone, leaving a disabled Google: %d, want 422", c)
	}
}

// An External Identity is one User's: binding another's is refused, and so
// is a second one of the same Provider (ADR 0003).
func TestBindRefusesAnotherUsersExternalIdentity(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.user("BOB", "phone:+8613900139000")
	up := e.addGoogle()
	bob := e.signIn("BOB", 0)
	if q := e.redirect(bob, "/v1/account/providers/google/bind"); q.Get("bound") != "google" {
		t.Fatalf("Bob binds: %v", q)
	}
	if q := e.redirect(bob, "/v1/account/providers/google/bind"); q.Get("bound") != "google" {
		t.Errorf("Bob binds the same again: %v", q)
	}

	alice := e.signIn("ALICE", 0)
	if q := e.redirect(alice, "/v1/account/providers/google/bind"); q.Get("error") != "这个外部账号已绑定其他账号,请先在那边解绑或注销" {
		t.Errorf("Alice binds Bob's: %v", q)
	}
	if got := e.bound(alice); len(got.ExternalIdentities) != 0 {
		t.Errorf("Alice: %+v", got)
	}
	up.Sub = "google-user-2"
	if q := e.redirect(bob, "/v1/account/providers/google/bind"); q.Get("error") != "已绑定这个外部登录方式的另一个账号,请先解绑" {
		t.Errorf("Bob binds a second Google account: %v", q)
	}
}

// Bind CSRF: a redirect from the account center finishes only in the
// browser Session that started it.
func TestAccountRedirectFinishesOnlyInItsSession(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.user("MALLORY", "phone:+8613900139000")
	e.addGoogle()
	mallory, alice := e.signIn("MALLORY", 0), e.signIn("ALICE", 0)
	for name, browser := range map[string]string{"Alice's browser": alice, "a browser signed in nowhere": ""} {
		if q := e.redirectIn(mallory, browser, "/v1/account/providers/google/bind"); !q.Has("error") {
			t.Errorf("%s: landed with %v", name, q)
		}
	}
	if got := e.bound(mallory); len(got.ExternalIdentities) != 0 {
		t.Fatalf("Alice's Google bound to Mallory: %+v", got)
	}

	if q := e.redirect(mallory, "/v1/account/providers/google/bind"); q.Get("bound") != "google" {
		t.Fatalf("Mallory binds in her own browser: %v", q)
	}
	if q := e.redirectIn(mallory, alice, "/v1/account/providers/google/reauth"); !q.Has("error") {
		t.Errorf("reauth in Alice's browser: %v", q)
	}
}

// A User without 两步验证 can reauthenticate by signing in afresh at a
// Provider they bound, as the External Identity they bound.
func TestReauthenticateWithProvider(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	e.user("ALICE", "phone:+8613800138000")
	up := e.addGoogle()
	tok := e.signIn("ALICE", 0)
	e.redirect(tok, "/v1/account/providers/google/bind")
	stale := func() {
		t.Helper()
		if _, err := e.pool.Exec(ctx, "UPDATE sessions SET auth_time = now() - interval '1 hour'"); err != nil {
			t.Fatal(err)
		}
	}
	recent := func() bool {
		t.Helper()
		var got me
		e.call("GET", tok, "/v1/account/me", nil, &got)
		return got.RecentAuthUntil.After(time.Now())
	}

	stale()
	if q := e.redirect(tok, "/v1/account/providers/google/reauth"); q.Get("reauthenticated") != "google" || !recent() {
		t.Fatalf("reauth: %v", q)
	}
	if up.Last.Prompt != "login" || up.Last.MaxAuthnAgeSecs == nil || *up.Last.MaxAuthnAgeSecs != 0 {
		t.Errorf("asked the upstream for prompt %q max_age %v", up.Last.Prompt, up.Last.MaxAuthnAgeSecs)
	}
	var amr []string
	if err := e.pool.QueryRow(ctx, "SELECT amr FROM sessions").Scan(&amr); err != nil || !slices.Equal(amr, []string{"fed"}) {
		t.Errorf("amr %v: %v", amr, err)
	}

	// Signed in at the upstream before the redirect: not afresh.
	stale()
	up.AuthTime = time.Now().Add(-time.Hour).Unix()
	if q := e.redirect(tok, "/v1/account/providers/google/reauth"); q.Get("error") != "请在外部登录页重新登录后再试" || recent() {
		t.Errorf("old auth_time: %v", q)
	}
	up.AuthTime = time.Now().Unix()
	if q := e.redirect(tok, "/v1/account/providers/google/reauth"); q.Get("reauthenticated") != "google" || !recent() {
		t.Errorf("fresh auth_time: %v", q)
	}

	// Another Google account is not the one bound.
	stale()
	up.Sub = "google-user-2"
	if q := e.redirect(tok, "/v1/account/providers/google/reauth"); q.Get("error") != "这不是你绑定的外部账号" || recent() {
		t.Errorf("another account: %v", q)
	}

	e.user("BOB", "phone:+8613900139000")
	if c := e.call("POST", e.signIn("BOB", time.Hour), "/v1/account/providers/google/reauth", nil, nil); c != 422 {
		t.Errorf("reauth at a Provider not bound: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/providers/nope/reauth", nil, nil); c != 422 && c != 404 {
		t.Errorf("reauth at no Provider: %d", c)
	}
}

// Reauthenticating at an OAuth2 Provider asks it for nothing: it has no
// prompt=login and no max_age, and it says no auth_time, so we take its
// word that the External Identity is still signed in there and give no
// discount for how long ago that was (ADR 0013).
func TestReauthenticateWithOAuth2Provider(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	e.user("ALICE", "phone:+8613800138000")
	f := e.addOAuth2()
	tok := e.signIn("ALICE", 0)
	if q := e.redirect(tok, "/v1/account/providers/oauth2/bind"); q.Get("bound") != "oauth2" {
		t.Fatalf("bind: %v", q)
	}
	if _, err := e.pool.Exec(ctx, "UPDATE sessions SET auth_time = now() - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	if q := e.redirect(tok, "/v1/account/providers/oauth2/reauth"); q.Get("reauthenticated") != "oauth2" {
		t.Fatalf("reauth: %v", q)
	}
	if f.Last.Has("prompt") || f.Last.Has("max_age") || f.Last.Has("nonce") {
		t.Errorf("asked the upstream for %v", f.Last)
	}
	var amr []string
	if err := e.pool.QueryRow(ctx, "SELECT amr FROM sessions").Scan(&amr); err != nil || !slices.Equal(amr, []string{"fed"}) {
		t.Errorf("amr %v: %v", amr, err)
	}

	// Another upstream account is not the one bound.
	f.Userinfo = map[string]any{"id": 43, "login": "someone-else"}
	if q := e.redirect(tok, "/v1/account/providers/oauth2/reauth"); q.Get("error") != "这不是你绑定的外部账号" {
		t.Errorf("another account: %v", q)
	}
}

// The export names each External Identity's Provider and when it was
// bound, nothing more.
func TestExportExternalIdentities(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.addGoogle()
	tok := e.signIn("ALICE", 0)
	e.redirect(tok, "/v1/account/providers/google/bind")
	var got struct {
		ExternalIdentities []map[string]any `json:"externalIdentities"`
	}
	if c := e.call("GET", tok, "/v1/account/export", nil, &got); c != 200 {
		t.Fatalf("export: %d", c)
	}
	if len(got.ExternalIdentities) != 1 || len(got.ExternalIdentities[0]) != 2 ||
		got.ExternalIdentities[0]["provider"] != "Google" || got.ExternalIdentities[0]["boundAt"] == nil {
		t.Errorf("export: %+v", got)
	}
}

// With 两步验证 on, a Provider does not reauthenticate: only a TOTP or
// recovery code does.
func TestReauthenticateWithProviderNeedsNoTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.addGoogle()
	tok := e.signIn("ALICE", 0)
	e.redirect(tok, "/v1/account/providers/google/bind")
	e.enableTwoFactor(tok)
	if c := e.call("POST", tok, "/v1/account/providers/google/reauth", nil, nil); c != 422 {
		t.Errorf("reauth at Google with 两步验证 on: %d", c)
	}
}
