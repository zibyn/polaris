package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/oidcstore"
)

const notAllowed = "该应用不支持这种登录方式"

// only gives Application client its own login methods (ADR 0027).
func (e *env) only(client string, methods ...string) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE applications SET login_methods = $2 WHERE client_id = $1", client, methods); err != nil {
		e.t.Fatal(err)
	}
}

// app registers another public Application with the test callback.
func (e *env) app(client string) {
	e.t.Helper()
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: client, Name: client, RedirectURIs: []string{callback},
	}); err != nil {
		e.t.Fatal(err)
	}
}

// sessionMethods are the login methods of the live Sessions, oldest first.
func (e *env) sessionMethods() []string {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "SELECT COALESCE(login_method, '') FROM sessions WHERE ended_at IS NULL ORDER BY auth_time")
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// An Application that names one Provider shows only that one, and the
// server refuses every other way in: codes, password, other Providers,
// Passkeys.
func TestApplicationWithOneProvider(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.addGoogle()
	e.addGitHub()
	e.only(clientID, "provider:google")

	_, page := e.authorize("")
	if !strings.Contains(page, "使用 Google 登录") || strings.Contains(page, "使用 GitHub 登录") ||
		strings.Contains(page, `name="identifier"`) || strings.Contains(page, `name="password"`) {
		t.Fatalf("login page:\n%s", page)
	}
	if _, ok := optionsOf(t, page); ok {
		t.Error("the page carries Passkey options")
	}

	for name, form := range map[string]url.Values{
		"code":     {"op": {"send"}, "identifier": {"+8613800138000"}, "altcha": {e.solve()}},
		"password": {"op": {"password"}, "username": {"owner"}, "password": {"password1"}},
		"github":   {"op": {"provider"}, "provider": {"github"}},
	} {
		resp, body := e.post(page, form)
		if resp.StatusCode/100 == 3 || !strings.Contains(body, notAllowed) {
			t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if code := e.inbox.take("+8613800138000"); code != "" {
		t.Error("a code was sent")
	}

	resp, _ := e.signInWith(page, "google")
	e.idToken(e.code(resp))
	if got := e.sessionMethods(); len(got) != 1 || got[0] != "provider:google" {
		t.Errorf("Session login methods: %v", got)
	}
}

// The direct auth API applies the same set, by client_id.
func TestDirectAuthWithOwnLoginMethods(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.only(clientID, "password")

	for name, form := range map[string]url.Values{
		"code":     {"identifier": {"+8613800138000"}, "altcha": {e.solve()}},
		"passkey":  {"passkey": {"begin"}},
		"provider": {"provider": {"google"}, "authorization_code": {"x"}},
	} {
		if got := e.challenge(form); got.Status != 403 || got.Error != "login_method_not_allowed" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	got := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}})
	if got.Status != 200 || got.Code == "" {
		t.Fatalf("password: %+v", got)
	}
}

// When the instance turns off the one method an Application names, the
// login page and the direct auth API say so; other Applications go on.
func TestNoLoginMethodLeft(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.only(clientID, "passkey")
	setPasskeyLogin(t, e, false)

	if resp, page := e.authorize(""); resp.StatusCode != 403 || !strings.Contains(page, "该应用没有可用的登录方式") {
		t.Errorf("login page: %d %s", resp.StatusCode, page)
	}
	if got := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}}); got.Status != 403 || got.Error != "no_login_method" {
		t.Errorf("challenge: %+v", got)
	}
	e.app("other")
	if resp, _ := e.authorizeAs("other", callback, ""); resp.StatusCode != 200 {
		t.Errorf("an Application following the instance: %d", resp.StatusCode)
	}
}

// 单点登录 into an Application that does not allow the Session's login
// method asks for a login with one it does. The same User keeps the
// Session, now under the new method; another User's ends it. Existing
// refresh tokens keep working.
func TestSingleSignOnChecksTheSessionsLoginMethod(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	owner := e.sub("owner")
	if err := e.ids.AddIdentifier(context.Background(), owner, "phone", "+8613800138000"); err != nil {
		t.Fatal(err)
	}
	tok := e.signIn() // password, on the Application following the instance
	e.app("staff")
	e.only("staff", "sms")

	resp, page := e.authorizeAs("staff", callback, "")
	if resp.StatusCode != 200 || !strings.Contains(page, `name="identifier"`) {
		t.Fatalf("staff with a password Session: %d", resp.StatusCode)
	}
	resp, _ = e.codeLogin(page, "+8613800138000", "+8613800138000")
	e.code(resp)
	if got := e.sessionMethods(); len(got) != 1 || got[0] != "sms" {
		t.Errorf("Session after signing in again as the same User: %v", got)
	}
	// Back on the first Application: an SMS Session is fine there.
	if !e.signedIn() {
		t.Error("the Session no longer signs in to the Application following the instance")
	}
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "" {
		t.Errorf("refresh after the setting changed: %s", errCode)
	}

	// Another User signs in where only a Provider is allowed: the owner's
	// Session ends.
	e.addGoogle()
	e.only("staff", "provider:google")
	_, page = e.authorizeAs("staff", callback, "")
	resp, _ = e.signInWith(page, "google")
	e.code(resp)
	var ended bool
	if err := e.pool.QueryRow(context.Background(), "SELECT ended_at IS NOT NULL FROM sessions WHERE user_id = $1", owner).Scan(&ended); err != nil || !ended {
		t.Errorf("the owner's Session did not end: %v", err)
	}
}

// The Session tells Providers apart: one signed in with Google is not
// signed in where only GitHub is allowed.
func TestSingleSignOnTellsProvidersApart(t *testing.T) {
	e := start(t)
	e.addGoogle()
	e.addGitHub()
	e.only(clientID, "provider:google")
	e.app("gh")
	e.only("gh", "provider:github")

	_, page := e.authorize("")
	resp, _ := e.signInWith(page, "google")
	e.code(resp)
	if resp, _ := e.authorize(""); resp.StatusCode/100 != 3 {
		t.Errorf("Google Session on the Google Application: %d", resp.StatusCode)
	}
	resp, page = e.authorizeAs("gh", callback, "")
	if resp.StatusCode != 200 || !strings.Contains(page, "使用 GitHub 登录") {
		t.Errorf("Google Session on the GitHub Application: %d", resp.StatusCode)
	}
	resp, _ = e.authorizeAs("gh", callback, "&prompt=none")
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc.Query().Get("error") != "login_required" {
		t.Errorf("prompt=none: %q", loc)
	}
}
