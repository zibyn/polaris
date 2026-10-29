package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// An Application that requires a Role turns away a User without one on its
// default API, on the hosted page, the direct auth API and refresh alike
// (#155, docs/spec/rbac.md).
func TestRequireRoleTurnsAwayUsersWithoutRoles(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	exec := func(sql string) {
		t.Helper()
		if _, err := e.pool.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO apis (identifier, name) VALUES ('https://track.example', 'Track');
		INSERT INTO roles (api, key, name) VALUES ('https://track.example', 'viewer', 'V');
		UPDATE applications SET default_api = 'https://track.example', require_role = true WHERE client_id = 'rp'`)

	// Hosted page: no code, a page that says why and offers 切换账号; the
	// browser stays signed in.
	_, page := e.authorize("")
	resp, page := e.submit(page, "owner", "password1")
	if resp.StatusCode != 403 || !strings.Contains(page, "你没有使用 Test RP 的权限,请联系管理员") || !strings.Contains(page, "切换账号") {
		t.Fatalf("hosted: %d %s", resp.StatusCode, page)
	}
	// Still signed in: the next authorization is a silent login, turned
	// away the same way rather than asking for a password.
	if resp, again := e.authorize(""); resp.StatusCode != 403 || !strings.Contains(again, "切换账号") {
		t.Errorf("silent login: %d %s", resp.StatusCode, again)
	}
	resp, page = e.post(page, url.Values{"op": {"switch-account"}})
	if resp.StatusCode != 200 || !strings.Contains(page, `name="identifier"`) {
		t.Errorf("切换账号: %d %s", resp.StatusCode, page)
	}

	// Direct auth API: its own error code, not an ordinary failure.
	if r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "terms_version": {""}}); r.Status != 403 || r.Error != "application_access_denied" || r.Code != "" {
		t.Errorf("direct: %+v", r)
	}

	// With a Role, both sign in.
	exec(`INSERT INTO user_roles SELECT user_id, 'https://track.example', 'viewer' FROM identifiers WHERE value = 'owner'`)
	if r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "terms_version": {""}}); r.Status != 200 || r.Code == "" {
		t.Errorf("direct with a Role: %+v", r)
	}
	e.newBrowser()
	tok := e.signIn()
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	next, errCode := e.refresh(tok.RefreshToken)
	if errCode != "" {
		t.Fatalf("refresh with a Role: %s", errCode)
	}

	// Every Role taken away: the refresh token no longer renews.
	exec(`DELETE FROM user_roles WHERE api = 'https://track.example'`)
	if _, errCode := e.refresh(next.RefreshToken); errCode != "invalid_grant" {
		t.Errorf("refresh without a Role: %q", errCode)
	}
}
