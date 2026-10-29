package login_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// signIn logs the owner in through the password form and redeems the code.
func (e *env) signIn() tokens {
	e.t.Helper()
	_, page := e.authorize("")
	resp, _ := e.submit(page, "owner", "password1")
	return e.exchange(clientID, callback, e.code(resp))
}

// refresh redeems a refresh token; a failure comes back as the error code.
func (e *env) refresh(rt string) (tokens, string) {
	e.t.Helper()
	resp, body := e.do("POST", "/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID},
	})
	var out struct {
		tokens
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		e.t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	return out.tokens, out.Error
}

// signedIn reports whether the browser still has a Session.
func (e *env) signedIn() bool {
	e.t.Helper()
	resp, _ := e.authorize("&prompt=none")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("code") != ""
}

func TestRefreshTokenReuseEndsTheSession(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	first := e.signIn()
	if first.RefreshToken == "" {
		t.Fatal("no refresh token")
	}

	second, errCode := e.refresh(first.RefreshToken)
	if errCode != "" || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.AccessToken == "" {
		t.Fatalf("refresh did not rotate: %q %+v", errCode, second)
	}

	if _, errCode := e.refresh(first.RefreshToken); errCode != "invalid_grant" {
		t.Errorf("reused refresh token: %q, want invalid_grant", errCode)
	}
	// The whole Session is over: the rotated token and the browser too.
	if _, errCode := e.refresh(second.RefreshToken); errCode != "invalid_grant" {
		t.Errorf("refresh after reuse: %q, want invalid_grant", errCode)
	}
	if e.signedIn() {
		t.Error("browser Session survived refresh token reuse")
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE event = 'refresh_token.reused'").Scan(&n); err != nil || n != 1 {
		t.Errorf("audited %d reuses: %v", n, err)
	}
}

// Whether refresh tokens are issued is the Application's setting;
// offline_access changes nothing.
func TestRefreshTokensFollowTheApplication(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	_, page := e.authorize("&scope=openid+offline_access")
	resp, _ := e.submit(page, "owner", "password1")
	if tok := e.exchange(clientID, callback, e.code(resp)); tok.RefreshToken == "" {
		t.Error("offline_access: no refresh token")
	}

	if _, err := e.pool.Exec(context.Background(), "UPDATE applications SET refresh_tokens = false WHERE client_id = $1", clientID); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"openid", "openid offline_access"} {
		resp, _ := e.authorize("&scope=" + url.QueryEscape(scope))
		if tok := e.exchange(clientID, callback, e.code(resp)); tok.RefreshToken != "" {
			t.Errorf("%s: refresh token issued with refresh tokens off", scope)
		}
	}
}

// Revoking an OIDC refresh token ends that grant, not the browser Session.
func TestRevokeRefreshToken(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	tok := e.signIn()
	resp, body := e.do("POST", "/revoke", url.Values{"token": {tok.RefreshToken}, "client_id": {clientID}})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d %s", resp.StatusCode, body)
	}
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "invalid_grant" {
		t.Errorf("refresh after revocation: %q, want invalid_grant", errCode)
	}
	if !e.signedIn() {
		t.Error("revoking a refresh token ended the browser Session")
	}
	// Unknown tokens are fine too (RFC 7009 §2.2).
	if resp, _ := e.do("POST", "/revoke", url.Values{"token": {"nope"}, "client_id": {clientID}}); resp.StatusCode != 200 {
		t.Errorf("revoke unknown token: %d", resp.StatusCode)
	}
}

// RP-Initiated Logout ends the browser Session and the refresh tokens under
// it. With the User's ID token as hint it goes straight through; without,
// the User confirms first.
func TestRPInitiatedLogout(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	tok := e.signIn()

	resp, _ := e.do("GET", "/logout?"+url.Values{
		"id_token_hint": {tok.IDToken}, "post_logout_redirect_uri": {afterLogout}, "state": {"st"},
	}.Encode(), nil)
	if loc := resp.Header.Get("Location"); loc != afterLogout+"?state=st" {
		t.Errorf("logout: %d %q", resp.StatusCode, loc)
	}
	if e.signedIn() {
		t.Error("browser Session survived logout")
	}
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "invalid_grant" {
		t.Errorf("refresh after logout: %q, want invalid_grant", errCode)
	}

	e.signIn()
	resp, page := e.do("GET", "/logout", nil)
	if resp.StatusCode != 200 || !actionRE.MatchString(page) {
		t.Fatalf("logout without hint: want a confirmation, got %d %s", resp.StatusCode, page)
	}
	if !e.signedIn() {
		t.Fatal("logged out before confirming")
	}
	resp, page = e.post(page, url.Values{"logout": {"1"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "已退出") {
		t.Errorf("confirm logout: %d %s", resp.StatusCode, page)
	}
	if e.signedIn() {
		t.Error("browser Session survived confirmed logout")
	}
}

// Logging in again as the same User renews the browser Session in place, so
// the refresh tokens under it keep working.
func TestReloginKeepsTheSession(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	tok := e.signIn()
	_, page := e.authorize("&prompt=login")
	resp, _ := e.submit(page, "owner", "password1")
	e.code(resp)
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "" {
		t.Errorf("refresh after re-login: %q", errCode)
	}
}

// Disabling a User (as the Management API does) ends their Sessions at
// once: refresh tokens and the browser too; they cannot sign in again until
// restored.
func TestDisablingAUserEndsTheirSessions(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	tok := e.signIn()
	var sub string
	if err := e.pool.QueryRow(context.Background(), "SELECT user_id FROM identifiers WHERE value = 'owner'").Scan(&sub); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(e.pool)
	if _, err := q.SetUserDisabled(context.Background(), sqlc.SetUserDisabledParams{UserID: sub, Disabled: true, By: "ADMIN"}); err != nil {
		t.Fatal(err)
	}

	if _, errCode := e.refresh(tok.RefreshToken); errCode != "invalid_grant" {
		t.Errorf("refresh: %q, want invalid_grant", errCode)
	}
	if e.signedIn() {
		t.Error("browser Session survived")
	}
	_, page := e.authorize("")
	if _, body := e.submit(page, "owner", "password1"); !strings.Contains(body, "已被管理员禁用") {
		t.Errorf("hosted login: %.300s", body)
	}
	if r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}}); r.Status != 400 || r.Code != "" {
		t.Errorf("direct login: %+v", r)
	}

	if _, err := q.SetUserDisabled(context.Background(), sqlc.SetUserDisabledParams{UserID: sub, Disabled: false, By: "ADMIN"}); err != nil {
		t.Fatal(err)
	}
	if r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}}); r.Status != 200 {
		t.Errorf("restored: %+v", r)
	}
}

// A Session keeps the IP and User-Agent it was last used from: signing in
// writes them, a refresh overwrites them, and a User-Agent is cut to 512
// bytes.
func TestSessionRemembersItsDevice(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.ua = "Mozilla/5.0 (Macintosh) Chrome/130.0"
	tok := e.signIn()
	device := func() (string, string) {
		t.Helper()
		var sub string
		if err := e.pool.QueryRow(context.Background(), "SELECT user_id FROM identifiers WHERE value = 'owner'").Scan(&sub); err != nil {
			t.Fatal(err)
		}
		rows, err := sqlc.New(e.pool).UserSessions(context.Background(), sub)
		if err != nil || len(rows) != 1 {
			t.Fatalf("sessions: %+v %v", rows, err)
		}
		return rows[0].Ip.String, rows[0].UserAgent.String
	}
	if ip, ua := device(); ip != "127.0.0.1" || ua != e.ua {
		t.Errorf("after sign-in: %q %q", ip, ua)
	}

	e.ua = "App/1.0 " + strings.Repeat("x", 600)
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "" {
		t.Fatal(errCode)
	}
	if _, ua := device(); ua != e.ua[:512] {
		t.Errorf("after refresh: %d bytes %.40q", len(ua), ua)
	}
}

// Fifty failures in an hour lock an IP out of logging in, whichever flow.
func TestIPLockout(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO login_failures (key) SELECT 'ip:127.0.0.1' FROM generate_series(1, 49)"); err != nil {
		t.Fatal(err)
	}
	if r := e.challenge(url.Values{"username": {"nobody"}, "password": {"x"}, "altcha": {e.solve()}}); r.Status != 400 {
		t.Fatalf("50th failure: %+v", r)
	}
	_, page := e.authorize("")
	if _, body := e.submit(page, "owner", "password1"); !strings.Contains(body, "1 小时后再试") {
		t.Errorf("hosted login: %.300s", body)
	}
}
