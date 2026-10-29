package login_test

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/login"
)

// event is an audit event as stored.
type event struct {
	Sub    string
	Detail map[string]any
}

// events returns the audit events named name, oldest first.
func (e *env) events(name string) []event {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "SELECT COALESCE(sub, ''), detail FROM audit_log WHERE event = $1 ORDER BY id", name)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []event
	for rows.Next() {
		var ev event
		var raw []byte
		if err := rows.Scan(&ev.Sub, &raw); err != nil {
			e.t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &ev.Detail); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func (e *env) sub(identifier string) string {
	e.t.Helper()
	var sub string
	if err := e.pool.QueryRow(context.Background(), "SELECT user_id FROM identifiers WHERE value = $1", identifier).Scan(&sub); err != nil {
		e.t.Fatal(err)
	}
	return sub
}

// wantSucceeded checks ev is a login of sub through client with amr, from
// the test browser.
func wantSucceeded(t *testing.T, ev event, sub, client string, amr ...string) {
	t.Helper()
	var got []string
	for _, a := range ev.Detail["amr"].([]any) {
		got = append(got, a.(string))
	}
	if ev.Sub != sub || ev.Detail["client_id"] != client || !slices.Equal(got, amr) ||
		ev.Detail["ip"] != "127.0.0.1" || ev.Detail["ua"] != "test-browser" {
		t.Errorf("login.succeeded %+v, want sub %s client %s amr %v", ev, sub, client, amr)
	}
}

// Each hosted login records login.succeeded, a re-login in the same browser
// too; signing in silently to another Application and refreshing do not.
func TestHostedLoginIsAudited(t *testing.T) {
	e := start(t)
	e.ua = "test-browser"
	e.bootstrap("owner", "password1")
	sub := e.sub("owner")

	tok := e.signIn()
	got := e.events("login.succeeded")
	if len(got) != 1 {
		t.Fatalf("password login: %d events", len(got))
	}
	wantSucceeded(t, got[0], sub, clientID, "pwd")

	_, page := e.authorize("&prompt=login")
	resp, _ := e.submit(page, "owner", "password1")
	e.code(resp)
	if got := e.events("login.succeeded"); len(got) != 2 {
		t.Fatalf("re-login: %d events", len(got))
	}

	resp, _ = e.authorizeAs(login.ConsoleClientID, e.issuer+"/console/callback", "&prompt=none")
	e.code(resp)
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "" {
		t.Fatal(errCode)
	}
	if got := e.events("login.succeeded"); len(got) != 2 {
		t.Errorf("silent login or refresh audited: %d events", len(got))
	}
}

// A User-Agent is kept to 512 bytes, as a Session keeps it, without a
// character cut in half.
func TestLoginAuditTruncatesUserAgent(t *testing.T) {
	e := start(t)
	e.ua = strings.Repeat("浏", 300)
	_, page := e.authorize("")
	resp, _ := e.codeLogin(page, "+8613800138000", "+8613800138000")
	e.code(resp)
	got := e.events("login.succeeded")
	if len(got) != 1 || got[0].Detail["ua"] != strings.Repeat("浏", 170) {
		t.Errorf("ua: %+v", got)
	}
}

// wantFailed checks the audited failures are, in order, of sub by methods.
func (e *env) wantFailed(sub string, methods ...string) {
	e.t.Helper()
	var got []string
	for _, ev := range e.events("login.failed") {
		got = append(got, ev.Detail["method"].(string))
		if ev.Sub != sub || ev.Detail["client_id"] != clientID || ev.Detail["ip"] != "127.0.0.1" || ev.Detail["ua"] != "test-browser" {
			e.t.Errorf("login.failed %+v, want sub %s", ev, sub)
		}
	}
	if !slices.Equal(got, methods) {
		e.t.Errorf("login.failed methods %v, want %v", got, methods)
	}
}

// A wrong password, code, TOTP code or 恢复码 on the hosted page is
// audited on the User it was tried on; 两步验证 logs in once, after the
// second step. A wrong password for nobody is not audited, only counted.
func TestHostedLoginFailuresAreAudited(t *testing.T) {
	e := start(t)
	e.ua = "test-browser"
	e.bootstrap("owner", "password1")
	sub := e.sub("owner")
	_, codes := e.twoFactor(sub)
	if err := e.ids.AddIdentifier(context.Background(), sub, "phone", "+8613800138000"); err != nil {
		t.Fatal(err)
	}

	_, page := e.authorize("")
	failures := e.ipFailures()
	e.submit(page, "nobody", "wrong")
	if e.ipFailures() != failures+1 {
		t.Error("unknown username not counted against the IP")
	}
	e.submit(page, "owner", "wrong")
	_, sent := e.post(page, url.Values{"op": {"send"}, "identifier": {"+8613800138000"}, "altcha": {e.solve()}})
	if e.inbox.take("+8613800138000") == "" {
		t.Fatalf("no code sent: %s", sent)
	}
	e.post(sent, url.Values{"op": {"verify"}, "identifier": {"+8613800138000"}, "code": {"000000"}})

	_, page = e.submit(page, "owner", "password1")
	if got := e.events("login.succeeded"); len(got) != 0 {
		t.Errorf("audited before TOTP: %+v", got)
	}
	_, page = e.post(page, url.Values{"op": {"totp"}, "totp": {"000000"}})
	_, page = e.post(page, url.Values{"op": {"totp"}, "recovery_code": {"nope-nope"}})
	resp, _ := e.post(page, url.Values{"op": {"totp"}, "recovery_code": {codes[0]}})
	e.code(resp)
	e.wantFailed(sub, "password", "code", "totp", "recovery_code")
	if got := e.events("login.succeeded"); len(got) != 1 {
		t.Fatalf("after TOTP: %d events", len(got))
	} else {
		wantSucceeded(t, got[0], sub, clientID, "pwd", "otp", "mfa")
	}
}

// The direct auth API audits its logins and failures like the hosted page.
func TestDirectLoginIsAudited(t *testing.T) {
	e := start(t)
	e.ua = "test-browser"
	e.bootstrap("owner", "password1")
	sub := e.sub("owner")

	e.challenge(url.Values{"username": {"nobody"}, "password": {"wrong"}, "altcha": {e.solve()}})
	e.challenge(url.Values{"username": {"owner"}, "password": {"wrong"}, "altcha": {e.solve()}})
	if r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}}); r.Status != 200 {
		t.Fatalf("password: %+v", r)
	}
	e.wantFailed(sub, "password")
	got := e.events("login.succeeded")
	if len(got) != 1 {
		t.Fatalf("%d events", len(got))
	}
	wantSucceeded(t, got[0], sub, clientID, "pwd")

	// A wrong code for a phone number nobody holds is nobody's failure.
	sent := e.challenge(url.Values{"identifier": {"+8613900139000"}, "altcha": {e.solve()}})
	e.challenge(url.Values{"auth_session": {sent.AuthSession}, "code": {"000000"}})
	e.wantFailed(sub, "password")
}

// Five wrong passwords in a row audit the lockout with when it ends.
func TestPasswordLockoutIsAuditedWithItsEnd(t *testing.T) {
	e := start(t)
	e.ua = "test-browser"
	e.bootstrap("owner", "password1")
	sub := e.sub("owner")
	_, page := e.authorize("")
	for range 6 {
		e.submit(page, "owner", "wrong")
	}
	e.wantFailed(sub, "password", "password", "password", "password", "password", "password")
	got := e.events("login.password_locked")
	if len(got) != 1 {
		t.Fatalf("%d lockouts", len(got))
	}
	var until time.Time
	if err := e.pool.QueryRow(context.Background(), "SELECT until FROM lockouts WHERE key = 'sub:' || $1", sub).Scan(&until); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, got[0].Detail["until"].(string))
	if err != nil || !at.Equal(until) || got[0].Sub != sub || got[0].Detail["client_id"] != clientID ||
		got[0].Detail["ip"] != "127.0.0.1" || got[0].Detail["ua"] != "test-browser" {
		t.Errorf("login.password_locked %+v, want until %v", got[0], until)
	}
}
