package account_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/identity"
)

type loginRow struct {
	At          time.Time  `json:"at"`
	Result      string     `json:"result"`
	Method      string     `json:"method"`
	TwoFactor   bool       `json:"twoFactor"`
	Application string     `json:"application"`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"userAgent"`
	LockedUntil *time.Time `json:"lockedUntil"`
}

type logins struct {
	Logins      []loginRow `json:"logins"`
	FailedCount int        `json:"failedCount"`
}

const chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// 最近登录 lists the User's own sign-ins, failures and lockouts of the last
// 30 days, newest first.
func TestRecentLogins(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	e.user("ALICE", "phone:+8613800138000")
	e.user("BOB", "phone:+8613900139000")
	e.password("ALICE", "correct horse battery")
	tok := e.signIn("ALICE", 0)
	ids := identity.New(e.pool, e.keyring)
	var empty logins
	if c := e.call("GET", tok, "/v1/account/logins", nil, &empty); c != 200 || empty.Logins == nil || len(empty.Logins) != 0 || empty.FailedCount != 0 {
		t.Fatalf("no logins yet: %d %+v", c, empty)
	}

	from := identity.Attempt{ClientID: "polaris-account", IP: "203.0.113.5", UA: chrome}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(ids.LoginSucceeded(ctx, identity.Attempt{ClientID: "gone-app", IP: "203.0.113.9"}, "ALICE", []string{"otp"}))
	must(ids.LoginSucceeded(ctx, from, "BOB", []string{"pwd"}))
	must(ids.LoginSucceeded(ctx, from, "ALICE", []string{"pwd"}))
	if _, err := e.pool.Exec(ctx, `UPDATE audit_log SET at = now() - interval '31 days' WHERE sub = 'ALICE' AND detail->'amr' = '["pwd"]'`); err != nil {
		t.Fatal(err)
	}
	if _, err := ids.Password(ctx, from, "+8613800138000", "wrong"); !errors.Is(err, identity.ErrBadCredentials) {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := ids.CheckPassword(ctx, from, "+8613800138000", "wrong"); err == nil {
			t.Fatal("wrong password accepted")
		}
	}
	must(ids.LoginSucceeded(ctx, from, "ALICE", []string{"pwd", "otp", "mfa"}))

	var got logins
	if c := e.call("GET", tok, "/v1/account/logins", nil, &got); c != 200 {
		t.Fatalf("list: %d", c)
	}
	if got.FailedCount != 1 || len(got.Logins) != 4 {
		t.Fatalf("logins: %+v", got)
	}
	newest, locked, failed, gone := got.Logins[0], got.Logins[1], got.Logins[2], got.Logins[3]
	if newest.Result != "succeeded" || newest.Method != "password" || !newest.TwoFactor ||
		newest.Application != "Polaris 账号中心" || newest.IP != "203.0.113.5" || newest.UserAgent != chrome {
		t.Errorf("password + 两步验证: %+v", newest)
	}
	if locked.Result != "locked" || locked.Method != "" || locked.LockedUntil == nil || !locked.LockedUntil.After(time.Now()) {
		t.Errorf("lockout: %+v", locked)
	}
	if failed.Result != "failed" || failed.Method != "password" || failed.TwoFactor {
		t.Errorf("wrong password: %+v", failed)
	}
	if gone.Application != "gone-app" || gone.Method != "code" || gone.UserAgent != "" {
		t.Errorf("deleted Application: %+v", gone)
	}
}

// Past 50 only the newest come back; failedCount still counts them all.
func TestRecentLoginsKeepTheNewest50(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	if _, err := e.pool.Exec(ctx, `
		INSERT INTO audit_log (event, sub, detail, at)
		SELECT 'login.failed', 'ALICE', '{"method":"code"}', now() - n * interval '1 minute' FROM generate_series(1, 55) n`); err != nil {
		t.Fatal(err)
	}
	var got logins
	if c := e.call("GET", tok, "/v1/account/logins", nil, &got); c != 200 || len(got.Logins) != 50 || got.FailedCount != 55 {
		t.Fatalf("%d: %d logins, %d failed", c, len(got.Logins), got.FailedCount)
	}
	if !got.Logins[0].At.After(got.Logins[49].At) {
		t.Errorf("not newest first: %v .. %v", got.Logins[0].At, got.Logins[49].At)
	}
}
