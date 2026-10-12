package management_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/zibyn/stars-auth/internal/management"
)

type settings struct {
	PasswordLogin       string `json:"passwordLogin"`
	RequirePhone        bool   `json:"requirePhone"`
	DailySendLimit      int    `json:"dailySendLimit"`
	TermsURL            string `json:"termsUrl"`
	PrivacyURL          string `json:"privacyUrl"`
	TermsVersion        string `json:"termsVersion"`
	AuditRetentionDays  int    `json:"auditRetentionDays"`
	AdminsNeedTwoFactor bool   `json:"adminsNeedTwoFactor"`
	PasskeyLogin        bool   `json:"passkeyLogin"`
}

// problem calls GET path and returns the status and the error's code.
func (e *env) problem(token, path string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.issuer+management.Prefix+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	var body struct{ Code string }
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Code
}

// With 管理员必须启用两步验证 on, an admin without 两步验证 is turned away
// from every endpoint, with a code the console knows, until they turn it on.
// No admin turns the switch on without 两步验证 of their own.
func TestAdminsMustUseTwoFactor(t *testing.T) {
	e := start(t)
	e.user("CAROL", []string{"readonly"})
	owner, carol := e.token(e.owner, nil), e.token("CAROL", nil)
	policy := settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, AdminsNeedTwoFactor: true, PasskeyLogin: true}

	if code := e.call("PUT", owner, "/settings", policy, nil); code != 422 {
		t.Fatalf("turn on without 两步验证 of one's own: %d, want 422", code)
	}
	e.twoFactorOn(e.owner)
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("turn on: %d", code)
	}
	var got settings
	if code := e.get(owner, "/settings", &got); code != 200 || got != policy {
		t.Errorf("after turning on: %d %+v", code, got)
	}

	for _, path := range []string{"/me", "/users", "/settings"} {
		if code, err := e.problem(carol, path); code != 403 || err != "two_factor_required" {
			t.Errorf("CAROL without 两步验证, %s: %d %q", path, code, err)
		}
	}
	e.twoFactorOn("CAROL")
	if code := e.get(carol, "/me", nil); code != 200 {
		t.Errorf("CAROL with 两步验证: %d", code)
	}
	// Saving the policy again while the switch is on is fine.
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Errorf("save while on: %d", code)
	}
}

// A Passkey meets 管理员必须启用两步验证或 Passkey too: an admin with only a Passkey
// turns the switch on, and one is let into the Management API by their
// Passkey alone. The user detail says which way the requirement is met.
func TestPasskeyMeetsAdminsTwoFactor(t *testing.T) {
	e := start(t)
	e.user("CAROL", []string{"readonly"})
	e.passkey(e.owner, "工作电脑", false) // the owner has no TOTP, only a Passkey
	owner := e.token(e.owner, nil)

	policy := settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, AdminsNeedTwoFactor: true, PasskeyLogin: true}
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("turn on with only a Passkey: %d", code)
	}
	carol := e.token("CAROL", nil)
	if code, err := e.problem(carol, "/me"); code != 403 || err != "two_factor_required" {
		t.Errorf("CAROL with neither: %d %q", code, err)
	}
	e.passkey("CAROL", "手机", true)
	if code := e.get(carol, "/me", nil); code != 200 {
		t.Errorf("CAROL with a Passkey: %d", code)
	}

	var detail struct {
		TwoFactor          bool `json:"twoFactor"`
		TwoFactorOrPasskey bool `json:"twoFactorOrPasskey"`
	}
	if code := e.get(owner, "/users/CAROL", &detail); code != 200 || detail.TwoFactor || !detail.TwoFactorOrPasskey {
		t.Errorf("detail, met by a Passkey: %d %+v", code, detail)
	}
	e.twoFactorOn("CAROL")
	if code := e.get(owner, "/users/CAROL", &detail); code != 200 || !detail.TwoFactor || !detail.TwoFactorOrPasskey {
		t.Errorf("detail, met by 两步验证: %d %+v", code, detail)
	}
}

func TestAdminChangesLoginPolicy(t *testing.T) {
	e := start(t)
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)

	var got settings
	if code := e.get(ro, "/settings", &got); code != 200 || got != (settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, PasskeyLogin: true}) {
		t.Fatalf("defaults: %d %+v", code, got)
	}
	want := settings{
		PasswordLogin: "on", RequirePhone: true, DailySendLimit: 50,
		TermsURL: "https://example.com/terms", PrivacyURL: "https://example.com/privacy", TermsVersion: "2026-10",
		AuditRetentionDays: 30, PasskeyLogin: true,
	}
	if code := e.call("PUT", ro, "/settings", want, nil); code != 403 {
		t.Errorf("readonly PUT: %d, want 403", code)
	}
	if code := e.call("PUT", owner, "/settings", want, nil); code != 204 {
		t.Fatalf("PUT: %d", code)
	}
	if code := e.get(ro, "/settings", &got); code != 200 || got != want {
		t.Errorf("after PUT: %d %+v", code, got)
	}

	for name, bad := range map[string]settings{
		"version without URLs": {PasswordLogin: "on", DailySendLimit: 1, AuditRetentionDays: 1, TermsVersion: "1"},
		"URL not https":        {PasswordLogin: "on", DailySendLimit: 1, AuditRetentionDays: 1, TermsVersion: "1", TermsURL: "http://x", PrivacyURL: "https://x"},
		"URL without version":  {PasswordLogin: "on", DailySendLimit: 1, AuditRetentionDays: 1, TermsURL: "javascript:alert(1)"},
		"no retention":         {PasswordLogin: "on", DailySendLimit: 1},
		"unknown password":     {PasswordLogin: "some", DailySendLimit: 1, AuditRetentionDays: 1},
	} {
		if code := e.call("PUT", owner, "/settings", bad, nil); code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}
}

// The Passkey switch cannot be turned off while the admin turning it off
// satisfies 管理员必须启用两步验证或 Passkey only with a Passkey: with it off
// their Passkey stops counting and they would be locked out. Turning the
// requirement off in the same save lets it through
// (docs/spec/consoles.md#设置).
func TestPasskeySwitchRefusesToLockOutAnAdmin(t *testing.T) {
	e := start(t)
	e.passkey(e.owner, "工作电脑", false) // the owner has no TOTP, only a Passkey
	owner := e.token(e.owner, nil)
	on := settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, AdminsNeedTwoFactor: true, PasskeyLogin: true}
	if code := e.call("PUT", owner, "/settings", on, nil); code != 204 {
		t.Fatalf("turn the requirement on with only a Passkey: %d", code)
	}

	off := on
	off.PasskeyLogin = false
	if code := e.call("PUT", owner, "/settings", off, nil); code != 422 {
		t.Fatalf("turn the Passkey switch off with only a Passkey: %d, want 422", code)
	}
	both := off
	both.AdminsNeedTwoFactor = false
	if code := e.call("PUT", owner, "/settings", both, nil); code != 204 {
		t.Fatalf("turn both off: %d", code)
	}
}

// With the Passkey switch off, a Passkey stops satisfying 管理员必须启用两步
// 验证或 Passkey: an admin whose only way in is a Passkey is turned away, and
// the user detail says the requirement is no longer met.
func TestPasskeySwitchStopsCountingForAdmins(t *testing.T) {
	e := start(t)
	e.user("CAROL", []string{"readonly"})
	e.passkey("CAROL", "手机", true)
	e.twoFactorOn(e.owner) // the owner has a TOTP, so the switch may go off
	owner := e.token(e.owner, nil)

	policy := settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, AdminsNeedTwoFactor: true, PasskeyLogin: true}
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("turn the requirement on: %d", code)
	}
	carol := e.token("CAROL", nil)
	if code := e.get(carol, "/me", nil); code != 200 {
		t.Errorf("CAROL's Passkey lets her in: %d", code)
	}
	var detail struct {
		TwoFactor          bool `json:"twoFactor"`
		TwoFactorOrPasskey bool `json:"twoFactorOrPasskey"`
	}
	if code := e.get(owner, "/users/CAROL", &detail); code != 200 || detail.TwoFactor || !detail.TwoFactorOrPasskey {
		t.Errorf("detail, met by a Passkey: %d %+v", code, detail)
	}

	off := policy
	off.PasskeyLogin = false
	if code := e.call("PUT", owner, "/settings", off, nil); code != 204 {
		t.Fatalf("turn the Passkey switch off: %d", code)
	}
	if code, err := e.problem(carol, "/me"); code != 403 || err != "two_factor_required" {
		t.Errorf("CAROL with only a Passkey while off: %d %q", code, err)
	}
	if code := e.get(owner, "/users/CAROL", &detail); code != 200 || detail.TwoFactor || detail.TwoFactorOrPasskey {
		t.Errorf("detail, Passkey no longer counting: %d %+v", code, detail)
	}
}

// Turning password login off while the admin doing it has no other way to
// sign in would shut them out of the console for good, with no CLI to rescue
// them. 首次引导 gives the first owner a username and a password and nothing
// else, so the guard is what stands between a deployment and a lockout.
func TestPasswordLoginOffRefusesToLockOutAnAdmin(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)

	policy := settings{PasswordLogin: "on", DailySendLimit: 1000, AuditRetentionDays: 180, PasskeyLogin: true}
	if code := e.call("PUT", owner, "/settings", policy, nil); code != 204 {
		t.Fatalf("save with password login on: %d", code)
	}
	off := policy
	off.PasswordLogin = "off"

	// The owner has a username and a password, nothing else.
	if code := e.call("PUT", owner, "/settings", off, nil); code != 422 {
		t.Fatalf("turn it off with only a password: %d, want 422", code)
	}
	if code := e.get(owner, "/settings", &policy); code != 200 || policy.PasswordLogin != "on" {
		t.Errorf("the refused save still went through: %d %+v", code, policy)
	}

	// An email or a phone is another way in, so it goes through.
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO identifiers VALUES ($1, 'email', 'owner@example.com')", e.owner); err != nil {
		t.Fatal(err)
	}
	if code := e.call("PUT", owner, "/settings", off, nil); code != 204 {
		t.Fatalf("turn it off with an email too: %d", code)
	}
	// ...and back on for the rest of the test.
	on := policy
	if code := e.call("PUT", owner, "/settings", on, nil); code != 204 {
		t.Fatalf("turn it back on: %d", code)
	}

	// An External Identity at an enabled Provider counts. A disabled Provider
	// is nothing anyone could sign in with, so it does not.
	if code := e.call("POST", owner, "/providers", google(nil), nil); code != 204 {
		t.Fatalf("add a Provider: %d", code)
	}
	e.user("CAROL", []string{"admin"}, "username:carol")
	carol := e.token("CAROL", nil)
	if _, err := e.pool.Exec(context.Background(),
		"INSERT INTO external_identities (provider, subject, user_id) VALUES ('google', 'c', 'CAROL')"); err != nil {
		t.Fatal(err)
	}
	if code := e.call("PUT", carol, "/settings", off, nil); code != 204 {
		t.Fatalf("turn it off with a bound Provider: %d", code)
	}
	if code := e.call("POST", owner, "/providers/google/disable", nil, nil); code != 204 {
		t.Fatalf("disable the Provider: %d", code)
	}
	if code := e.call("PUT", carol, "/settings", off, nil); code != 422 {
		t.Errorf("turn it off with the Provider disabled: %d, want 422", code)
	}
}

func TestOwnerRotatesSigningKeys(t *testing.T) {
	e := start(t)
	e.user("ADMIN", []string{"admin"})
	owner, admin := e.token(e.owner, nil), e.token("ADMIN", nil)

	type key struct {
		Kid     string
		Current bool
	}
	var before, after struct{ Keys []key }
	if code := e.get(admin, "/signing-keys", &before); code != 200 || len(before.Keys) != 1 || !before.Keys[0].Current {
		t.Fatalf("keys: %d %+v", code, before)
	}
	if code := e.call("POST", admin, "/signing-keys/rotate", nil, nil); code != 403 {
		t.Errorf("admin rotates: %d, want 403", code)
	}
	if code := e.call("POST", owner, "/signing-keys/rotate", nil, nil); code != 204 {
		t.Fatalf("rotate: %d", code)
	}
	if code := e.get(admin, "/signing-keys", &after); code != 200 || len(after.Keys) != 2 ||
		!after.Keys[0].Current || after.Keys[1] != (key{Kid: before.Keys[0].Kid}) {
		t.Errorf("after rotate: %d %+v", code, after)
	}
	// The token signed before the rotation still works.
	if code := e.get(owner, "/me", nil); code != 200 {
		t.Errorf("old token: %d", code)
	}
}

func TestCleanupKeepsAuditForTheRetentionPeriod(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE settings SET audit_retention_days = 30;
		INSERT INTO audit_log (event, at) VALUES ('old', now() - interval '31 days'), ('recent', now() - interval '29 days')`); err != nil {
		t.Fatal(err)
	}
	if err := management.DeleteOldAudit(ctx, e.pool); err != nil {
		t.Fatal(err)
	}
	var events []string
	rows, _ := e.pool.Query(ctx, "SELECT event FROM audit_log WHERE event IN ('old', 'recent')")
	for rows.Next() {
		var ev string
		_ = rows.Scan(&ev)
		events = append(events, ev)
	}
	if len(events) != 1 || events[0] != "recent" {
		t.Errorf("left %v, want [recent]", events)
	}
}
