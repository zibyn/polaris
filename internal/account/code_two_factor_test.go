package account_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/identity"
)

// codeFactors is what me says of the User's 短信 and 邮箱 second factors.
func (e *env) codeFactors(tok string) (sms, email bool) {
	e.t.Helper()
	var got struct {
		TwoFactor struct {
			SMS   bool `json:"sms"`
			Email bool `json:"email"`
		} `json:"twoFactor"`
	}
	if c := e.call("GET", tok, "/v1/account/me", nil, &got); c != 200 {
		e.t.Fatalf("me: %d", c)
	}
	return got.TwoFactor.SMS, got.TwoFactor.Email
}

// A User with a phone number and another way in adds it as a second factor
// and turns 两步验证 on with it alone, getting the 10 recovery codes; adding
// and removing the email after keeps them. The last factor cannot go (ADR
// 0038).
func TestCodeSecondFactors(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000", "email:alice@example.com")
	tok := e.signIn("ALICE", 0)

	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 422 {
		t.Errorf("turn on with no factor: %d", c)
	}
	if c := e.call("PUT", e.signIn("ALICE", time.Hour), "/v1/account/2fa/identifiers/phone", nil, nil); c != 403 {
		t.Errorf("add without reauthentication: %d", c)
	}
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("add SMS: %d", c)
	}
	if sms, email := e.codeFactors(tok); !sms || email {
		t.Errorf("me after adding SMS: %v %v", sms, email)
	}
	var codes recoveryCodes
	if c := e.call("POST", tok, "/v1/account/2fa", nil, &codes); c != 200 {
		t.Fatalf("turn on with SMS: %d", c)
	}
	checkRecoveryCodes(t, codes.RecoveryCodes)
	e.audited(t, "sms.added", 1)
	e.audited(t, "mfa.enabled", 1)

	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/email", nil, nil); c != 204 {
		t.Fatalf("add email: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("remove SMS: %d", c)
	}
	if got := e.twoFactorOf(tok); !got.Enabled || got.RecoveryCodesLeft != 10 {
		t.Errorf("after adding and removing: %+v", got)
	}
	e.audited(t, "email.added", 1)
	e.audited(t, "sms.removed", 1)
	if c := e.call("DELETE", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 404 {
		t.Errorf("remove SMS again: %d, want 404", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa/identifiers/email", nil, nil); c != 409 {
		t.Errorf("remove the last factor: %d, want 409", c)
	}
	if sms, email := e.codeFactors(tok); sms || !email {
		t.Errorf("me at the end: %v %v", sms, email)
	}
}

// A phone number that is the User's only way in protects nothing as a
// second factor: every login by it would leave the recovery codes alone.
func TestOnlyWayInIsNoSecondFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 422 {
		t.Errorf("add the only way in: %d, want 422", c)
	}
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/email", nil, nil); c != 422 {
		t.Errorf("add an email not bound: %d, want 422", c)
	}
	e.password("ALICE", "password1")
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Errorf("add with a password too: %d", c)
	}
}

// With Passkey login off a Passkey is no factor at all: deleting one leaves
// what 两步验证 can be passed with as it was, so it is not refused.
func TestPasskeysDoNotCountWhilePasskeyLoginIsOff(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)
	first := e.passkey("ALICE", "手机")
	e.passkey("ALICE", "电脑")
	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 200 {
		t.Fatalf("turn on with Passkeys: %d", c)
	}
	e.setPasskeyLogin(false)
	if c := e.call("DELETE", tok, "/v1/account/passkeys/"+first, nil, nil); c != 204 {
		t.Errorf("delete one of two Passkeys, Passkey login off: %d, want 204", c)
	}
}

// With the SMS Channel gone, the phone number is no factor 两步验证 can be
// passed with: removing it, as a factor or by unbinding it, leaves that as it
// was, so neither is refused though it was all 两步验证 had.
func TestRemovingAnUnusableFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000", "email:alice@example.com")
	tok := e.signIn("ALICE", 0)
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("add SMS: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 200 {
		t.Fatalf("turn on with SMS: %d", c)
	}
	if _, err := e.pool.Exec(context.Background(), "DELETE FROM channels WHERE kind = 'phone'"); err != nil {
		t.Fatal(err)
	}
	// me says so, for the account center not to hold the removal back.
	var me struct {
		TwoFactor struct {
			SMSChannel   bool `json:"smsChannel"`
			EmailChannel bool `json:"emailChannel"`
		} `json:"twoFactor"`
	}
	if c := e.call("GET", tok, "/v1/account/me", nil, &me); c != 200 || me.TwoFactor.SMSChannel || !me.TwoFactor.EmailChannel {
		t.Errorf("me with the phone Channel gone: %d %+v", c, me.TwoFactor)
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Errorf("remove SMS, its Channel gone: %d, want 204", c)
	}
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("add SMS again: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 204 {
		t.Errorf("unbind the phone number, its Channel gone: %d, want 204", c)
	}
	e.audited(t, "sms.removed", 2)
}

// smsOnly is ALICE with 两步验证 on by her phone number alone, in a Session
// in need of reauthentication.
func (e *env) smsOnly() string {
	e.t.Helper()
	e.user("ALICE", "phone:+8613800138000")
	e.password("ALICE", "password1")
	tok := e.signIn("ALICE", 0)
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		e.t.Fatalf("add SMS: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 200 {
		e.t.Fatalf("turn on with SMS: %d", c)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE sessions SET auth_time = now() - interval '1 hour'"); err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// With 两步验证 on by SMS alone, a code to the phone number reauthenticates
// as sms + mfa; the email, not added, sends nothing (ADR 0038).
func TestReauthenticationWithSMSFactor(t *testing.T) {
	e := start(t)
	tok := e.smsOnly()
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO identifiers (user_id, kind, value) VALUES ('ALICE', 'email', 'alice@example.com')"); err != nil {
		t.Fatal(err)
	}

	if c := e.call("POST", tok, "/v1/account/reauth/code", map[string]string{"kind": "email"}, nil); c != 422 {
		t.Errorf("send to the email, not a factor: %d, want 422", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth/code", map[string]string{"kind": "phone"}, nil); c != 204 {
		t.Fatalf("send to the phone: %d", c)
	}
	code := e.inbox.take("+8613800138000")
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"kind": "phone", "code": "000000"}, nil); c != 422 {
		t.Errorf("wrong code: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"kind": "email", "code": code}, nil); c != 422 {
		t.Errorf("the code, by the email: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"kind": "phone", "code": code}, nil); c != 204 {
		t.Fatalf("reauth by SMS: %d", c)
	}
	var amr []string
	if err := e.pool.QueryRow(context.Background(), "SELECT amr FROM sessions").Scan(&amr); err != nil ||
		!slices.Equal(amr, []string{"sms", "mfa"}) {
		t.Errorf("amr %v: %v", amr, err)
	}
	if got := e.logins("login.failed"); !slices.Equal(got, []string{"code"}) {
		t.Errorf("login.failed: %v", got)
	}
}

// Wrong codes at reauthentication count toward 2fa:<sub>: the tenth locks
// 两步验证, and the second step of a login, from anywhere, is refused too.
func TestReauthenticationSMSFactorLock(t *testing.T) {
	e := start(t)
	tok := e.smsOnly()
	for i := range 10 {
		if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"kind": "phone", "code": "000000"}, nil); c != 422 {
			t.Fatalf("wrong code %d: %d", i+1, c)
		}
	}
	err := identity.New(e.pool, e.keyring).SecondFactor(context.Background(),
		identity.Attempt{ClientID: "app", IP: "198.51.100.7"}, "ALICE", "totp", func() error { return nil })
	if !errors.Is(err, identity.ErrTwoFactorLocked) {
		t.Errorf("login second step after the lock: %v", err)
	}
}

// Unbinding the phone number that is 两步验证's last factor is refused; with
// another factor left it goes, and the factor with it (ADR 0038).
func TestUnbindCodeSecondFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000", "email:alice@example.com")
	tok := e.signIn("ALICE", 0)
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("add SMS: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 200 {
		t.Fatalf("turn on with SMS: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 409 {
		t.Errorf("unbind the last factor's phone number: %d, want 409", c)
	}
	if c := e.call("PUT", tok, "/v1/account/2fa/identifiers/email", nil, nil); c != 204 {
		t.Fatalf("add email: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/identifiers/phone", nil, nil); c != 204 {
		t.Fatalf("unbind the phone number with the email left: %d", c)
	}
	e.audited(t, "sms.removed", 1)
	if sms, email := e.codeFactors(tok); sms || !email {
		t.Errorf("me after unbinding: %v %v", sms, email)
	}
}
