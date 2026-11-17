package account_test

import (
	"testing"
	"time"
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

// With Passkey login off a Passkey is no factor at all: deleting one of two
// is refused while 两步验证 has nothing else.
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
	if c := e.call("DELETE", tok, "/v1/account/passkeys/"+first, nil, nil); c != 409 {
		t.Errorf("delete one of two Passkeys, Passkey login off: %d, want 409", c)
	}
}
