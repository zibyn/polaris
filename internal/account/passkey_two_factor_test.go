package account_test

import (
	"context"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/passkey/passkeytest"
)

// twoFactorTOTP is whether me says the User has a TOTP.
func (e *env) twoFactorTOTP(tok string) bool {
	e.t.Helper()
	var got struct {
		TwoFactor struct {
			TOTP bool `json:"totp"`
		} `json:"twoFactor"`
	}
	if c := e.call("GET", tok, "/v1/account/me", nil, &got); c != 200 {
		e.t.Fatalf("me: %d", c)
	}
	return got.TwoFactor.TOTP
}

// A User with a Passkey and no TOTP turns 两步验证 on with the Passkey
// alone and gets the 10 recovery codes; a TOTP can then be added and
// removed on its own, which leaves the recovery codes and 两步验证 as they
// were. The last Passkey can't go while it is all 两步验证 has.
func TestEnableTwoFactorWithPasskey(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	tok := e.signIn("ALICE", 0)

	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 422 {
		t.Errorf("turn on without a Passkey: %d", c)
	}
	last := e.passkey("ALICE", "手机")
	e.setPasskeyLogin(false)
	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 422 {
		t.Errorf("turn on while Passkey login is off: %d", c)
	}
	e.setPasskeyLogin(true)
	if c := e.call("POST", e.signIn("ALICE", time.Hour), "/v1/account/2fa", nil, nil); c != 403 {
		t.Errorf("turn on without reauthentication: %d", c)
	}

	var codes recoveryCodes
	if c := e.call("POST", tok, "/v1/account/2fa", nil, &codes); c != 200 {
		t.Fatalf("turn on with a Passkey: %d", c)
	}
	checkRecoveryCodes(t, codes.RecoveryCodes)
	if got := e.twoFactorOf(tok); !got.Enabled || got.RecoveryCodesLeft != 10 || e.twoFactorTOTP(tok) {
		t.Errorf("after: %+v", got)
	}
	if c := e.call("POST", tok, "/v1/account/2fa", nil, nil); c != 409 {
		t.Errorf("turn on while on: %d", c)
	}
	e.audited(t, "mfa.enabled", 1)

	if c := e.call("DELETE", tok, "/v1/account/passkeys/"+last, nil, nil); c != 409 {
		t.Errorf("delete the last Passkey, nothing else: %d, want 409", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa/totp", nil, nil); c != 404 {
		t.Errorf("remove a TOTP there isn't: %d, want 404", c)
	}

	// Adding a TOTP keeps the recovery codes and is no second turning on.
	var added recoveryCodes
	var setup totpSetup
	if c := e.call("POST", tok, "/v1/account/2fa/totp", nil, &setup); c != 200 {
		t.Fatalf("begin TOTP: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/2fa/totp/confirm", map[string]string{"code": totp(t, setup.Secret, time.Now())}, &added); c != 200 || len(added.RecoveryCodes) != 0 {
		t.Fatalf("add TOTP: %d %v", c, added.RecoveryCodes)
	}
	if got := e.twoFactorOf(tok); !got.Enabled || got.RecoveryCodesLeft != 10 || !e.twoFactorTOTP(tok) {
		t.Errorf("after adding the TOTP: %+v", got)
	}
	e.audited(t, "mfa.enabled", 1)
	e.audited(t, "totp.added", 1)

	// And it goes again on its own.
	if c := e.call("DELETE", tok, "/v1/account/2fa/totp", nil, nil); c != 204 {
		t.Fatalf("remove TOTP: %d", c)
	}
	if got := e.twoFactorOf(tok); !got.Enabled || got.RecoveryCodesLeft != 10 || e.twoFactorTOTP(tok) {
		t.Errorf("after removing the TOTP: %+v", got)
	}
	e.audited(t, "totp.removed", 1)

	// With a TOTP, the last Passkey may go; then the TOTP may not.
	e.enableTwoFactor(tok)
	if c := e.call("DELETE", tok, "/v1/account/passkeys/"+last, nil, nil); c != 204 {
		t.Errorf("delete the last Passkey with a TOTP: %d", c)
	}
	if c := e.call("DELETE", tok, "/v1/account/2fa/totp", nil, nil); c != 409 {
		t.Errorf("remove the TOTP, no Passkey left: %d, want 409", c)
	}
	if c := e.call("DELETE", e.signIn("ALICE", time.Hour), "/v1/account/2fa/totp", nil, nil); c != 403 {
		t.Errorf("remove TOTP without reauthentication: %d", c)
	}
}

// With 两步验证 on by a Passkey alone, the Passkey or a recovery code
// reauthenticates; a TOTP code (there is none), a code to an Identifier and
// the password are refused.
func TestReauthenticationWithPasskeyTwoFactor(t *testing.T) {
	e := start(t)
	e.user("ALICE", "phone:+8613800138000")
	e.password("ALICE", "password1")
	tok := e.signIn("ALICE", 0)
	a := passkeytest.New(t)
	a.Origin, a.UserHandle = e.issuer, []byte("ALICE")
	if code, _ := e.enroll(tok, a); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	var codes recoveryCodes
	if c := e.call("POST", tok, "/v1/account/2fa", nil, &codes); c != 200 {
		t.Fatalf("turn on: %d", c)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'on'; UPDATE sessions SET auth_time = now() - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}

	if c := e.call("POST", tok, "/v1/account/reauth/code", map[string]string{"kind": "phone"}, nil); c != 422 {
		t.Errorf("send reauth code: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"password": "password1"}, nil); c != 422 {
		t.Errorf("reauth by password: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"totp": "123456"}, nil); c != 422 {
		t.Errorf("reauth by TOTP, none added: %d", c)
	}
	if c := e.call("POST", tok, "/v1/account/reauth", map[string]string{"recoveryCode": codes.RecoveryCodes[0]}, nil); c != 204 {
		t.Errorf("reauth by recovery code: %d", c)
	}
	options := e.passkeyReauthOptions(tok, 200)
	a.SignCount = 1
	if code := e.reauthPasskey(tok, a.Assert(options)); code != 204 {
		t.Errorf("reauth by Passkey: %d", code)
	}
}
