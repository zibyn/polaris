package login_test

import (
	"bytes"
	"context"
	"html"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/passkey/passkeytest"
	"github.com/zibyn/polaris/internal/twofactor"
)

// passkeyOnlyOwner bootstraps owner with password1 and a Passkey of a's, and
// turns 两步验证 on with the Passkey alone; it returns the 恢复码.
func (e *env) passkeyOnlyOwner(a *passkeytest.Authenticator) []string {
	e.t.Helper()
	e.bootstrap("owner", "password1")
	var sub string
	if err := e.pool.QueryRow(context.Background(), "SELECT user_id FROM identifiers WHERE value = 'owner'").Scan(&sub); err != nil {
		e.t.Fatal(err)
	}
	enrollPasskey(e.t, e, a, sub)
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	codes, err := twofactor.New(e.pool, keyring).Enable(context.Background(), sub)
	if err != nil {
		e.t.Fatal(err)
	}
	return codes
}

// A User whose 两步验证 is on by a Passkey alone is asked for the second
// step after the password: the page opens on the 恢复码 form, with no TOTP
// to switch to, and offers the Passkey. A TOTP code is no way past it.
func TestHostedPasskeyOnlyTwoFactor(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	codes := e.passkeyOnlyOwner(a)

	_, page := e.authorize("")
	_, page = e.submit(page, "owner", "password1")
	if !strings.Contains(page, `name="recovery_code"`) || strings.Contains(page, totpForm) || strings.Contains(page, "使用验证器") {
		t.Fatalf("want the 恢复码 form: %s", page)
	}
	_, ok := optionsOf(t, page)
	if !ok {
		t.Fatalf("no Passkey offered: %s", page)
	}
	resp, page := e.post(page, url.Values{"op": {"totp"}, "totp": {"123456"}})
	if resp.StatusCode/100 == 3 || !strings.Contains(html.UnescapeString(page), twofactor.ErrCode.Error()) {
		t.Fatalf("TOTP code with none added: %d %s", resp.StatusCode, page)
	}

	options, _ := optionsOf(t, page)
	a.SignCount = 1
	resp, _ = e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if amr, _ := e.idToken(e.code(resp))["amr"].([]any); !slices.Equal(amr, []any{"pwd", "hwk", "mfa"}) {
		t.Fatalf("amr after the Passkey: %v", amr)
	}

	e.newBrowser()
	_, page = e.authorize("")
	_, page = e.submit(page, "owner", "password1")
	resp, _ = e.post(page, url.Values{"op": {"totp"}, "recovery_code": {codes[0]}})
	if amr, _ := e.idToken(e.code(resp))["amr"].([]any); !slices.Equal(amr, []any{"pwd", "otp", "mfa"}) {
		t.Fatalf("amr after a 恢复码: %v", amr)
	}
}

// Over the direct API the same User finishes with a 恢复码; a TOTP code is
// refused, not let through: at next passkey, recovery_code works as at
// next totp.
func TestDirectPasskeyOnlyTwoFactorRecoveryCode(t *testing.T) {
	e := start(t)
	const phone = "+8613800138000"
	sub := passkeyUser(t, e, passkeytest.New(t))
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	codes, err := twofactor.New(e.pool, keyring).Enable(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}

	r := directSecondStep(t, e, phone)
	if r.Status != 403 || r.Error != "insufficient_authorization" || r.Next != "passkey" {
		t.Fatalf("want next passkey: %+v", r)
	}
	as := r.AuthSession
	if r := e.challenge(url.Values{"auth_session": {as}, "totp": {"123456"}}); r.Status != 400 || r.AuthSession != as {
		t.Fatalf("TOTP code with none added: %+v", r)
	}
	done := e.challenge(url.Values{"auth_session": {as}, "recovery_code": {codes[0]}})
	if done.Status != 200 {
		t.Fatalf("recovery code: %+v", done)
	}
	if amr, _ := e.claims(e.exchange(clientID, "", done.Code).IDToken)["amr"].([]any); !slices.Equal(amr, []any{"sms", "otp", "mfa"}) {
		t.Errorf("amr: %v", amr)
	}
}
