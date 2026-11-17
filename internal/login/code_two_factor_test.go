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
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/otp"
	"github.com/zibyn/polaris/internal/twofactor"
)

const (
	ownerPhone = "+8613800138000"
	ownerEmail = "owner@example.com"
)

// ownerCodeFactors bootstraps owner with password1, binds ownerPhone and
// ownerEmail, adds the kinds given as second factors and turns 两步验证 on
// by them; it returns owner's sub.
func (e *env) ownerCodeFactors(kinds ...string) string {
	e.t.Helper()
	ctx := context.Background()
	e.bootstrap("owner", "password1")
	var sub string
	if err := e.pool.QueryRow(ctx, "SELECT user_id FROM identifiers WHERE value = 'owner'").Scan(&sub); err != nil {
		e.t.Fatal(err)
	}
	q := sqlc.New(e.pool)
	for kind, value := range map[string]string{"phone": ownerPhone, "email": ownerEmail} {
		if err := q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: kind, Value: value}); err != nil {
			e.t.Fatal(err)
		}
	}
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	s := twofactor.New(e.pool, keyring)
	for _, kind := range kinds {
		if err := s.AddCode(ctx, sub, kind); err != nil {
			e.t.Fatal(err)
		}
	}
	if _, err := s.Enable(ctx, sub); err != nil {
		e.t.Fatal(err)
	}
	return sub
}

// passwordToSecondStep signs owner in by password, in a new browser, up to
// the 两步验证 step.
func (e *env) passwordToSecondStep() string {
	e.t.Helper()
	e.newBrowser()
	_, page := e.authorize("")
	_, page = e.submit(page, "owner", "password1")
	if !strings.Contains(page, "两步验证") {
		e.t.Fatalf("want the 两步验证 step: %s", page)
	}
	return page
}

// sendSecondStep asks for the second step's code by factor, clearing the
// 60-second limit of earlier sends first.
func (e *env) sendSecondStep(page, factor string) string {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
		e.t.Fatal(err)
	}
	_, page = e.post(page, url.Values{"op": {"send-2fa"}, "factor": {factor}})
	return page
}

func amrOf(claims map[string]any) []string {
	var amr []string
	for _, v := range claims["amr"].([]any) {
		amr = append(amr, v.(string))
	}
	return amr
}

// A User who added their phone number and email signs in by password and
// passes 两步验证 with a code to either: the page sends one only when asked,
// then takes it in a one-time-code field. The login methods of the
// Application do not matter, only that the Channel is there (ADR 0038).
func TestHostedSecondStepByCode(t *testing.T) {
	e := start(t)
	e.ownerCodeFactors("phone", "email")
	e.only(clientID, identity.MethodPassword) // no code login at all
	for _, c := range []struct{ factor, to, masked, amr string }{
		{"sms", ownerPhone, "138****8000", "sms"},
		{"email", ownerEmail, "o***@example.com", "otp"},
	} {
		page := e.passwordToSecondStep()
		if !strings.Contains(page, "发送验证码到 "+c.masked) || strings.Contains(page, `name="code"`) {
			t.Fatalf("%s: want a send button and no code field yet: %s", c.factor, page)
		}
		if e.inbox.take(c.to) != "" {
			t.Fatalf("%s: a code sent unasked", c.factor)
		}
		page = e.sendSecondStep(page, c.factor)
		code := e.inbox.take(c.to)
		if code == "" || !strings.Contains(page, `name="code" autocomplete="one-time-code"`) {
			t.Fatalf("%s: want a code sent and its field: %s", c.factor, page)
		}
		_, page = e.post(page, url.Values{"op": {"code-2fa"}, "factor": {c.factor}, "code": {"000000"}})
		if !strings.Contains(html.UnescapeString(page), otp.ErrWrongCode.Error()) || !strings.Contains(page, `name="code"`) {
			t.Fatalf("%s: wrong code: %s", c.factor, page)
		}
		resp, _ := e.post(page, url.Values{"op": {"code-2fa"}, "factor": {c.factor}, "code": {code}})
		if got := amrOf(e.idToken(e.code(resp))); !slices.Equal(got, []string{"pwd", c.amr, "mfa"}) {
			t.Errorf("%s: amr %v", c.factor, got)
		}
	}

	// Without the phone Channel there is no code to send by SMS.
	if _, err := e.pool.Exec(context.Background(), "DELETE FROM channels WHERE kind = 'phone'"); err != nil {
		t.Fatal(err)
	}
	page := e.passwordToSecondStep()
	if strings.Contains(page, "138****8000") || !strings.Contains(page, "o***@example.com") {
		t.Errorf("SMS offered with no phone Channel: %s", page)
	}
	if page = e.sendSecondStep(page, "sms"); e.inbox.take(ownerPhone) != "" {
		t.Errorf("sent by SMS with no phone Channel")
	}
}

// A code login does not offer a code over its own channel at the second
// step; with nothing else left, the 恢复码 is all there is, and the page says
// to sign in another way (ADR 0038).
func TestHostedSecondStepLeavesOutTheFirstChannel(t *testing.T) {
	e := start(t)
	e.ownerCodeFactors("phone", "email")
	_, page := e.authorize("")
	_, page = e.codeLogin(page, ownerPhone, ownerPhone)
	if strings.Contains(page, "138****8000") || !strings.Contains(page, "发送验证码到 o***@example.com") {
		t.Fatalf("an SMS login's second step: %s", page)
	}
	// Nor is it sent when asked anyway.
	if page = e.sendSecondStep(page, "sms"); e.inbox.take(ownerPhone) != "" {
		t.Errorf("sent the second step's code over the first factor's channel")
	}

	e.newBrowser()
	if _, err := e.pool.Exec(context.Background(), "UPDATE identifiers SET second_factor = false WHERE kind = 'email'"); err != nil {
		t.Fatal(err)
	}
	_, page = e.authorize("")
	_, page = e.codeLogin(page, ownerPhone, ownerPhone)
	if strings.Contains(page, "发送验证码到") || !strings.Contains(page, `name="recovery_code"`) || !strings.Contains(page, "改用其他方式登录") {
		t.Errorf("only the recovery code, and a hint, when the one factor is the first's channel: %s", page)
	}
}

// The second step's codes share the send limits of login codes, and wrong
// ones count as the TOTP's do: toward 2fa:<sub>, whose lock refuses a right
// code too, and toward the login's five tries.
func TestHostedSecondStepCodeLimits(t *testing.T) {
	e := start(t)
	sub := e.ownerCodeFactors("phone")
	ctx := context.Background()

	// A code login sent to the phone a moment ago: the second step must
	// wait out the same minute.
	_, first := e.authorize("")
	if _, err := e.pool.Exec(ctx, "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	e.post(first, url.Values{"op": {"send"}, "identifier": {ownerPhone}, "altcha": {e.solve()}})
	e.inbox.take(ownerPhone)
	page := e.passwordToSecondStep()
	_, page = e.post(page, url.Values{"op": {"send-2fa"}, "factor": {"sms"}})
	if !strings.Contains(html.UnescapeString(page), otp.ErrTooSoon.Error()) {
		t.Fatalf("want the send limit login codes left: %s", page)
	}

	page = e.sendSecondStep(page, "sms")
	code := e.inbox.take(ownerPhone)
	for range 4 {
		_, page = e.post(page, url.Values{"op": {"code-2fa"}, "factor": {"sms"}, "code": {"000000"}})
	}
	if n := e.failures(identity.TwoFactorLockKey(sub)); n != 4 {
		t.Errorf("%d failures of 2fa:<sub>, want 4", n)
	}
	_, page = e.post(page, url.Values{"op": {"code-2fa"}, "factor": {"sms"}, "code": {"000000"}})
	if !strings.Contains(page, `name="identifier"`) {
		t.Fatalf("the fifth wrong code should end the login: %s", page)
	}

	// Locked: the right code is refused.
	if _, err := e.pool.Exec(ctx, "INSERT INTO lockouts (key, until) VALUES ($1, now() + interval '15 minutes')", identity.TwoFactorLockKey(sub)); err != nil {
		t.Fatal(err)
	}
	page = e.passwordToSecondStep()
	page = e.sendSecondStep(page, "sms")
	code = e.inbox.take(ownerPhone)
	resp, page := e.post(page, url.Values{"op": {"code-2fa"}, "factor": {"sms"}, "code": {code}})
	if resp.StatusCode != 200 || !strings.Contains(html.UnescapeString(page), identity.ErrTwoFactorLocked.Error()) {
		t.Errorf("a right code while locked: %d %s", resp.StatusCode, page)
	}
}

// failures is how many failures key has counted.
func (e *env) failures(key string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM login_failures WHERE key = $1", key).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}
