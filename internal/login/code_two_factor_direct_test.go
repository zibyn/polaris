package login_test

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/otp"
)

// appPassword signs owner in by password with the direct auth API.
func (e *env) appPassword() challengeResp {
	e.t.Helper()
	return e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}})
}

// appSendSecondStep asks for the second step's code by factor on as,
// clearing the 60-second limit of earlier sends first.
func (e *env) appSendSecondStep(as, factor string) challengeResp {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
		e.t.Fatal(err)
	}
	return e.challenge(url.Values{"auth_session": {as}, "two_factor": {factor}})
}

// A User whose one factor is their phone number, or their email, gets next
// sms or email; two_factor=<it> sends the code, next code takes it (ADR 0038).
func TestDirectSecondStepByCode(t *testing.T) {
	for _, c := range []struct{ kind, factor, to, amr string }{
		{"phone", "sms", ownerPhone, "sms"},
		{"email", "email", ownerEmail, "otp"},
	} {
		t.Run(c.factor, func(t *testing.T) {
			e := start(t)
			e.ownerCodeFactors(c.kind)
			r := e.appPassword()
			if r.Status != 403 || r.Error != "insufficient_authorization" || r.Next != c.factor || r.Methods != nil || r.AuthSession == "" {
				t.Fatalf("want next %s: %+v", c.factor, r)
			}
			as := r.AuthSession
			if e.inbox.take(c.to) != "" {
				t.Fatal("a code sent unasked")
			}
			if r := e.challenge(url.Values{"auth_session": {as}, "code": {"000000"}}); r.Status != 400 || r.Error != "invalid_request" || r.AuthSession != as {
				t.Fatalf("a code before one was sent: %+v", r)
			}
			r = e.appSendSecondStep(as, c.factor)
			code := e.inbox.take(c.to)
			if r.Status != 403 || r.Next != "code" || r.AuthSession != as || code == "" {
				t.Fatalf("send: %+v", r)
			}
			done := e.challenge(url.Values{"auth_session": {as}, "code": {code}})
			if done.Status != 200 {
				t.Fatalf("code: %+v", done)
			}
			if got := amrOf(e.claims(e.exchange(clientID, "", done.Code).IDToken)); !slices.Equal(got, []string{"pwd", c.amr, "mfa"}) {
				t.Errorf("amr %v", got)
			}
		})
	}
}

// With a TOTP and an SMS factor the User chooses: methods in the order
// twofactor.Usable gives them.
func TestDirectSecondStepMethods(t *testing.T) {
	e := start(t)
	sub := e.ownerCodeFactors("phone", "email")
	e.twoFactor(sub)
	if r := e.appPassword(); r.Next != "two_factor" || !slices.Equal(r.Methods, []string{"totp", "sms", "email"}) {
		t.Fatalf("password login: %+v", r)
	}

	// An SMS login leaves out sms, and its code is not sent when asked.
	r := e.challenge(url.Values{"identifier": {ownerPhone}, "altcha": {e.solve()}})
	r = e.challenge(url.Values{"auth_session": {r.AuthSession}, "code": {e.inbox.take(ownerPhone)}})
	if r.Next != "two_factor" || !slices.Equal(r.Methods, []string{"totp", "email"}) {
		t.Fatalf("SMS login: %+v", r)
	}
	as := r.AuthSession
	if r := e.appSendSecondStep(as, "sms"); r.Status != 400 || r.Error != "invalid_request" || r.AuthSession != as || e.inbox.take(ownerPhone) != "" {
		t.Errorf("sms on an SMS login: %+v", r)
	}

	// Left with email alone, an SMS login gets next email.
	if r := e.challenge(url.Values{"auth_session": {as}, "two_factor": {"email"}}); r.Next != "code" || e.inbox.take(ownerEmail) == "" {
		t.Errorf("email on an SMS login: %+v", r)
	}
	for _, sql := range []string{"DELETE FROM totp_credentials", "UPDATE sends SET sent_at = sent_at - interval '1 minute'"} {
		if _, err := e.pool.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	r = e.challenge(url.Values{"identifier": {ownerPhone}, "altcha": {e.solve()}})
	r = e.challenge(url.Values{"auth_session": {r.AuthSession}, "code": {e.inbox.take(ownerPhone)}})
	if r.Next != "email" || r.Methods != nil {
		t.Errorf("SMS login with email left: %+v", r)
	}
}

// An SMS login of a User whose one factor is SMS is left with the 恢复码:
// next totp, saying to sign in another way, as the hosted page does; a
// password login, and a User with a TOTP, are told just totp (ADR 0038).
func TestDirectSecondStepLeavesOutTheFirstChannel(t *testing.T) {
	const totp = "两步验证 is on: send totp or recovery_code"
	e := start(t)
	sub := e.ownerCodeFactors("phone")
	r := e.challenge(url.Values{"identifier": {ownerPhone}, "altcha": {e.solve()}})
	r = e.challenge(url.Values{"auth_session": {r.AuthSession}, "code": {e.inbox.take(ownerPhone)}})
	if r.Next != "totp" || !strings.Contains(r.Describe, "sign in another way") {
		t.Errorf("SMS login, SMS the one factor: %+v", r)
	}
	e.twoFactor(sub)
	if _, err := e.pool.Exec(context.Background(), "UPDATE identifiers SET second_factor = false"); err != nil {
		t.Fatal(err)
	}
	if r := e.appPassword(); r.Next != "totp" || r.Describe != totp {
		t.Errorf("password login, a TOTP alone: %+v", r)
	}
}

// Wrong codes count as wrong TOTP codes do: invalid_request with the
// auth_session, toward 2fa:<sub>, and the fifth ends the auth_session. Too
// soon a send is otp's error, the auth_session kept.
func TestDirectSecondStepCodeMistakes(t *testing.T) {
	e := start(t)
	sub := e.ownerCodeFactors("phone")
	as := e.appPassword().AuthSession
	e.appSendSecondStep(as, "sms")
	e.inbox.take(ownerPhone)
	if r := e.challenge(url.Values{"auth_session": {as}, "two_factor": {"sms"}}); r.Status != 400 || r.Error != "invalid_request" || r.Describe != otp.ErrTooSoon.Error() || r.AuthSession != as {
		t.Fatalf("too soon: %+v", r)
	}
	for i := range 4 {
		if r := e.challenge(url.Values{"auth_session": {as}, "code": {"000000"}}); r.Status != 400 || r.Error != "invalid_request" || r.AuthSession != as {
			t.Fatalf("mistake %d: %+v", i+1, r)
		}
	}
	if n := e.failures(identity.TwoFactorLockKey(sub)); n != 4 {
		t.Errorf("%d failures of 2fa:<sub>, want 4", n)
	}
	if r := e.challenge(url.Values{"auth_session": {as}, "code": {"000000"}}); r.Status != 400 || r.Error != "invalid_session" {
		t.Errorf("fifth mistake: %+v", r)
	}
}
