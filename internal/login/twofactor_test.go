package login_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"html"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/login"
	"github.com/zibyn/polaris/internal/twofactor"
)

// twoFactor turns 两步验证 on for sub with a code from a step ago; it
// returns the TOTP secret and the 恢复码.
func (e *env) twoFactor(sub string) (string, []string) {
	e.t.Helper()
	ctx := context.Background()
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	s := twofactor.New(e.pool, keyring)
	secret, err := s.Begin(ctx, sub)
	if err != nil {
		e.t.Fatal(err)
	}
	codes, err := s.Confirm(ctx, sub, totpAt(secret, -1))
	if err != nil {
		e.t.Fatal(err)
	}
	return secret, codes
}

// totpAt is what an authenticator shows for secret, steps 30-second steps
// from now (RFC 6238).
func totpAt(secret string, steps int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, time.Now().Unix()/30+steps)
	sum := mac.Sum(nil)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[sum[19]&0xf:])&0x7fffffff)%1_000_000)
}

func (e *env) hasSessionCookie() bool {
	issuer, _ := url.Parse(e.issuer)
	for _, c := range e.client.Jar.Cookies(issuer) {
		if c.Name == "__Host-session" {
			return true
		}
	}
	return false
}

func (e *env) audits(event string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE event = $1", event).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) ipFailures() int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM login_failures WHERE key = 'ip:127.0.0.1'").Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

const totpForm = `name="totp"`

// The hosted login of a User with 两步验证 asks for a TOTP code or a 恢复码
// after the first factor; until one is entered the browser holds no
// Session. Each code works once.
func TestHostedLoginAsksForTOTP(t *testing.T) {
	e := start(t)
	const phone = "+8613800138000"
	sub, err := e.ids.SignIn(context.Background(), "phone", phone)
	if err != nil {
		t.Fatal(err)
	}
	secret, codes := e.twoFactor(sub)

	_, page := e.authorize("")
	resp, page := e.codeLogin(page, phone, phone)
	if resp.StatusCode != 200 || !strings.Contains(page, totpForm) || !strings.Contains(page, `autocomplete="one-time-code"`) {
		t.Fatalf("want the TOTP step, got %d %s", resp.StatusCode, page)
	}
	if e.hasSessionCookie() {
		t.Errorf("Session cookie before TOTP")
	}
	redirect := e.issuer + "/console/callback"
	resp, _ = e.authorizeAs(login.ConsoleClientID, redirect, "&prompt=none")
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc.Query().Get("error") != "login_required" {
		t.Errorf("silent login before TOTP: %d %q", resp.StatusCode, loc)
	}

	failures := e.ipFailures()
	_, page = e.post(page, url.Values{"op": {"totp"}, "totp": {"000000"}})
	if !strings.Contains(html.UnescapeString(page), twofactor.ErrCode.Error()) || !strings.Contains(page, totpForm) {
		t.Fatalf("wrong TOTP: %s", page)
	}
	if e.ipFailures() != failures+1 {
		t.Errorf("wrong TOTP not counted against the IP")
	}
	resp, _ = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	claims := e.idToken(e.code(resp))
	if claims["sub"] != sub || !slices.Equal(claims["amr"].([]any), []any{"sms", "otp", "mfa"}) {
		t.Errorf("id token: %v", claims)
	}
	// The browser Session signs in silently, with no TOTP again.
	resp, _ = e.authorizeAs(login.ConsoleClientID, redirect, "&prompt=none")
	e.code(resp)
	resp, _ = e.authorize("")
	e.code(resp)

	// The same code does not work twice.
	e.newBrowser()
	_, page = e.authorize("")
	_, page = e.codeLogin(page, phone, phone)
	_, page = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	if !strings.Contains(html.UnescapeString(page), twofactor.ErrCode.Error()) {
		t.Fatalf("replayed TOTP: %s", page)
	}
	// A 恢复码 does, once.
	_, page = e.link(page, "使用恢复码")
	if !strings.Contains(page, `name="recovery_code"`) {
		t.Fatalf("no recovery code form: %s", page)
	}
	resp, _ = e.post(page, url.Values{"op": {"totp"}, "recovery_code": {strings.ToUpper(codes[0])}})
	claims = e.idToken(e.code(resp))
	if !slices.Equal(claims["amr"].([]any), []any{"sms", "otp", "mfa"}) || e.audits("recovery_code.used") != 1 {
		t.Errorf("recovery code login: %v", claims)
	}
	e.newBrowser()
	_, page = e.authorize("")
	_, page = e.codeLogin(page, phone, phone)
	_, page = e.post(page, url.Values{"op": {"totp"}, "recovery_code": {codes[0]}})
	if !strings.Contains(html.UnescapeString(page), twofactor.ErrRecoveryCode.Error()) {
		t.Fatalf("used recovery code: %s", page)
	}

	// Five mistakes end the login: back to the first step.
	for range 4 {
		_, page = e.post(page, url.Values{"op": {"totp"}, "totp": {"000000"}})
	}
	if strings.Contains(page, totpForm) || !strings.Contains(page, `name="identifier"`) {
		t.Fatalf("after five mistakes, want the first step: %s", page)
	}
	if resp, _ := e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 1)}}); resp.StatusCode != 200 || e.hasSessionCookie() {
		t.Errorf("TOTP accepted after the login ended")
	}
}

// TOTP comes before binding a phone number.
func TestTOTPBeforeBindingPhone(t *testing.T) {
	e := start(t)
	sub, err := e.ids.SignIn(context.Background(), "email", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := e.twoFactor(sub)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}

	_, page := e.authorize("")
	_, page = e.codeLogin(page, "a@example.com", "a@example.com")
	if !strings.Contains(page, totpForm) || strings.Contains(page, "绑定手机号") {
		t.Fatalf("want the TOTP step first: %s", page)
	}
	// No binding before TOTP.
	_, body := e.post(page, url.Values{"op": {"send"}, "identifier": {"13900139000"}, "altcha": {e.solve()}})
	if e.inbox.take("+8613900139000") != "" || !strings.Contains(body, totpForm) {
		t.Errorf("sent a code to bind before TOTP: %s", body)
	}
	_, page = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	if !strings.Contains(page, "绑定手机号") {
		t.Fatalf("want the bind page after TOTP: %s", page)
	}
	resp, _ := e.codeLogin(page, "13900139000", "+8613900139000")
	if claims := e.idToken(e.code(resp)); !slices.Equal(claims["amr"].([]any), []any{"otp", "mfa"}) {
		t.Errorf("id token: %v", claims)
	}
}

// The direct auth API asks for 两步验证 with next totp, takes totp or
// recovery_code in the same auth_session, and lets five mistakes end it.
func TestDirectLoginAsksForTOTP(t *testing.T) {
	e := start(t)
	const phone = "+8613800138000"
	sub, err := e.ids.SignIn(context.Background(), "phone", phone)
	if err != nil {
		t.Fatal(err)
	}
	secret, codes := e.twoFactor(sub)

	// signIn enters phone's code and returns the TOTP step's auth_session.
	signIn := func() string {
		t.Helper()
		if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
			t.Fatal(err)
		}
		sent := e.challenge(url.Values{"identifier": {phone}, "altcha": {e.solve()}})
		r := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "code": {e.inbox.take(phone)}})
		if r.Status != 403 || r.Error != "insufficient_authorization" || r.Next != "totp" || r.AuthSession != sent.AuthSession {
			t.Fatalf("want next totp: %+v", r)
		}
		return r.AuthSession
	}

	as := signIn()
	failures := e.ipFailures()
	if r := e.challenge(url.Values{"auth_session": {as}, "totp": {"000000"}}); r.Status != 400 || r.Error != "invalid_request" || r.AuthSession != as {
		t.Fatalf("wrong TOTP: %+v", r)
	}
	if e.ipFailures() != failures+1 {
		t.Errorf("wrong TOTP not counted against the IP")
	}
	done := e.challenge(url.Values{"auth_session": {as}, "totp": {totpAt(secret, 0)}})
	if done.Status != 200 {
		t.Fatalf("TOTP: %+v", done)
	}
	if claims := e.claims(e.exchange(clientID, "", done.Code).IDToken); claims["sub"] != sub || !slices.Equal(claims["amr"].([]any), []any{"sms", "otp", "mfa"}) {
		t.Errorf("id token: %v", claims)
	}

	as = signIn()
	if r := e.challenge(url.Values{"auth_session": {as}, "totp": {totpAt(secret, 0)}}); r.Status != 400 || r.AuthSession != as {
		t.Errorf("replayed TOTP: %+v", r)
	}
	if r := e.challenge(url.Values{"auth_session": {as}, "recovery_code": {codes[0]}}); r.Status != 200 || e.audits("recovery_code.used") != 1 {
		t.Errorf("recovery code: %+v", r)
	}

	as = signIn()
	for i := range 4 {
		if r := e.challenge(url.Values{"auth_session": {as}, "recovery_code": {codes[0]}}); r.Error != "invalid_request" {
			t.Fatalf("mistake %d: %+v", i+1, r)
		}
	}
	if r := e.challenge(url.Values{"auth_session": {as}, "totp": {"000000"}}); r.Status != 400 || r.Error != "invalid_session" {
		t.Errorf("fifth mistake: %+v", r)
	}
	if r := e.challenge(url.Values{"auth_session": {as}, "totp": {totpAt(secret, 1)}}); r.Error != "invalid_session" {
		t.Errorf("after five mistakes: %+v", r)
	}
}

// With 两步验证 and a phone number to bind, the App enters TOTP first.
func TestDirectTOTPBeforeBindingPhone(t *testing.T) {
	e := start(t)
	sub, err := e.ids.SignIn(context.Background(), "email", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := e.twoFactor(sub)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}
	sent := e.challenge(url.Values{"identifier": {"a@example.com"}, "altcha": {e.solve()}})
	r := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "code": {e.inbox.take("a@example.com")}})
	if r.Next != "totp" {
		t.Fatalf("want next totp: %+v", r)
	}
	// No binding before TOTP.
	e.challenge(url.Values{"auth_session": {r.AuthSession}, "identifier": {"13900139000"}, "altcha": {e.solve()}})
	if e.inbox.take("+8613900139000") != "" {
		t.Errorf("sent a code to bind before TOTP")
	}
	if r = e.challenge(url.Values{"auth_session": {r.AuthSession}, "totp": {totpAt(secret, 0)}}); r.Next != "phone" {
		t.Fatalf("want next phone after TOTP: %+v", r)
	}
	sent = e.challenge(url.Values{"auth_session": {r.AuthSession}, "identifier": {"13900139000"}, "altcha": {e.solve()}})
	done := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "code": {e.inbox.take("+8613900139000")}})
	if claims := e.claims(e.exchange(clientID, "", done.Code).IDToken); !slices.Equal(claims["amr"].([]any), []any{"otp", "mfa"}) {
		t.Errorf("id token: %v", claims)
	}
}
