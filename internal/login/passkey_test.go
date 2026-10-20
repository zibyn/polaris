package login_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/passkey"
	"github.com/zibyn/polaris/internal/passkey/passkeytest"
)

// optionsOf pulls the assertion options embedded in the login page, and says
// whether the page carries them at all.
func optionsOf(t *testing.T, page string) (json.RawMessage, bool) {
	t.Helper()
	const open, close = `<script type="application/json" id="passkey-options">`, "</script>"
	i := strings.Index(page, open)
	if i < 0 {
		return nil, false
	}
	rest := page[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		t.Fatalf("passkey options run to the end of the page")
	}
	return json.RawMessage(rest[:j]), true
}

// passkeyUser signs ALICE in with the phone code once, giving the sub a
// Passkey of a's through the account center's store.
func passkeyUser(t *testing.T, e *env, a *passkeytest.Authenticator) string {
	t.Helper()
	return passkeyUserAt(t, e, a, "phone", "+8613800138000")
}

// passkeyUserAt is passkeyUser for a User who signs up as kind/value.
func passkeyUserAt(t *testing.T, e *env, a *passkeytest.Authenticator, kind, value string) string {
	t.Helper()
	sub, err := e.ids.SignIn(context.Background(), kind, value)
	if err != nil {
		t.Fatal(err)
	}
	// The account center's registration challenge hangs off its Session.
	if _, err := e.pool.Exec(context.Background(),
		"INSERT INTO sessions (id, id_hash, user_id, auth_time, amr) VALUES ('pk-enroll', '\x02', $1, now(), '{}')", sub); err != nil {
		t.Fatal(err)
	}
	store, err := passkey.New(e.pool, e.issuer)
	if err != nil {
		t.Fatal(err)
	}
	a.Origin = e.issuer
	a.UserHandle = []byte(sub)
	options, err := store.Begin(context.Background(), sub, sub, "pk-enroll")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finish(context.Background(), sub, "pk-enroll", a.Enroll(options)); err != nil {
		t.Fatal(err)
	}
	return sub
}

// The first step of the login page carries assertion options, its identifier
// field says it takes a Passkey, and the password form carries none; a
// Passkey then signs its User in with no code, no password and no TOTP.
func TestPasskeyLogin(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	sub := passkeyUser(t, e, a)

	_, page := e.authorize("")
	options, ok := optionsOf(t, page)
	if !ok {
		t.Fatal("no passkey options on the first step")
	}
	if !strings.Contains(page, `autocomplete="username webauthn"`) ||
		!strings.Contains(page, `id="passkey-login" hidden`) {
		t.Fatal("the identifier field or the button is missing")
	}
	// The password form is a first step too — an instance with no Channels
	// offers nothing else — so it carries the options as well. A visit of
	// its own: rendering any first step renews the challenge.
	_, other := e.authorize("")
	m := actionRE.FindStringSubmatch(other)
	if m == nil {
		t.Fatal("no form on the page")
	}
	_, pw := e.do("GET", html.UnescapeString(m[1])+"?password", nil)
	if _, ok := optionsOf(t, pw); !ok {
		t.Fatal("no options on the password form")
	}
	if !strings.Contains(pw, `autocomplete="username webauthn"`) {
		t.Fatal("the password form's username field lacks the webauthn hint")
	}

	a.SignCount = 2
	resp, page := e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if resp.StatusCode/100 != 3 {
		t.Fatalf("passkey login: %d %s", resp.StatusCode, page)
	}
	claims := e.idToken(e.code(resp))
	if amr, _ := claims["amr"].([]any); len(amr) != 2 || amr[0] != "hwk" || amr[1] != "mfa" {
		t.Fatalf("amr: %v", claims["amr"])
	}

	// The sign-in marked the Passkey used.
	var signCount int64
	if err := e.pool.QueryRow(context.Background(),
		"SELECT sign_count FROM passkeys WHERE user_id = $1", sub).Scan(&signCount); err != nil {
		t.Fatal(err)
	}
	if signCount != 2 {
		t.Fatalf("sign_count: %d", signCount)
	}
}

// A synced Passkey is a software key in the amr claim.
func TestPasskeyLoginSynced(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	a.BE, a.BS = true, true
	passkeyUser(t, e, a)

	_, page := e.authorize("")
	options, _ := optionsOf(t, page)
	a.SignCount = 1
	resp, page := e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if resp.StatusCode/100 != 3 {
		t.Fatalf("passkey login: %d %s", resp.StatusCode, page)
	}
	claims := e.idToken(e.code(resp))
	if amr, _ := claims["amr"].([]any); len(amr) != 2 || amr[0] != "swk" || amr[1] != "mfa" {
		t.Fatalf("amr: %v", claims["amr"])
	}
}

// 两步验证 asks a code login for a TOTP, but a Passkey has passed it
// already.
func TestPasskeyLoginPastTOTP(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	sub := passkeyUser(t, e, a)
	e.twoFactor(sub)

	_, page := e.authorize("")
	options, _ := optionsOf(t, page)
	a.SignCount = 1
	resp, page := e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if resp.StatusCode/100 != 3 {
		t.Fatalf("passkey login past TOTP: %d %s", resp.StatusCode, page)
	}
}

// The terms are still asked: the assertion's form is the page's own script,
// which ticked no box, so the consent step comes after the Passkey signs the
// User in.
func TestPasskeyLoginThenConsent(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	sub := passkeyUser(t, e, a)
	e.setTerms("v1")

	_, page := e.authorize("")
	options, _ := optionsOf(t, page)
	a.SignCount = 1
	resp, page := e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if resp.StatusCode != 200 || !strings.Contains(page, `name="agree" value="v1" required`) {
		t.Fatalf("the consent step did not come: %d %s", resp.StatusCode, page)
	}
	if got := e.consents(sub); len(got) != 0 {
		t.Fatalf("consents recorded without a ticked box: %v", got)
	}
	resp, _ = e.post(page, url.Values{"op": {"consent"}, "agree": {"v1"}})
	claims := e.idToken(e.code(resp))
	if claims["sub"] != sub {
		t.Fatalf("sub: %v", claims["sub"])
	}
	if got := e.consents(sub); len(got) != 1 || got[0] != "v1@"+clientID {
		t.Fatalf("consents: %v", got)
	}
}

// A refused assertion — a credential nobody holds here — shows the User their
// way out and signs nobody in; the next first step carries a fresh challenge,
// so the refused assertion cannot come back.
func TestPasskeyLoginRefused(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	passkeyUser(t, e, a)

	_, page := e.authorize("")
	first, _ := optionsOf(t, page)

	unknown := passkeytest.New(t)
	unknown.Origin, unknown.UserHandle = a.Origin, a.UserHandle
	resp, page := e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(unknown.Assert(first))}})
	if resp.StatusCode != 200 || !strings.Contains(page, passkey.ErrNoPasskey.Error()) {
		t.Fatalf("an unknown credential: %d %s", resp.StatusCode, page)
	}
	var users int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Fatalf("a refused assertion signed someone in: %d users", users)
	}

	second, _ := optionsOf(t, page)
	if string(first) == string(second) {
		t.Fatal("the challenge was not renewed")
	}
	a.SignCount = 1
	resp, _ = e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(first))}})
	if resp.StatusCode/100 == 3 {
		t.Fatal("the refused page's assertion signed in")
	}
}

// setPasskeyLogin turns the instance's Passkey switch on or off.
func setPasskeyLogin(t *testing.T, e *env, on bool) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET passkey_login = $1", on); err != nil {
		t.Fatal(err)
	}
}

// With Passkey login off the first step carries no assertion options — so no
// conditional UI, no 「使用 Passkey 登录」 button and no webauthn autocomplete
// hint — and both the hosted form and the direct API refuse an assertion.
// Turning it back on restores the Passkeys Users already added
// (docs/spec/consoles.md#设置).
func TestPasskeyLoginOff(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	passkeyUser(t, e, a)

	// A first step and a direct-API ceremony begun while it is on, to submit
	// once it is off.
	_, page := e.authorize("")
	options, _ := optionsOf(t, page)
	begun := e.challenge(url.Values{"passkey": {"begin"}})
	if begun.Status != 200 {
		t.Fatalf("begin: %+v", begun)
	}
	setPasskeyLogin(t, e, false)

	_, step := e.authorize("")
	if _, ok := optionsOf(t, step); ok {
		t.Fatal("the first step carried assertion options while Passkey login is off")
	}
	for _, gone := range []string{`id="passkey-login"`, "passkey.js", "webauthn"} {
		if strings.Contains(step, gone) {
			t.Errorf("a Passkey entry survived the switch off: %q", gone)
		}
	}

	// The assertion the page had carried while it was on is refused.
	a.SignCount = 1
	resp, refused := e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if resp.StatusCode != 200 || !strings.Contains(refused, passkey.ErrOff.Error()) {
		t.Fatalf("the hosted form while off: %d %s", resp.StatusCode, refused)
	}
	// So is the direct API's begin, and an assertion begun before it.
	if off := e.challenge(url.Values{"passkey": {"begin"}}); off.Status != 400 || off.Options != nil {
		t.Fatalf("begin while off: %+v", off)
	}
	if done := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(a.Assert(begun.Options))}}); done.Status != 400 || done.Code != "" {
		t.Fatalf("assertion while off: %+v", done)
	}

	// Back on, the Passkey added before signs the User in.
	setPasskeyLogin(t, e, true)
	_, page = e.authorize("")
	options, ok := optionsOf(t, page)
	if !ok {
		t.Fatal("no assertion options once Passkey login is back on")
	}
	a.SignCount = 2
	resp, page = e.post(page, url.Values{"op": {"passkey"}, "passkey": {string(a.Assert(options))}})
	if resp.StatusCode/100 != 3 {
		t.Fatalf("passkey login after turning it back on: %d %s", resp.StatusCode, page)
	}
}

// androidOrigin is what an Android app with this signing certificate puts in
// clientDataJSON, and the fingerprint the console is given for it.
func androidOriginAndFingerprint(raw []byte) (origin, fingerprint string) {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(raw), strings.Join(parts, ":")
}

// The direct API's Passkey sign-in takes two requests: passkey=begin answers
// 200 with assertion options and an auth_session and needs no PoW, and the
// assertion submitted on it signs the User in — past 两步验证, which a Passkey
// has already passed (ADR 0014).
func TestDirectPasskeyLogin(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	sub := passkeyUser(t, e, a)
	e.twoFactor(sub)

	begun := e.challenge(url.Values{"passkey": {"begin"}})
	if begun.Status != 200 || begun.AuthSession == "" || begun.Options == nil {
		t.Fatalf("begin: %+v", begun)
	}
	var options struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			RPID             string `json:"rpId"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(begun.Options, &options); err != nil {
		t.Fatalf("options: %v: %s", err, begun.Options)
	}
	if options.PublicKey.Challenge == "" || options.PublicKey.RPID == "" || options.PublicKey.UserVerification != "required" {
		t.Fatalf("options are not credential request options: %s", begun.Options)
	}

	a.SignCount = 2
	done := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(a.Assert(begun.Options))}})
	if done.Status != 200 || done.Code == "" {
		t.Fatalf("assert: %+v", done)
	}
	claims := e.claims(e.exchange(clientID, "", done.Code).IDToken)
	if claims["sub"] != sub || !slices.Equal(claims["amr"].([]any), []any{"hwk", "mfa"}) {
		t.Fatalf("id token: %v", claims)
	}
}

// A User the instance requires a phone number of meets that step after a
// Passkey signs them in, as after any other first factor.
func TestDirectPasskeyLoginBindsRequiredPhone(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	passkeyUserAt(t, e, a, "email", "a@example.com")
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}

	begun := e.challenge(url.Values{"passkey": {"begin"}})
	a.SignCount = 1
	bind := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(a.Assert(begun.Options))}})
	if bind.Status != 403 || bind.Error != "insufficient_authorization" || bind.Next != "phone" || bind.AuthSession != begun.AuthSession {
		t.Fatalf("want a bind step: %+v", bind)
	}
}

// A refused assertion answers 400 invalid_request and spends the
// auth_session: nothing comes back to send another one on.
func TestDirectPasskeyLoginRefused(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	passkeyUser(t, e, a)

	begun := e.challenge(url.Values{"passkey": {"begin"}})
	unknown := passkeytest.New(t)
	unknown.Origin, unknown.UserHandle = a.Origin, a.UserHandle
	refused := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(unknown.Assert(begun.Options))}})
	if refused.Status != 400 || refused.Error != "invalid_request" || refused.AuthSession != "" ||
		refused.Describe != passkey.ErrNoPasskey.Error() {
		t.Fatalf("a refused assertion: %+v", refused)
	}
	if again := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(unknown.Assert(begun.Options))}}); again.Error != "invalid_session" {
		t.Fatalf("the auth_session outlived the refusal: %+v", again)
	}
}

// An assertion from a registered Android app passes; the same credential
// from an origin no Application registered does not.
func TestDirectPasskeyAndroidOrigin(t *testing.T) {
	e := start(t)
	a := passkeytest.New(t)
	passkeyUser(t, e, a)

	raw := bytes.Repeat([]byte{0xAB}, 32)
	origin, fingerprint := androidOriginAndFingerprint(raw)
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE applications SET android_apps = jsonb_build_array(jsonb_build_object(
			'packageName', 'com.example.app', 'sha256CertFingerprints', jsonb_build_array($1::text)))`,
		fingerprint); err != nil {
		t.Fatal(err)
	}

	a.Origin, a.SignCount = origin, 1
	begun := e.challenge(url.Values{"passkey": {"begin"}})
	if done := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(a.Assert(begun.Options))}}); done.Status != 200 || done.Code == "" {
		t.Fatalf("a registered Android app's assertion: %+v", done)
	}

	// The same app signed with another certificate: an origin nobody
	// registered, and an hour later nothing about it is remembered.
	other, _ := androidOriginAndFingerprint(bytes.Repeat([]byte{0xCD}, 32))
	a.Origin, a.SignCount = other, 2
	begun = e.challenge(url.Values{"passkey": {"begin"}})
	if done := e.challenge(url.Values{"auth_session": {begun.AuthSession}, "passkey": {string(a.Assert(begun.Options))}}); done.Status != 400 {
		t.Fatalf("an unregistered origin: %+v", done)
	}
}

// begin is what an IP locked out of signing in is refused, standing in for
// the PoW it does not have to solve: both on the key the password and code
// failures count under and on begin's own budget.
func TestDirectPasskeyBeginRateLimited(t *testing.T) {
	for _, key := range []string{"ip:127.0.0.1", "start:ip:127.0.0.1"} {
		t.Run(key, func(t *testing.T) {
			e := start(t)
			if _, err := e.pool.Exec(context.Background(),
				"INSERT INTO lockouts (key, until) VALUES ($1, now() + interval '1 hour')", key); err != nil {
				t.Fatal(err)
			}
			begun := e.challenge(url.Values{"passkey": {"begin"}})
			if begun.Status != 400 || begun.Error != "invalid_request" || begun.Options != nil {
				t.Fatalf("begin from a locked-out IP: %+v", begun)
			}
		})
	}
}
