package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
)

const errRegistrationClosed = "本实例未开放注册"

func (e *env) closeRegistration() {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET open_registration = false"); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sends() int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM sends").Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// With registration closed, a code to an Identifier no User holds is never
// sent, nor counted against any send limit (ADR 0021).
func TestClosedRegistrationSendsNoCodeToStrangers(t *testing.T) {
	e := start(t)
	e.closeRegistration()
	const phone = "+8613800138000"

	_, page := e.authorize("")
	resp, body := e.post(page, url.Values{"op": {"send"}, "identifier": {phone}, "altcha": {e.solve()}})
	if resp.StatusCode != 200 || !strings.Contains(body, errRegistrationClosed) {
		t.Errorf("hosted page: %d %s", resp.StatusCode, body)
	}
	app := e.challenge(url.Values{"identifier": {"someone@example.com"}, "altcha": {e.solve()}})
	if app.Status != 400 || app.Error != "registration_closed" || app.Describe != errRegistrationClosed {
		t.Errorf("direct API: %+v", app)
	}
	if e.inbox.take(phone) != "" || e.inbox.take("someone@example.com") != "" || e.sends() != 0 {
		t.Errorf("a code went out: %d sends", e.sends())
	}
}

// Closing registration leaves existing Users' logins alone: setup, then
// code (hosted page and direct API) and password.
func TestClosedRegistrationLetsUsersIn(t *testing.T) {
	e := start(t)
	e.closeRegistration()
	e.bootstrap("owner", "password1") // the setup page still works
	const phone = "+8613800138000"
	// The phone signs up while it is open: an existing User from then on.
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET open_registration = true"); err != nil {
		t.Fatal(err)
	}
	_, page := e.authorize("")
	resp, _ := e.codeLogin(page, phone, phone)
	sub := e.idToken(e.code(resp))["sub"]
	e.closeRegistration()

	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.codeLogin(page, phone, phone)
	if again := e.idToken(e.code(resp))["sub"]; again != sub {
		t.Errorf("code login: sub %v, want %v", again, sub)
	}
	if again := e.claims(e.exchange(clientID, "", e.appCodeLogin(phone)).IDToken)["sub"]; again != sub {
		t.Errorf("direct API: sub %v, want %v", again, sub)
	}
	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.submit(page, "owner", "password1")
	e.code(resp)
}

// 重新获取 asks again: registration closed after the first send stops it.
func TestClosedRegistrationStopsResend(t *testing.T) {
	e := start(t)
	const phone = "+8613800138000"
	_, page := e.authorize("")
	_, page = e.post(page, url.Values{"op": {"send"}, "identifier": {phone}, "altcha": {e.solve()}})
	e.inbox.take(phone)
	e.closeRegistration()
	if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	_, body := e.post(page, url.Values{"op": {"resend"}})
	if !strings.Contains(body, errRegistrationClosed) || e.inbox.take(phone) != "" || e.sends() != 1 {
		t.Errorf("resend: %d sends %s", e.sends(), body)
	}
}

// The backstop: a verified Identifier no User holds signs nobody up.
func TestClosedRegistrationSignInCreatesNobody(t *testing.T) {
	e := start(t)
	e.closeRegistration()
	if _, err := e.ids.SignIn(context.Background(), "phone", "+8613800138000"); err != identity.ErrRegistrationClosed {
		t.Errorf("SignIn: %v, want %v", err, identity.ErrRegistrationClosed)
	}
	if n := e.users(); n != 0 {
		t.Errorf("%d users", n)
	}
}

func (e *env) users() int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// An External Identity bound to nobody is refused; a bound one signs in.
func TestClosedRegistrationRefusesNewExternalIdentities(t *testing.T) {
	e := start(t)
	e.addGoogle()
	_, page := e.authorize("")
	resp, _ := e.signInWith(page, "google")
	sub := e.idToken(e.code(resp))["sub"]
	e.closeRegistration()

	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.signInWith(page, "google")
	if again := e.idToken(e.code(resp))["sub"]; again != sub {
		t.Errorf("bound External Identity: sub %v, want %v", again, sub)
	}

	if _, err := e.pool.Exec(context.Background(), "DELETE FROM users"); err != nil {
		t.Fatal(err)
	}
	e.newBrowser()
	_, page = e.authorize("")
	resp, body := e.signInWith(page, "google")
	if resp.StatusCode != 403 || !strings.Contains(body, errRegistrationClosed) || e.users() != 0 {
		t.Errorf("new External Identity: %d, %d users %s", resp.StatusCode, e.users(), body)
	}
}
