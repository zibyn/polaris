package login_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
)

// Login CSRF past the first factor: an attacker stops at a later step and
// hands the victim's browser the login page. Only the attacker's browser
// goes on: the victim's sees no step, enters nothing, gets no Session and
// no code.
func TestPendingLoginGoesOnOnlyInTheBrowserThatStartedIt(t *testing.T) {
	const phone = "+8613900139000"
	type factor struct {
		user  func(e *env) string // a User, in this browser or none
		login func(e *env, page string) (*http.Response, string)
	}
	factors := map[string]factor{
		"password": {
			user: func(e *env) string {
				e.bootstrap("owner", "password1")
				sub, _ := e.ids.CheckPassword(context.Background(), identity.Attempt{}, "owner", "password1")
				return sub
			},
			login: func(e *env, page string) (*http.Response, string) { return e.submit(page, "owner", "password1") },
		},
		"code": {
			user: func(e *env) string {
				sub, _ := e.ids.SignIn(context.Background(), "email", "a@example.com")
				return sub
			},
			login: func(e *env, page string) (*http.Response, string) {
				return e.codeLogin(page, "a@example.com", "a@example.com")
			},
		},
		"google": {
			user: func(e *env) string {
				e.addGoogle()
				_, page := e.authorize("")
				resp, _ := e.signInWith(page, "google")
				sub := e.idToken(e.code(resp))["sub"].(string)
				e.newBrowser()
				return sub
			},
			login: func(e *env, page string) (*http.Response, string) { return e.signInWith(page, "google") },
		},
		// A live Session, asked to agree to new terms.
		"session": {
			user: func(e *env) string {
				e.bootstrap("owner", "password1")
				_, page := e.authorize("")
				resp, _ := e.submit(page, "owner", "password1")
				return e.idToken(e.code(resp))["sub"].(string)
			},
			login: func(_ *env, page string) (*http.Response, string) { return nil, page },
		},
	}
	// A step's setup makes the User stop at it and returns what enters it.
	type step struct {
		marker string
		setup  func(e *env, sub string) func(e *env, page string) *http.Response
	}
	steps := map[string]step{
		"totp": {totpForm, func(e *env, sub string) func(*env, string) *http.Response {
			secret, _ := e.twoFactor(sub)
			return func(e *env, page string) *http.Response {
				resp, _ := e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
				return resp
			}
		}},
		"phone": {"绑定手机号", func(e *env, _ string) func(*env, string) *http.Response {
			if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
				e.t.Fatal(err)
			}
			return func(e *env, page string) *http.Response {
				if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
					e.t.Fatal(err)
				}
				e.post(page, url.Values{"op": {"send"}, "identifier": {phone}, "altcha": {e.solve()}})
				code := e.inbox.take(phone)
				if code == "" {
					return nil
				}
				resp, _ := e.post(page, url.Values{"op": {"verify"}, "identifier": {phone}, "code": {code}})
				return resp
			}
		}},
		"consent": {`value="consent"`, func(e *env, _ string) func(*env, string) *http.Response {
			e.setTerms("v1")
			return func(e *env, page string) *http.Response {
				resp, _ := e.post(page, url.Values{"op": {"consent"}, "agree": {"v1"}})
				return resp
			}
		}},
	}
	// Password and code logins agree to the terms with the first factor;
	// only a live Session or a Provider login stops at them.
	cases := []struct{ factor, step string }{
		{"password", "totp"}, {"password", "phone"},
		{"code", "totp"}, {"code", "phone"},
		{"google", "totp"}, {"google", "phone"}, {"google", "consent"},
		{"session", "consent"},
	}
	for _, c := range cases {
		f, s := factors[c.factor], steps[c.step]
		t.Run(c.factor+"/"+c.step, func(t *testing.T) {
			e := start(t)
			sub := f.user(e)
			advance := s.setup(e, sub)
			_, page := e.authorize("")
			_, page = f.login(e, page)
			if !strings.Contains(page, s.marker) {
				t.Fatalf("want the %s step:\n%s", c.step, page)
			}
			attacker := e.client

			e.newBrowser()
			signedIn := func(resp *http.Response) bool {
				return resp != nil && (strings.HasPrefix(resp.Header.Get("Location"), callback) || e.hasSessionCookie())
			}
			action := html.UnescapeString(actionRE.FindStringSubmatch(page)[1])
			resp, body := e.do("GET", action, nil)
			for _, other := range steps {
				if signedIn(resp) || strings.Contains(body, other.marker) {
					t.Errorf("forwarded page showed a step: %d %s", resp.StatusCode, body)
				}
			}
			if resp := advance(e, page); signedIn(resp) || len(e.consents(sub)) > 0 {
				t.Errorf("forwarded page went on: %v %v", resp, e.consents(sub))
			}

			// The attacker's browser still goes on: the TOTP code is unspent, the
			// phone number unbound.
			e.client = attacker
			if got := e.idToken(e.code(advance(e, page)))["sub"]; got != sub {
				t.Errorf("signed in as %v, want %s", got, sub)
			}
		})
	}
}

// Tabs of one browser each go on with their own login.
func TestPendingLoginsInTabsOfOneBrowser(t *testing.T) {
	e := start(t)
	sub, err := e.ids.SignIn(context.Background(), "email", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	secret, codes := e.twoFactor(sub)
	_, one := e.authorize("")
	_, one = e.codeLogin(one, "a@example.com", "a@example.com")
	_, two := e.authorize("")
	_, two = e.codeLogin(two, "a@example.com", "a@example.com")

	resp, _ := e.post(one, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	e.code(resp)
	resp, _ = e.post(two, url.Values{"op": {"totp"}, "recovery_code": {codes[0]}})
	e.code(resp)
}
