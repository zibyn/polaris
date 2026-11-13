package login_test

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
)

// ownerTwoFactor bootstraps owner with password1 and turns 两步验证 on for
// them; it returns the TOTP secret.
func (e *env) ownerTwoFactor() string {
	e.t.Helper()
	e.bootstrap("owner", "password1")
	var sub string
	if err := e.pool.QueryRow(context.Background(), "SELECT user_id FROM identifiers WHERE value = 'owner'").Scan(&sub); err != nil {
		e.t.Fatal(err)
	}
	secret, _ := e.twoFactor(sub)
	return secret
}

// endLockouts makes every lockout over.
func (e *env) endLockouts() {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE lockouts SET until = now() - interval '1 second'"); err != nil {
		e.t.Fatal(err)
	}
}

// Wrong TOTP codes and 恢复码 count against the User across logins and IPs:
// a right one starts the count over, and the tenth wrong one in a row locks
// 两步验证, a right code refused too, audited once. The login is not ended:
// once the lock is over, the same login goes on.
func TestHostedTwoFactorLocksTheUser(t *testing.T) {
	e := start(t)
	secret := e.ownerTwoFactor()

	// login starts a login from ip, up to the TOTP step.
	login := func(ip string) string {
		t.Helper()
		e.ip = ip
		e.newBrowser()
		_, page := e.authorize("")
		_, page = e.submit(page, "owner", "password1")
		if !strings.Contains(page, totpForm) {
			t.Fatalf("want the TOTP step: %s", page)
		}
		return page
	}
	page := login("198.51.100.1")
	for range 4 {
		_, page = e.post(page, url.Values{"op": {"totp"}, "totp": {"000000"}})
	}
	resp, _ := e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	e.code(resp)

	wrong := 0
	for ip := 2; wrong < 10; ip++ {
		page = login(fmt.Sprintf("198.51.100.%d", ip))
		for n := 0; n < 4 && wrong < 10; n++ {
			form := url.Values{"op": {"totp"}, "totp": {"000000"}}
			if n == 1 {
				form = url.Values{"op": {"totp"}, "recovery_code": {"aaaa-aaaa"}}
			}
			_, page = e.post(page, form)
			wrong++
		}
	}
	resp, page = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 1)}})
	if resp.StatusCode != 200 || !strings.Contains(html.UnescapeString(page), identity.ErrTwoFactorLocked.Error()) || !strings.Contains(page, totpForm) || e.hasSessionCookie() {
		t.Fatalf("right TOTP while locked: %d %s", resp.StatusCode, page)
	}
	if n := e.audits("login.two_factor_locked"); n != 1 {
		t.Errorf("audited %d lockouts", n)
	}

	e.endLockouts()
	resp, _ = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 1)}})
	e.code(resp)
}

// The direct auth API shares the lock: the right code is refused with the
// lock's error, and the auth_session stays.
func TestDirectTwoFactorLocksTheUser(t *testing.T) {
	e := start(t)
	secret := e.ownerTwoFactor()

	var as string
	for wrong, ip := 0, 1; wrong < 10; ip++ {
		e.ip = fmt.Sprintf("198.51.100.%d", ip)
		r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}})
		if r.Next != "totp" {
			t.Fatalf("want next totp: %+v", r)
		}
		as = r.AuthSession
		for n := 0; n < 4 && wrong < 10; n++ {
			e.challenge(url.Values{"auth_session": {as}, "totp": {"000000"}})
			wrong++
		}
	}
	r := e.challenge(url.Values{"auth_session": {as}, "totp": {totpAt(secret, 0)}})
	if r.Status != 400 || r.Error != "invalid_request" || r.Describe != identity.ErrTwoFactorLocked.Error() || r.AuthSession != as {
		t.Fatalf("right TOTP while locked: %+v", r)
	}
	if n := e.audits("login.two_factor_locked"); n != 1 {
		t.Errorf("audited %d lockouts", n)
	}

	e.endLockouts()
	if r := e.challenge(url.Values{"auth_session": {as}, "totp": {totpAt(secret, 0)}}); r.Status != 200 {
		t.Errorf("after the lock: %+v", r)
	}
}
