package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// setTerms publishes a version of the terms, as the admin does in the console.
func (e *env) setTerms(version string) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE settings SET terms_version = $1,
		terms_url = 'https://example.com/terms', privacy_url = 'https://example.com/privacy'`, version); err != nil {
		e.t.Fatal(err)
	}
}

// consents lists the versions sub agreed to, through which Application.
func (e *env) consents(sub string) []string {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "SELECT version || '@' || client_id FROM consents WHERE user_id = $1 ORDER BY at", sub)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func TestLoginRequiresAgreeingToTheTerms(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.setTerms("v1")

	_, page := e.authorize("")
	if !strings.Contains(page, `href="https://example.com/terms"`) || !strings.Contains(page, `href="https://example.com/privacy"`) ||
		!strings.Contains(page, `name="agree" value="v1" required`) || strings.Contains(page, "checked") {
		t.Fatalf("login page lacks an unticked terms checkbox:\n%s", page)
	}
	resp, page := e.submit(page, "owner", "password1")
	if resp.StatusCode != 200 || !strings.Contains(page, "请先阅读并同意") {
		t.Fatalf("without agreeing: %d %s", resp.StatusCode, page)
	}
	resp, _ = e.post(page, url.Values{"op": {"password"}, "username": {"owner"}, "password": {"password1"}, "agree": {"v1"}, "altcha": {e.solve()}})
	sub := e.idToken(e.code(resp))["sub"].(string)
	if got := e.consents(sub); len(got) != 1 || got[0] != "v1@"+clientID {
		t.Errorf("consents: %v", got)
	}

	// The same version is not asked again.
	resp, _ = e.authorize("")
	e.code(resp)

	// A new version is, even with a live Session.
	e.setTerms("v2")
	resp, _ = e.authorize("&prompt=none")
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc.Query().Get("error") != "interaction_required" {
		t.Errorf("prompt=none with new terms: %d %q", resp.StatusCode, loc)
	}
	resp, page = e.authorize("")
	if resp.StatusCode != 200 || !strings.Contains(page, `name="agree" value="v2" required`) || strings.Contains(page, `name="password"`) {
		t.Fatalf("want the consent page, got %d %s", resp.StatusCode, page)
	}
	resp, page = e.post(page, url.Values{"op": {"consent"}, "agree": {"v1"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "请先阅读并同意") {
		t.Fatalf("agreeing to the old version: %d %s", resp.StatusCode, page)
	}
	resp, _ = e.post(page, url.Values{"op": {"consent"}, "agree": {"v2"}})
	if again := e.idToken(e.code(resp)); again["sub"] != sub {
		t.Errorf("after consent: %v", again)
	}
	if got := e.consents(sub); len(got) != 2 || got[1] != "v2@"+clientID {
		t.Errorf("consents: %v", got)
	}

	// Consents go with the User.
	if _, err := e.pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", sub); err != nil {
		t.Fatal(err)
	}
	if got := e.consents(sub); len(got) != 0 {
		t.Errorf("consents after deletion: %v", got)
	}
}

// Code login asks for agreement before sending the code.
func TestCodeLoginRequiresAgreeingToTheTerms(t *testing.T) {
	e := start(t)
	e.setTerms("v1")
	const phone = "+8613800138000"

	_, page := e.authorize("")
	resp, body := e.post(page, url.Values{"op": {"send"}, "identifier": {phone}, "altcha": {e.solve()}})
	if !strings.Contains(body, "请先阅读并同意") || e.inbox.take(phone) != "" {
		t.Fatalf("send without agreeing: %d %s", resp.StatusCode, body)
	}
	_, body = e.post(page, url.Values{"op": {"send"}, "identifier": {phone}, "altcha": {e.solve()}, "agree": {"v1"}})
	code := e.inbox.take(phone)
	if !strings.Contains(body, `name="agree" value="v1"`) {
		t.Fatalf("code page does not carry the agreement:\n%s", body)
	}
	resp, _ = e.post(body, url.Values{"op": {"verify"}, "identifier": {phone}, "code": {code}, "agree": {"v1"}})
	sub := e.idToken(e.code(resp))["sub"].(string)
	if got := e.consents(sub); len(got) != 1 {
		t.Errorf("consents: %v", got)
	}
}

// An App draws its own checkbox and sends the version the User agreed to.
func TestDirectLoginChecksTheTermsVersion(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.setTerms("v2")

	_, body := e.do("GET", "/v1/auth/terms", nil)
	if body != `{"privacy_url":"https://example.com/privacy","terms_url":"https://example.com/terms","version":"v2"}`+"\n" {
		t.Errorf("terms: %s", body)
	}
	for _, v := range []string{"v1", ""} {
		r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "terms_version": {v}})
		if r.Status != 400 || r.Error != "invalid_request" || r.Code != "" {
			t.Errorf("version %q: %+v", v, r)
		}
	}
	r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "terms_version": {"v2"}})
	if r.Status != 200 {
		t.Fatalf("current version: %+v", r)
	}
	sub := e.claims(e.exchange(clientID, "", r.Code).IDToken)["sub"].(string)
	if got := e.consents(sub); len(got) != 1 || got[0] != "v2@"+clientID {
		t.Errorf("consents: %v", got)
	}
}
