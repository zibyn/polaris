package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// The hosted pages speak the browser's language when it is Chinese or
// English, and Chinese otherwise.
func TestLoginPageLanguage(t *testing.T) {
	e := start(t)
	for lang, want := range map[string]string{
		"en-US,en;q=0.9":       `<html lang="en">`,
		"fr":                   `<html lang="zh-CN">`,
		"":                     `<html lang="zh-CN">`,
		"zh-TW":                `<html lang="zh-CN">`,
		"fr, en;q=0.5":         `<html lang="en">`,
		"en;q=0.1, zh-CN;q=.8": `<html lang="zh-CN">`,
	} {
		e.lang = lang
		_, page := e.authorize("")
		if !strings.Contains(page, want) {
			t.Errorf("Accept-Language %q: want %s in\n%s", lang, want, page)
		}
		if en := strings.Contains(page, "Sign in"); en != (want == `<html lang="en">`) {
			t.Errorf("Accept-Language %q: English text %v", lang, en)
		}
	}
}

// ui_locales outranks Accept-Language, and the login keeps it: the code step
// and the password step after the first are in the same language.
func TestUILocalesLastsTheLogin(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.lang = "zh-CN"
	_, page := e.authorize("ui_locales=fr en")
	if !strings.Contains(page, `<html lang="en">`) {
		t.Fatalf("ui_locales=en:\n%s", page)
	}
	first := page

	// The password step, reached from the identifier form.
	_, page = e.post(first, url.Values{"op": {"send"}, "identifier": {"owner"}})
	if !strings.Contains(page, `<html lang="en">`) || !strings.Contains(page, ">Password<") {
		t.Fatalf("password step:\n%s", page)
	}
	_, page = e.post(page, url.Values{"op": {"password"}, "username": {"owner"}, "password": {"wrong-password"}, "altcha": {e.solve()}})
	if !strings.Contains(page, "Wrong username or password") {
		t.Errorf("wrong password, in English:\n%s", page)
	}

	// The code step.
	if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	_, page = e.post(first, url.Values{"op": {"send"}, "identifier": {"a@example.com"}, "altcha": {e.solve()}})
	if !strings.Contains(page, `<html lang="en">`) || !strings.Contains(page, "Code sent") {
		t.Errorf("code step:\n%s", page)
	}
}

// English pages link the English terms where they are set, Chinese pages
// the Chinese ones; without English ones both link the Chinese.
func TestEnglishTermsLinks(t *testing.T) {
	e := start(t)
	e.setTerms("v1")
	check := func(lang, terms, privacy string) {
		t.Helper()
		e.lang = lang
		_, page := e.authorize("")
		if !strings.Contains(page, `href="`+terms+`"`) || !strings.Contains(page, `href="`+privacy+`"`) {
			t.Errorf("%s: want %s and %s in\n%s", lang, terms, privacy, page)
		}
	}
	check("en", "https://example.com/terms", "https://example.com/privacy")
	if _, err := e.pool.Exec(context.Background(), `UPDATE settings SET terms_url_en = 'https://example.com/en/terms', privacy_url_en = 'https://example.com/en/privacy'`); err != nil {
		t.Fatal(err)
	}
	check("en", "https://example.com/en/terms", "https://example.com/en/privacy")
	check("zh-CN", "https://example.com/terms", "https://example.com/privacy")
}
