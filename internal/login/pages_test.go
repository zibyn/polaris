package login

import (
	"bytes"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/provider"
)

// The Chinese pages are, byte for byte, what they were before the message
// tables and brands came in (testdata/golden, captured then).
func TestPagesGolden(t *testing.T) {
	for name, c := range goldenCases() {
		w := httptest.NewRecorder()
		page(w, langZH, 200, c.tmpl, c.data)
		want, err := os.ReadFile("testdata/golden/" + name + ".html")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(w.Body.Bytes(), want) {
			t.Errorf("%s differs from its golden file:\n%s", name, w.Body)
		}
	}
}

var han = regexp.MustCompile(`\p{Han}`)

// Every page renders in English, and has no Chinese left outside comments.
func TestPagesEnglish(t *testing.T) {
	comments := regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)
	for name, c := range goldenCases() {
		w := httptest.NewRecorder()
		page(w, langEN, 200, c.tmpl, c.data)
		body := w.Body.String()
		if !bytes.Contains(w.Body.Bytes(), []byte(`<html lang="en">`)) || !bytes.Contains(w.Body.Bytes(), []byte("</html>")) {
			t.Errorf("%s did not render in English:\n%s", name, body)
		}
		if m := han.FindAllString(comments.ReplaceAllString(body, ""), -1); m != nil {
			t.Errorf("%s has Chinese left %q:\n%s", name, m, body)
		}
	}
}

type goldenCase struct {
	tmpl string
	data any
}

func goldenCases() map[string]goldenCase {
	terms := sqlc.TermsRow{TermsUrl: "https://t.example/terms", PrivacyUrl: "https://t.example/privacy", TermsVersion: "v1"}
	base := loginPage{Client: "Test RP", Action: "/authorize/abc", Terms: terms, CodeKinds: "手机号或邮箱", IdentifierLabel: "手机号、邮箱或用户名", PasswordOn: true,
		Providers: []provider.Button{{ID: "a", Type: "apple"}, {ID: "g", Type: "google"}, {ID: "m", Type: "microsoft"}, {ID: "h", Type: "github"}, {ID: "f", Type: "feishu"}, {ID: "l", Type: "lark"}, {ID: "d", Type: "dingtalk"}, {ID: "w", Type: "wecom"}, {ID: "o", Type: "oidc", Name: "Okta"}},
		Passkey:   `{"publicKey":{"challenge":"x"}}`}
	with := func(f func(*loginPage)) loginPage { p := base; f(&p); return p }
	return map[string]goldenCase{
		"login-first": {"login", base},
		"login-first-phone": {"login", with(func(p *loginPage) {
			p.PasswordOn = false
			p.CodeKinds = "手机号"
			p.IdentifierLabel = "手机号"
			p.Passkey = ""
		})},
		"login-first-email": {"login", with(func(p *loginPage) {
			p.PasswordOn = false
			p.CodeKinds = "邮箱"
			p.IdentifierLabel = "邮箱"
			p.Error = "人机验证未通过,请重试"
		})},
		"login-password":     {"login", with(func(p *loginPage) { p.PasswordForm = true; p.Error = "用户名或密码错误" })},
		"login-username":     {"login", with(func(p *loginPage) { p.Username = "alice"; p.Passkey = "" })},
		"login-code-sent":    {"login", with(func(p *loginPage) { p.Identifier = "a@b.c"; p.CodeSent = true; p.Passkey = "" })},
		"login-totp":         {"login", with(func(p *loginPage) { p.TOTP = true; p.Error = "验证码不正确或已用过" })},
		"login-recovery":     {"login", with(func(p *loginPage) { p.TOTP = true; p.Recovery = true })},
		"login-consent":      {"login", with(func(p *loginPage) { p.Consent = true })},
		"login-consent-none": {"login", with(func(p *loginPage) { p.Consent = true; p.Terms = sqlc.TermsRow{} })},
		"login-bind": {"login", with(func(p *loginPage) {
			p.Bind = true
			p.CodeKinds = "手机号"
			p.IdentifierLabel = "手机号"
			p.Providers = nil
			p.Passkey = ""
		})},
		"login-bind-sent": {"login", with(func(p *loginPage) {
			p.Bind = true
			p.CodeSent = true
			p.Identifier = "+8613800000000"
			p.Providers = nil
			p.Passkey = ""
		})},
		"login-set-password": {"login", with(func(p *loginPage) { p.SetPassword = true; p.Error = "密码至少 8 位" })},
		"setup":              {"setup", setupForm{Token: "tok", Username: "root", Error: "setup token 无效"}},
		"invite":             {"invite", inviteForm{Token: "tok", Error: "密码至少 8 位"}},
		"message":            {"message", "已退出登录"},
		"denied":             {"denied", loginPage{Client: "Test RP", Action: "/authorize/abc"}},
		"logout":             {"logout", "/logout/abc"},
	}
}
