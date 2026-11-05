package login_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/oidcstore"

	_ "github.com/zibyn/polaris/internal/provider/dingtalk"
	_ "github.com/zibyn/polaris/internal/provider/feishu"
	_ "github.com/zibyn/polaris/internal/provider/github"
	_ "github.com/zibyn/polaris/internal/provider/google"
	_ "github.com/zibyn/polaris/internal/provider/microsoft"
	_ "github.com/zibyn/polaris/internal/provider/wecom"
)

// The named providers get a button of their own, as each one's brand
// guidelines ask: its logo inline, and the wording the brand lays down.
// The generic types keep the plain text button (TestSignInWithGenericOIDC).
func TestNamedProviderButtons(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	create := func(typ, name string, config map[string]string) {
		t.Helper()
		if err := e.providers().Create(ctx, typ, typ, name, config, audit.User("")); err != nil {
			t.Fatal(err)
		}
	}
	create("google", "Google", map[string]string{"client_id": "c", "client_secret": "s"})
	create("microsoft", "Microsoft", map[string]string{"tenant": "common", "client_id": "c", "client_secret": "s"})
	create("github", "GitHub", map[string]string{"client_id": "c", "client_secret": "s"})
	create("feishu", "飞书", map[string]string{"client_id": "c", "client_secret": "s"})
	create("lark", "Lark", map[string]string{"client_id": "c", "client_secret": "s"})
	create("dingtalk", "钉钉", map[string]string{"client_id": "c", "client_secret": "s"})
	create("wecom", "企业微信", map[string]string{"corp_id": "c", "agent_id": "1", "secret": "s"})

	_, page := e.authorize("")
	for _, want := range []string{
		`class="google"`, "使用 Google 账号登录",
		`class="microsoft"`, "使用 Microsoft 登录",
		`class="github"`, "使用 GitHub 登录",
		`class="feishu"`, "使用飞书登录", "使用 Lark 登录", "#00d6b9",
		`class="dingtalk"`, "使用钉钉登录", "#0285fc",
		`class="wecom"`, "使用企业微信登录", "#2dbc00",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("no %s in:\n%s", want, page)
		}
	}
	// Google's guidelines forbid a monochrome G: the logo is the colour one.
	for _, c := range []string{"#EA4335", "#4285F4", "#FBBC05", "#34A853"} {
		if !strings.Contains(page, c) {
			t.Errorf("Google logo missing %s:\n%s", c, page)
		}
	}
}

// setBrand gives the instance a 品牌, with a Logo blob under logo when set.
func (e *env) setBrand(name, logo, color string) {
	e.t.Helper()
	ctx := context.Background()
	if logo != "" {
		if _, err := e.pool.Exec(ctx, `INSERT INTO blobs (key, content_type, bytes) VALUES ('brand/' || $1, 'image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg"/>')`, logo); err != nil {
			e.t.Fatal(err)
		}
		logo = "brand/" + logo
	}
	if _, err := e.pool.Exec(ctx, `UPDATE settings SET brand_name = $1, brand_logo = $2, brand_color = $3`, name, logo, color); err != nil {
		e.t.Fatal(err)
	}
}

// The instance's 品牌 replaces the 「星云」 look on every hosted page: its
// name in the brand panel and the title, its Logo for the star and the
// favicon, its colour's shades, and no Polaris byline.
func TestInstanceBrandOnTheLoginPage(t *testing.T) {
	e := start(t)
	e.setBrand("Acme", "LOGO", "#0a66c2")
	_, page := e.authorize("")
	for _, want := range []string{
		"<title>登录 · Acme</title>", `<link rel="icon" href="/brand-logos/LOGO">`,
		`<div><img src="/brand-logos/LOGO" alt="">Acme</div>`, `<img class="logo" src="/brand-logos/LOGO" alt="">`,
		"--primary: #0a66c2;", "继续前往 <b>Test RP</b>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("no %s in:\n%s", want, page)
		}
	}
	for _, gone := range []string{`class="sky"`, `class="star"`, "由 Polaris 提供安全登录", "Polaris"} {
		if strings.Contains(page, gone) {
			t.Errorf("%s still in:\n%s", gone, page)
		}
	}

	// The Logo is served sandboxed: an SVG's scripts never run.
	resp, _ := e.do("GET", "/brand-logos/LOGO", nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/svg+xml" ||
		resp.Header.Get("Content-Security-Policy") != "sandbox" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Logo: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := e.do("GET", "/brand-logos/nope", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown Logo: %d", resp.StatusCode)
	}

	// Only a colour: the nebula goes, and the name stays Polaris.
	e.setBrand("", "", "#0a66c2")
	_, page = e.authorize("")
	if strings.Contains(page, `class="sky"`) || !strings.Contains(page, "<div>Polaris</div>") || strings.Contains(page, "<img") {
		t.Errorf("colour only:\n%s", page)
	}
}

// An Application that overrides only the colour keeps the instance's name
// and Logo; another Application, and the invite page, keep the instance's
// colour.
func TestApplicationBrandOverridesItemByItem(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	e.setBrand("Acme", "LOGO", "#0a66c2")
	if err := oidcstore.CreateApplication(ctx, e.pool, oidcstore.Application{
		ClientID: "other", Name: "Other", RedirectURIs: []string{callback},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE applications SET brand_color = '#d00000' WHERE client_id = $1`, clientID); err != nil {
		t.Fatal(err)
	}
	_, page := e.authorize("")
	if !strings.Contains(page, "--primary: #d00000;") || !strings.Contains(page, ">Acme</div>") || !strings.Contains(page, "/brand-logos/LOGO") {
		t.Errorf("own colour, instance name and Logo:\n%s", page)
	}
	_, page = e.authorizeAs("other", callback, "")
	if !strings.Contains(page, "--primary: #0a66c2;") {
		t.Errorf("another Application:\n%s", page)
	}
	_, token := e.invited("alice@example.com")
	_, page = e.do("GET", "/invite?token="+token, nil)
	if !strings.Contains(page, "--primary: #0a66c2;") || !strings.Contains(page, ">Acme</div>") {
		t.Errorf("invite page:\n%s", page)
	}
}
