package login_test

import (
	"context"
	"strings"
	"testing"

	_ "github.com/zibyn/polaris/internal/provider/github"
	_ "github.com/zibyn/polaris/internal/provider/google"
	_ "github.com/zibyn/polaris/internal/provider/microsoft"
)

// The named providers get a button of their own, as each one's brand
// guidelines ask: its logo inline, and the wording the brand lays down.
// The generic types keep the plain text button (TestSignInWithGenericOIDC).
func TestNamedProviderButtons(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	create := func(typ, name string, config map[string]string) {
		t.Helper()
		if err := e.providers().Create(ctx, typ, typ, name, config); err != nil {
			t.Fatal(err)
		}
	}
	create("google", "Google", map[string]string{"client_id": "c", "client_secret": "s"})
	create("microsoft", "Microsoft", map[string]string{"tenant": "common", "client_id": "c", "client_secret": "s"})
	create("github", "GitHub", map[string]string{"client_id": "c", "client_secret": "s"})

	_, page := e.authorize("")
	for _, want := range []string{
		`class="google"`, "使用 Google 账号登录",
		`class="microsoft"`, "使用 Microsoft 登录",
		`class="github"`, "使用 GitHub 登录",
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
