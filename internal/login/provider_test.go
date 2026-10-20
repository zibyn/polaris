package login_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	oidcop "github.com/zibyn/polaris/internal/oidc/provider"
	"github.com/zibyn/polaris/internal/provider"
	_ "github.com/zibyn/polaris/internal/provider/oidc"
)

// upstream is an OpenID Provider standing in for Google: whoever the browser
// is, it signs them in as sub.
type upstream struct {
	issuer string
	sub    string
}

func startUpstream(t *testing.T, redirectURI string) *upstream {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	up := &upstream{issuer: "http://" + ts.Listener.Addr().String(), sub: "google-user-1"}
	op, err := oidcop.New(
		oidcop.Config{
			Issuer: up.issuer,
			JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
				return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}, nil
			},
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgRS256},
		},
		oidcop.WithStaticClients(&goidc.Client{ID: "upstream", Secret: "shh", ClientMeta: goidc.ClientMeta{
			RedirectURIs: []string{redirectURI}, TokenAuthnMethod: goidc.AuthnMethodSecretBasic,
			GrantTypes: []goidc.GrantType{goidc.GrantAuthorizationCode}, ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			ScopeIDs: "openid",
		}}),
		oidcop.WithScopes(goidc.ScopeOpenID),
		oidcop.WithSecretBasicAuthn(),
		oidcop.WithAuthCodeGrant(
			oidcop.AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			oidcop.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}, oidcop.WithPKCERequired()),
			oidcop.WithAuthPolicies(goidc.NewPolicy("anyone",
				func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { return true },
				func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					as.Subject, as.GrantedScopes = up.sub, as.Scopes
					return goidc.StatusSuccess, nil
				})),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = op.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return up
}

// addGoogle adds the upstream as the Provider "google" and returns it.
func (e *env) addGoogle() *upstream {
	e.t.Helper()
	up := startUpstream(e.t, provider.CallbackURL(e.issuer, "google"))
	if err := e.providers().Create(context.Background(), "google", "oidc", "Google",
		map[string]string{"issuer": up.issuer, "client_id": "upstream", "client_secret": "shh"}); err != nil {
		e.t.Fatal(err)
	}
	return up
}

func (e *env) providers() *provider.Store {
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	return provider.NewStore(e.pool, keyring)
}

var providerFormRE = regexp.MustCompile(`(?s)<form[^>]*action="([^"]+)"[^>]*>\s*<input type="hidden" name="op" value="provider">(.*?)</form>`)

// signInWith presses the button of Provider id on the login page and follows
// the redirects through the upstream and back to the page after it.
func (e *env) signInWith(page, id string) (*http.Response, string) {
	e.t.Helper()
	m := providerFormRE.FindStringSubmatch(page)
	if m == nil || !strings.Contains(m[2], `value="`+id+`"`) {
		e.t.Fatalf("no button for %s in:\n%s", id, page)
	}
	resp, body := e.do("POST", html.UnescapeString(m[1]), url.Values{"op": {"provider"}, "provider": {id}})
	for resp.StatusCode/100 == 3 {
		loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
		if err != nil {
			e.t.Fatal(err)
		}
		if strings.HasPrefix(loc.String(), callback) {
			return resp, body
		}
		resp, body = e.do("GET", loc.String(), nil)
	}
	return resp, body
}

func TestSignInWithGenericOIDC(t *testing.T) {
	e := start(t)
	e.addGoogle()

	_, page := e.authorize("")
	if !strings.Contains(page, "使用 Google 登录") {
		t.Fatalf("no Google button:\n%s", page)
	}
	resp, _ := e.signInWith(page, "google")
	claims := e.idToken(e.code(resp))
	sub, _ := claims["sub"].(string)
	if sub == "" || sub == "google-user-1" || !slices.Equal(claims["amr"].([]any), []any{"fed"}) {
		t.Errorf("first login: %v", claims)
	}

	// Another browser, the same Google account: the same User.
	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.signInWith(page, "google")
	if again := e.idToken(e.code(resp)); again["sub"] != sub {
		t.Errorf("second login: %v, want sub %s", again, sub)
	}

	// A callback replayed, or from no login started here, signs nobody in.
	if resp, _ := e.do("GET", provider.CallbackURL("", "google")+"?state=forged&code=x", nil); resp.StatusCode != 400 {
		t.Errorf("forged callback: %d, want 400", resp.StatusCode)
	}
}

func TestProviderLoginGoesOnToTwoFactorTermsAndPhone(t *testing.T) {
	e := start(t)
	e.addGoogle()
	_, page := e.authorize("")
	resp, _ := e.signInWith(page, "google")
	sub := e.idToken(e.code(resp))["sub"].(string)

	secret, _ := e.twoFactor(sub)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}
	e.setTerms("v1")

	e.newBrowser()
	_, page = e.authorize("&scope=openid+phone")
	resp, page = e.signInWith(page, "google")
	if resp.StatusCode != 200 || !strings.Contains(page, totpForm) {
		t.Fatalf("want the TOTP page, got %d %s", resp.StatusCode, page)
	}
	resp, page = e.post(page, url.Values{"op": {"totp"}, "totp": {totpAt(secret, 0)}})
	if resp.StatusCode != 200 || !strings.Contains(page, `value="consent"`) {
		t.Fatalf("want the terms page, got %d %s", resp.StatusCode, page)
	}
	resp, page = e.post(page, url.Values{"op": {"consent"}, "agree": {"v1"}})
	if resp.StatusCode != 200 || !strings.Contains(page, "绑定手机号") {
		t.Fatalf("want the bind page, got %d %s", resp.StatusCode, page)
	}
	resp, _ = e.codeLogin(page, "13900139000", "+8613900139000")
	claims := e.idToken(e.code(resp))
	if claims["sub"] != sub || !slices.Equal(claims["amr"].([]any), []any{"fed", "otp", "mfa"}) ||
		claims["phone_number"] != "+8613900139000" {
		t.Errorf("after the steps: %v", claims)
	}
}

func TestDisabledProviderSignsNobodyIn(t *testing.T) {
	e := start(t)
	e.addGoogle()
	ctx := context.Background()

	// Disabled between pressing the button and coming back.
	_, page := e.authorize("")
	m := providerFormRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no Provider buttons:\n%s", page)
	}
	resp, _ := e.do("POST", html.UnescapeString(m[1]), url.Values{"op": {"provider"}, "provider": {"google"}})
	if resp.StatusCode != 303 {
		t.Fatalf("button: %d", resp.StatusCode)
	}
	resp, _ = e.do("GET", resp.Header.Get("Location"), nil) // the upstream signs in
	if err := e.providers().SetEnabled(ctx, "google", false); err != nil {
		t.Fatal(err)
	}
	if resp, body := e.do("GET", resp.Header.Get("Location"), nil); resp.StatusCode != 400 {
		t.Errorf("callback after disabling: %d %s", resp.StatusCode, body)
	}

	_, page = e.authorize("")
	if strings.Contains(page, "使用 Google 登录") {
		t.Error("button still shown")
	}
	resp, _ = e.post(page, url.Values{"op": {"provider"}, "provider": {"google"}})
	if resp.StatusCode/100 == 3 {
		t.Errorf("pressed anyway: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestDeletedUserLeavesTheirExternalIdentity(t *testing.T) {
	e := start(t)
	e.addGoogle()
	_, page := e.authorize("")
	resp, _ := e.signInWith(page, "google")
	sub := e.idToken(e.code(resp))["sub"].(string)

	if err := e.ids.Delete(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	e.newBrowser()
	_, page = e.authorize("")
	resp, _ = e.signInWith(page, "google")
	if again := e.idToken(e.code(resp))["sub"]; again == sub {
		t.Errorf("signed in as the deleted User %s", sub)
	}
}

// pressGoogle presses the Google button on page and signs in at the
// upstream, returning the callback URL the upstream sends the browser to.
func (e *env) pressGoogle(page string) string {
	e.t.Helper()
	m := providerFormRE.FindStringSubmatch(page)
	if m == nil {
		e.t.Fatalf("no Provider buttons:\n%s", page)
	}
	resp, _ := e.do("POST", html.UnescapeString(m[1]), url.Values{"op": {"provider"}, "provider": {"google"}})
	resp, _ = e.do("GET", resp.Header.Get("Location"), nil)
	return resp.Header.Get("Location")
}

// Login CSRF: an attacker signs in at Google as themselves and hands the
// victim's browser the rest of the flow.
func TestProviderLoginFinishesOnlyInTheBrowserThatStartedIt(t *testing.T) {
	e := start(t)
	e.addGoogle()
	signedIn := func(resp *http.Response) bool {
		return strings.HasPrefix(resp.Header.Get("Location"), callback) ||
			slices.ContainsFunc(resp.Cookies(), func(c *http.Cookie) bool { return c.Name == "__Host-session" && c.MaxAge >= 0 })
	}

	// The callback URL, forwarded.
	_, page := e.authorize("")
	cb := e.pressGoogle(page)
	attacker := e.client
	e.newBrowser()
	if resp, body := e.do("GET", cb, nil); resp.StatusCode != 400 || signedIn(resp) {
		t.Errorf("forwarded callback: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}

	// The login page after the callback, forwarded.
	e.client = attacker
	_, page = e.authorize("")
	resp, _ := e.do("GET", e.pressGoogle(page), nil)
	next := resp.Header.Get("Location")
	if !strings.HasPrefix(next, "/authorize/") {
		t.Fatalf("callback: %d %s", resp.StatusCode, next)
	}
	e.newBrowser()
	if resp, _ := e.do("GET", next, nil); signedIn(resp) {
		t.Errorf("forwarded %s signed the victim in: %d %s", next, resp.StatusCode, resp.Header.Get("Location"))
	}
	e.client = attacker
	if resp, _ := e.do("GET", next, nil); !strings.HasPrefix(resp.Header.Get("Location"), callback) {
		t.Errorf("the attacker's own browser: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestProviderSignUpGetsDefaultRoles(t *testing.T) {
	e := start(t)
	e.addGoogle()
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO apis (identifier, name) VALUES ('https://track.example', 'Track');
		INSERT INTO roles (api, key, name, default_role) VALUES ('https://track.example', 'member', '会员', true)`); err != nil {
		e.t.Fatal(err)
	}
	_, page := e.authorize("")
	resp, _ := e.signInWith(page, "google")
	sub, _ := e.idToken(e.code(resp))["sub"].(string)
	var n int
	if err := e.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM user_roles WHERE user_id = $1 AND api = 'https://track.example' AND role = 'member'", sub).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("a Provider sign-up's default Roles: %d", n)
	}
}
