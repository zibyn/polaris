package login_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/login"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/server"
)

const (
	clientID    = "rp"
	callback    = "https://rp.example/cb"
	afterLogout = "https://rp.example/bye"
	verifier    = "a-pkce-code-verifier-that-is-at-least-43-characters-long"
)

type env struct {
	t      *testing.T
	issuer string
	client *http.Client // a browser: keeps cookies, stops at redirects
	ids    *identity.Store
	pool   *pgxpool.Pool
	inbox  *inbox
	ua     string // the User-Agent the browser sends, if set
}

// start runs the whole HTTP surface against a fresh database, with one public
// Application registered.
func start(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := oidcstore.NewKeys(pool, keyring).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := oidcstore.CreateApplication(ctx, pool, oidcstore.Application{
		ClientID: clientID, Name: "Test RP", RedirectURIs: []string{callback}, PostLogoutRedirectURIs: []string{afterLogout},
	}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	// A Passkey's RP ID is the issuer's hostname, which may not be an IP
	// address; localhost is both a hostname and this server's address, which
	// the generated certificate does not cover.
	issuer := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	client := ts.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server, not production
	client.Transport = transport
	auth, err := login.New(ctx, pool, keyring, issuer)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = server.New(pool.Ping, http.NotFoundHandler(), nil, auth.Register)
	e := &env{t: t, issuer: issuer, client: client, ids: identity.New(pool, keyring), pool: pool, inbox: &inbox{codes: map[string]string{}}}
	e.newBrowser()
	hook := httptest.NewServer(e.inbox)
	t.Cleanup(hook.Close)
	for _, kind := range []string{"phone", "email"} {
		if err := channel.NewStore(pool, keyring).Put(ctx, kind, "webhook", map[string]string{"url": hook.URL, "secret": "s"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) newBrowser() {
	jar, _ := cookiejar.New(nil)
	c := *e.client
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	e.client = &c
}

func (e *env) do(method, path string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	u := path
	if !strings.Contains(u, "://") {
		u = e.issuer + path
	}
	req, err := http.NewRequest(method, u, strings.NewReader(form.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if e.ua != "" {
		req.Header.Set("User-Agent", e.ua)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// authorize starts a code flow with extra parameters.
func (e *env) authorize(extra string) (*http.Response, string) {
	return e.authorizeAs(clientID, callback, extra)
}

func (e *env) authorizeAs(client, redirect, extra string) (*http.Response, string) {
	sum := sha256.Sum256([]byte(verifier))
	over, _ := url.ParseQuery(extra)
	q := url.Values{
		"client_id":             {client},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"redirect_uri":          {redirect},
		"state":                 {"st"},
		"nonce":                 {"n"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range over {
		q[k] = v
	}
	return e.do("GET", "/authorize?"+q.Encode(), nil)
}

var actionRE = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)

// submit posts the password form found in page.
func (e *env) submit(page, username, password string) (*http.Response, string) {
	e.t.Helper()
	return e.post(page, url.Values{"op": {"password"}, "username": {username}, "password": {password}})
}

// post posts form to the login page's form action.
func (e *env) post(page string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	m := actionRE.FindStringSubmatch(page)
	if m == nil {
		e.t.Fatalf("no login form in:\n%s", page)
	}
	return e.do("POST", html.UnescapeString(m[1]), form)
}

// code returns the authorization code a response redirects back with.
func (e *env) code(resp *http.Response) string {
	e.t.Helper()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode/100 != 3 || loc.Query().Get("code") == "" {
		e.t.Fatalf("want a redirect with a code, got %d %q", resp.StatusCode, loc)
	}
	return loc.Query().Get("code")
}

func (e *env) idToken(code string) map[string]any {
	e.t.Helper()
	return e.claims(e.exchange(clientID, callback, code).IDToken)
}

type tokens struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (e *env) exchange(client, redirect, code string) tokens {
	e.t.Helper()
	resp, body := e.do("POST", "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {client}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		e.t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	var tok tokens
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// claims verifies a JWT against the published JWKS.
func (e *env) claims(token string) map[string]any {
	e.t.Helper()
	_, jwksBody := e.do("GET", "/jwks", nil)
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jwksBody), &jwks); err != nil {
		e.t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		e.t.Fatal(err)
	}
	var claims map[string]any
	if err := parsed.Claims(jwks.Key(parsed.Headers[0].KeyID)[0].Key, &claims); err != nil {
		e.t.Fatal(err)
	}
	return claims
}

// bootstrap creates the owner through the setup page.
func (e *env) bootstrap(username, password string) {
	e.t.Helper()
	token, err := e.ids.SetupToken(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	resp, page := e.do("GET", "/setup?token="+token, nil)
	if resp.StatusCode != 200 || !strings.Contains(page, `value="`+token+`"`) {
		e.t.Fatalf("setup page: %d %s", resp.StatusCode, page)
	}
	if !strings.Contains(page, `autocomplete="new-password"`) {
		e.t.Errorf("setup page lacks autocomplete hints")
	}
	// Creating the owner lands on the console, which starts its sign-in.
	resp, page = e.do("POST", "/setup", url.Values{"token": {token}, "username": {username}, "password": {password}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/console" {
		e.t.Fatalf("setup: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), page)
	}
}

func TestSetupThenPasswordLogin(t *testing.T) {
	e := start(t)
	token, _ := e.ids.SetupToken(context.Background())

	// A wrong token is turned away and the form shown again.
	resp, page := e.do("POST", "/setup", url.Values{"token": {"nope"}, "username": {"owner"}, "password": {"password1"}})
	if !strings.Contains(page, identity.ErrSetupToken.Error()) || !strings.Contains(page, "<form") {
		t.Fatalf("wrong token: %d %s", resp.StatusCode, page)
	}

	e.bootstrap("owner", "password1")

	// The setup page is closed for good, and the token is dead.
	if resp, _ := e.do("GET", "/setup?token="+token, nil); resp.StatusCode != 404 {
		t.Errorf("setup page after bootstrap: %d", resp.StatusCode)
	}
	if resp, _ := e.do("POST", "/setup", url.Values{"token": {token}, "username": {"x"}, "password": {"password1"}}); resp.StatusCode != 404 {
		t.Errorf("setup again: %d", resp.StatusCode)
	}

	resp, page = e.authorize("")
	if resp.StatusCode != 200 {
		t.Fatalf("authorize: %d %s", resp.StatusCode, page)
	}
	// The identifier field also offers Passkeys in its autofill now.
	for _, want := range []string{`autocomplete="username webauthn"`, `method="post"`} {
		if !strings.Contains(page, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
	if _, form := e.link(page, "使用密码登录"); !strings.Contains(form, `autocomplete="current-password"`) {
		t.Errorf("password form lacks autocomplete hints")
	}

	resp, page = e.submit(page, "owner", "wrong-password")
	if resp.StatusCode != 200 || !strings.Contains(page, identity.ErrBadCredentials.Error()) {
		t.Fatalf("wrong password: %d %s", resp.StatusCode, page)
	}
	resp, _ = e.submit(page, "owner", "password1")
	claims := e.idToken(e.code(resp))
	sub, _ := claims["sub"].(string)
	if sub == "" || !slices.Equal(claims["amr"].([]any), []any{"pwd"}) || claims["auth_time"] == nil || claims["nonce"] != "n" {
		t.Errorf("id token claims: %v", claims)
	}

	// The browser Session signs the next request in silently.
	resp, _ = e.authorize("")
	if again := e.idToken(e.code(resp)); again["sub"] != sub || again["auth_time"] != claims["auth_time"] {
		t.Errorf("silent SSO: %v", again)
	}
	resp, _ = e.authorize("&prompt=none")
	e.code(resp)

	// These ask for the password again, even with a Session.
	for _, extra := range []string{"&prompt=login", "&prompt=select_account", "&max_age=0"} {
		if resp, page := e.authorize(extra); resp.StatusCode != 200 || !actionRE.MatchString(page) {
			t.Errorf("%s: want the login form, got %d", extra, resp.StatusCode)
		}
	}
	resp, _ = e.authorize("&prompt=none+login")
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc.Query().Get("error") != "invalid_request" {
		t.Errorf("prompt=none login: %d %q", resp.StatusCode, loc)
	}
	// prompt=consent is accepted and ignored: no consent page.
	resp, _ = e.authorize("&prompt=consent")
	e.code(resp)

	// Without a Session, prompt=none fails back to the Application.
	e.newBrowser()
	resp, _ = e.authorize("&prompt=none")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), callback) || loc.Query().Get("error") != "login_required" {
		t.Errorf("prompt=none without a Session: %d %q", resp.StatusCode, loc)
	}
}

// A login form posted from another site is refused (login CSRF).
func TestLoginFormRejectsCrossSitePost(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	_, page := e.authorize("")
	m := actionRE.FindStringSubmatch(page)
	req, _ := http.NewRequest("POST", e.issuer+html.UnescapeString(m[1]),
		strings.NewReader(url.Values{"username": {"owner"}, "password": {"password1"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 == 3 && strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Errorf("cross-site login went through")
	}
}

// The console signs in like any Application, and its access token is for the
// Management API.
func TestConsoleAccessTokenIsForManagementAPI(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	redirect := e.issuer + "/console/callback"
	_, page := e.authorizeAs(identity.ConsoleClientID, redirect, "")
	resp, _ := e.submit(page, "owner", "password1")
	claims := e.claims(e.exchange(identity.ConsoleClientID, redirect, e.code(resp)).AccessToken)
	if claims["aud"] != identity.ManagementAPI || claims["client_id"] != identity.ConsoleClientID {
		t.Errorf("access token claims: %v", claims)
	}
}

// The account center signs in like any Application; its access token is for
// the Account API and names the Session it was issued in.
func TestAccountAccessTokenNamesItsSession(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	redirect := e.issuer + "/account/callback"
	_, page := e.authorizeAs(identity.AccountClientID, redirect, "")
	resp, _ := e.submit(page, "owner", "password1")
	claims := e.claims(e.exchange(identity.AccountClientID, redirect, e.code(resp)).AccessToken)
	var sid string
	if err := e.pool.QueryRow(context.Background(), "SELECT id FROM sessions").Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != identity.AccountAPI || claims["sid"] != sid {
		t.Errorf("access token claims: %v, Session %s", claims, sid)
	}
}

// The access token carries the User's Roles and their Permissions on the
// API it is for, and only that API's; the ID token carries none.
func TestAccessTokenCarriesRolesOfItsAPI(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO apis (identifier, name) VALUES ('https://track.example', 'Track'), ('https://other.example', 'Other');
		INSERT INTO permissions (api, key, name) VALUES
			('https://track.example', 'track:read', 'r'), ('https://track.example', 'track:write', 'w'),
			('https://other.example', 'other:x', 'x');
		INSERT INTO roles (api, key, name) VALUES
			('https://track.example', 'viewer', 'V'), ('https://track.example', 'editor', 'E'), ('https://other.example', 'boss', 'B');
		INSERT INTO role_permissions VALUES
			('https://track.example', 'viewer', 'track:read'), ('https://track.example', 'editor', 'track:read'),
			('https://track.example', 'editor', 'track:write'), ('https://other.example', 'boss', 'other:x');
		INSERT INTO user_roles SELECT user_id, r.api, r.key FROM identifiers, roles r WHERE value = 'owner' AND NOT r.builtin;
		UPDATE applications SET default_api = 'https://track.example' WHERE client_id = 'rp'`); err != nil {
		t.Fatal(err)
	}
	_, page := e.authorize("")
	resp, _ := e.submit(page, "owner", "password1")
	tok := e.exchange(clientID, callback, e.code(resp))
	at := e.claims(tok.AccessToken)
	if at["aud"] != "https://track.example" ||
		fmt.Sprint(at["roles"]) != "[editor viewer]" || fmt.Sprint(at["entitlements"]) != "[track:read track:write]" {
		t.Errorf("access token: %v", at)
	}
	if id := e.claims(tok.IDToken); id["roles"] != nil || id["entitlements"] != nil || id["groups"] != nil {
		t.Errorf("ID token: %v", id)
	}
}

// The first step asks only for an Identifier; a username goes on to a
// password step, with no code sent and no PoW asked for.
func TestUsernameGoesToPasswordStep(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.setTerms("v1")
	_, page := e.authorize("")
	if strings.Count(page, `name="identifier"`) != 1 || strings.Count(page, `name="agree"`) != 1 || strings.Contains(page, `name="password"`) {
		t.Fatalf("first step is not a single identifier form:\n%s", page)
	}
	resp, page := e.post(page, url.Values{"op": {"send"}, "identifier": {"owner"}, "agree": {"v1"}})
	// The terms were agreed to on the first step; the box is not shown again.
	if resp.StatusCode != 200 || strings.Count(page, `name="password"`) != 1 || strings.Contains(page, "<altcha-widget") ||
		!strings.Contains(page, `name="username" value="owner"`) || strings.Contains(page, `type="checkbox"`) ||
		!strings.Contains(page, `name="agree" value="v1"`) {
		t.Fatalf("want the password step, got %d:\n%s", resp.StatusCode, page)
	}
	if len(e.inbox.codes) != 0 {
		t.Errorf("a code was sent: %v", e.inbox.codes)
	}
	if _, back := e.link(page, "更换账号"); !strings.Contains(back, `name="identifier"`) || strings.Contains(back, `name="password"`) {
		t.Errorf("更换账号 does not go back to the first step:\n%s", back)
	}
	resp, _ = e.post(page, url.Values{"op": {"password"}, "username": {"owner"}, "password": {"password1"}, "agree": {"v1"}})
	if claims := e.idToken(e.code(resp)); !slices.Equal(claims["amr"].([]any), []any{"pwd"}) {
		t.Errorf("id token claims: %v", claims)
	}
}

// With password login off, the page offers no password, and a username is
// turned away the same whether it exists or not.
func TestPasswordLoginOffTurnsUsernamesAway(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET password_login = 'off'"); err != nil {
		t.Fatal(err)
	}
	_, page := e.authorize("")
	if strings.Contains(page, "使用密码登录") {
		t.Errorf("password link shown with password login off")
	}
	for _, name := range []string{"owner", "nobody"} {
		resp, body := e.post(page, url.Values{"op": {"send"}, "identifier": {name}})
		if resp.StatusCode != 200 || !strings.Contains(body, "该账号不能用验证码登录") || strings.Contains(body, `name="password"`) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
}

// link follows the page's link with the given text.
func (e *env) link(page, text string) (*http.Response, string) {
	e.t.Helper()
	m := regexp.MustCompile(`<a href="([^"]+)">` + text + `</a>`).FindStringSubmatch(page)
	if m == nil {
		e.t.Fatalf("no %s link in:\n%s", text, page)
	}
	return e.do("GET", html.UnescapeString(m[1]), nil)
}

// The password form takes the Identifier and the password together, with
// no PoW, and links back to codes.
func TestPasswordForm(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	e.setTerms("v1")
	_, page := e.authorize("")
	_, page = e.link(page, "使用密码登录")
	if strings.Count(page, `name="username"`) != 1 || strings.Count(page, `name="password"`) != 1 ||
		strings.Count(page, `name="agree"`) != 1 || strings.Contains(page, `name="identifier"`) || strings.Contains(page, "<altcha-widget") {
		t.Fatalf("password form:\n%s", page)
	}
	// Unticked, the form comes back as it was.
	_, body := e.post(page, url.Values{"op": {"password"}, "mode": {"password"}, "username": {"owner"}, "password": {"password1"}})
	if !strings.Contains(body, "请先阅读并同意") || !strings.Contains(body, `type="checkbox" name="agree"`) {
		t.Errorf("unticked: %s", body)
	}
	if _, back := e.link(page, "改用验证码登录"); !strings.Contains(back, `name="identifier"`) || strings.Contains(back, `name="password"`) {
		t.Errorf("back to codes:\n%s", back)
	}
	resp, _ := e.post(page, url.Values{"op": {"password"}, "mode": {"password"}, "username": {"owner"}, "password": {"password1"}, "agree": {"v1"}})
	e.code(resp)
}

// With no Channel, the password form is the page, with nothing to switch to.
func TestNoChannelShowsPasswordForm(t *testing.T) {
	e := start(t)
	if _, err := e.pool.Exec(context.Background(), "DELETE FROM channels"); err != nil {
		t.Fatal(err)
	}
	_, page := e.authorize("")
	if !strings.Contains(page, `name="password"`) || strings.Contains(page, `name="identifier"`) || strings.Contains(page, "改用验证码登录") {
		t.Errorf("page:\n%s", page)
	}
}

// A mistyped phone number or email is an error, not a username.
func TestMistypedIdentifierIsNotAUsername(t *testing.T) {
	e := start(t)
	_, page := e.authorize("")
	for _, typed := range []string{"foo@bar", "1381234"} {
		_, body := e.post(page, url.Values{"op": {"send"}, "identifier": {typed}})
		if !strings.Contains(html.UnescapeString(body), identity.ErrIdentifier.Error()) || strings.Contains(body, `name="password"`) {
			t.Errorf("%s: %s", typed, body)
		}
	}
}

// An M2M Application gets a token as itself: the grant is its only one, the
// token is for its default API, it lives 10 minutes, and there is no refresh
// token (ADR 0015).
func TestClientCredentials(t *testing.T) {
	e := start(t)
	const trackAPI = "https://track.example"
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO apis (identifier, name) VALUES ($1, 'Track')`, trackAPI); err != nil {
		t.Fatal(err)
	}
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "batch", Name: "对账任务", Type: "m2m", Secret: "m2m-secret", DefaultAPI: trackAPI,
	}); err != nil {
		t.Fatal(err)
	}

	// An M2M Application authenticates with client_secret_basic.
	token := func(client, secret string, form url.Values) (*http.Response, string) {
		u, err := url.Parse(e.issuer)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword(client, secret)
		u.Path = "/token"
		return e.do("POST", u.String(), form)
	}
	access := func(resp *http.Response, body string) map[string]any {
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil || tok.AccessToken == "" {
			t.Fatalf("want a token, got %d %s", resp.StatusCode, body)
		}
		return e.claims(tok.AccessToken)
	}

	var before int64 // setting up the Channels is audited
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log").Scan(&before); err != nil {
		t.Fatal(err)
	}
	resp, body := token("batch", "m2m-secret", url.Values{"grant_type": {"client_credentials"}})
	if resp.StatusCode != 200 {
		t.Fatalf("client_credentials: %d %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresIn != 600 || tok.RefreshToken != "" {
		t.Errorf("expires_in %d, refresh token %q", tok.ExpiresIn, tok.RefreshToken)
	}
	// 换令牌不写审计 (docs/spec/security-compliance.md): done every 10
	// minutes, it would drown the log.
	var audited int64
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log").Scan(&audited); err != nil || audited != before {
		t.Errorf("client_credentials wrote %d audit events, want none: %v", audited-before, err)
	}
	if at := e.claims(tok.AccessToken); at["aud"] != trackAPI || at["sub"] != "batch" || at["client_id"] != "batch" {
		t.Errorf("claims: %v", at)
	}
	// No Roles assigned yet, so the token carries none.
	if id := e.claims(tok.AccessToken); id["roles"] != nil || id["entitlements"] != nil {
		t.Errorf("an M2M token with no Roles carries none: %v", id)
	}

	// A scope in the request is ignored: the token is for the Application's
	// default API and grants nothing else. phone is a scope the server would
	// otherwise grant, so this would fail if the middleware let it through.
	at := access(token("batch", "m2m-secret", url.Values{"grant_type": {"client_credentials"}, "scope": {"phone"}}))
	if at["aud"] != trackAPI || at["scope"] != "" {
		t.Errorf("with a scope: %v", at)
	}

	// The secret goes in the Authorization header, not the body.
	resp, body = e.do("POST", "/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"batch"}, "client_secret": {"m2m-secret"},
	})
	if resp.StatusCode != 401 || !strings.Contains(body, "invalid_client") {
		t.Errorf("client_secret_post: %d %s", resp.StatusCode, body)
	}

	// It has no login, so no authorization code.
	if resp, _ := e.authorizeAs("batch", "https://batch.example/cb", ""); resp.StatusCode/100 == 3 {
		t.Errorf("the authorization endpoint signed an m2m Application in: %d", resp.StatusCode)
	}

	// A wrong secret, a secret rotated away, and a deleted Application are
	// all invalid_client.
	invalidClient := func(what string, resp *http.Response, body string) {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal([]byte(body), &e)
		if resp.StatusCode != 401 || e.Error != "invalid_client" {
			t.Errorf("%s: %d %s", what, resp.StatusCode, body)
		}
	}
	resp, body = token("batch", "wrong", url.Values{"grant_type": {"client_credentials"}})
	invalidClient("wrong secret", resp, body)
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE applications SET secret_hash = $1 WHERE client_id = 'batch'`, oidcstore.SecretHash("new-secret")); err != nil {
		t.Fatal(err)
	}
	resp, body = token("batch", "m2m-secret", url.Values{"grant_type": {"client_credentials"}})
	invalidClient("a rotated-away secret", resp, body)
	access(token("batch", "new-secret", url.Values{"grant_type": {"client_credentials"}}))
	if _, err := e.pool.Exec(context.Background(), `DELETE FROM applications WHERE client_id = 'batch'`); err != nil {
		t.Fatal(err)
	}
	resp, body = token("batch", "new-secret", url.Values{"grant_type": {"client_credentials"}})
	invalidClient("a deleted Application", resp, body)

	// Neither can a public or a confidential Application use the grant.
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "backend", Name: "订单后端", Type: "confidential", Secret: "backend-secret",
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ id, secret string }{{clientID, ""}, {"backend", "backend-secret"}} {
		u, _ := url.Parse(e.issuer)
		u.User = url.UserPassword(c.id, c.secret)
		u.Path = "/token"
		resp, body = e.do("POST", u.String(), url.Values{"grant_type": {"client_credentials"}})
		if resp.StatusCode != 401 || !strings.Contains(body, "unauthorized_client") {
			t.Errorf("%s: %d %s", c.id, resp.StatusCode, body)
		}
	}
}

// An M2M Application's token carries the Roles assigned to it on its default
// API, with their Permissions as entitlements, in the same shape as a User's
// token (ADR 0015).
func TestClientCredentialsTokenCarriesApplicationRoles(t *testing.T) {
	e := start(t)
	const trackAPI = "https://track.example"
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO apis (identifier, name) VALUES ('https://track.example', 'Track'), ('https://other.example', 'Other');
		INSERT INTO permissions (api, key, name) VALUES
			('https://track.example', 'track:read', 'r'), ('https://track.example', 'track:write', 'w'),
			('https://other.example', 'other:x', 'x');
		INSERT INTO roles (api, key, name) VALUES
			('https://track.example', 'viewer', 'V'), ('https://track.example', 'editor', 'E'), ('https://other.example', 'boss', 'B');
		INSERT INTO role_permissions VALUES
			('https://track.example', 'viewer', 'track:read'), ('https://track.example', 'editor', 'track:read'),
			('https://track.example', 'editor', 'track:write'), ('https://other.example', 'boss', 'other:x')`); err != nil {
		t.Fatal(err)
	}
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "batch", Name: "对账任务", Type: "m2m", Secret: "m2m-secret", DefaultAPI: trackAPI,
	}); err != nil {
		t.Fatal(err)
	}
	token := func() map[string]any {
		u, err := url.Parse(e.issuer)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("batch", "m2m-secret")
		u.Path = "/token"
		resp, body := e.do("POST", u.String(), url.Values{"grant_type": {"client_credentials"}})
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &tok) != nil || tok.AccessToken == "" {
			t.Fatalf("client_credentials: %d %s", resp.StatusCode, body)
		}
		return e.claims(tok.AccessToken)
	}

	// Two Roles on its API: both, and the union of their Permissions. A Role
	// on another API is out of reach.
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO application_roles (client_id, api, role) VALUES
			('batch', 'https://track.example', 'viewer'), ('batch', 'https://track.example', 'editor')`); err != nil {
		t.Fatal(err)
	}
	at := token()
	if at["aud"] != trackAPI || fmt.Sprint(at["roles"]) != "[editor viewer]" || fmt.Sprint(at["entitlements"]) != "[track:read track:write]" {
		t.Errorf("with Roles: %v", at)
	}

	// Revoking one drops its Permissions with it.
	if _, err := e.pool.Exec(context.Background(), `DELETE FROM application_roles WHERE role = 'editor'`); err != nil {
		t.Fatal(err)
	}
	at = token()
	if fmt.Sprint(at["roles"]) != "[viewer]" || fmt.Sprint(at["entitlements"]) != "[track:read]" {
		t.Errorf("after revoking a Role: %v", at)
	}
}
