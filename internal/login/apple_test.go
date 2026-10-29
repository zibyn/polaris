package login_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/apple/appletest"
)

// addApple adds a fake Apple as the Provider "apple".
func (e *env) addApple() *appletest.Fake {
	e.t.Helper()
	f := appletest.Start(e.t)
	if err := e.providers().Create(context.Background(), "apple", "apple", "Apple", f.Config(), ""); err != nil {
		e.t.Fatal(err)
	}
	return f
}

// signInWithApple presses the Apple button on page, approves at the fake
// Apple, and comes back by Apple's form_post: a cross-site POST, which
// carries no Lax cookie. It returns the response that leaves Polaris
// for the Application (or the page it stops at) and the code Apple gave.
func (e *env) signInWithApple(f *appletest.Fake, page string) (*http.Response, string, string) {
	e.t.Helper()
	m := providerFormRE.FindStringSubmatch(page)
	if m == nil || !strings.Contains(m[2], `value="apple"`) {
		e.t.Fatalf("no Apple button in:\n%s", page)
	}
	resp, _ := e.do("POST", html.UnescapeString(m[1]), url.Values{"op": {"provider"}, "provider": {"apple"}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("button: %d", resp.StatusCode)
	}
	form := f.Approve(resp.Header.Get("Location"))
	browser := e.client
	e.client = &http.Client{Transport: browser.Transport, CheckRedirect: browser.CheckRedirect}
	resp, body := e.do("POST", provider.CallbackURL(e.issuer, "apple"), form)
	e.client = browser
	for resp.StatusCode/100 == 3 && !strings.HasPrefix(resp.Header.Get("Location"), callback) {
		resp, body = e.do("GET", resp.Header.Get("Location"), nil)
	}
	return resp, body, form.Get("code")
}

func (e *env) appleTokens() [][]byte {
	e.t.Helper()
	rows, err := e.pool.Query(context.Background(), "SELECT token FROM external_identities WHERE provider = 'apple'")
	if err != nil {
		e.t.Fatal(err)
	}
	var out [][]byte
	for rows.Next() {
		var tok []byte
		if err := rows.Scan(&tok); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, tok)
	}
	return out
}

func TestSignInWithAppleOnTheWeb(t *testing.T) {
	e := start(t)
	f := e.addApple()

	_, page := e.authorize("")
	if !strings.Contains(page, `class="apple"`) || !strings.Contains(page, "通过 Apple 登录") {
		t.Fatalf("no HIG Apple button:\n%s", page)
	}
	resp, body, code := e.signInWithApple(f, page)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("after Apple: %d %s", resp.StatusCode, body)
	}
	claims := e.idToken(e.code(resp))
	sub, _ := claims["sub"].(string)
	if sub == "" || sub == f.Sub || !slices.Equal(claims["amr"].([]any), []any{"fed"}) || claims["email"] != nil {
		t.Errorf("id_token: %v", claims)
	}

	if len(f.ClientSecrets) != 1 {
		t.Fatalf("client secrets: %v", f.ClientSecrets)
	}
	cs := f.ClientSecrets[0]
	life := cs["exp"].(float64) - cs["iat"].(float64)
	if cs["iss"] != appletest.TeamID || cs["sub"] != appletest.ServicesID || cs["aud"] != "https://appleid.apple.com" || life <= 0 || life > 600 {
		t.Errorf("client secret claims: %v", cs)
	}

	tokens := e.appleTokens()
	if len(tokens) != 1 || len(tokens[0]) == 0 || strings.Contains(string(tokens[0]), "rt-"+code) {
		t.Errorf("stored refresh token is not sealed: %q", tokens)
	}

	// Again, from another browser: the same User.
	e.newBrowser()
	_, page = e.authorize("")
	resp, _, _ = e.signInWithApple(f, page)
	if again := e.idToken(e.code(resp))["sub"]; again != sub {
		t.Errorf("second login: %v, want %s", again, sub)
	}
}

func TestAppleTokenFailureFailsTheLogin(t *testing.T) {
	e := start(t)
	f := e.addApple()
	f.FailToken = true

	_, page := e.authorize("")
	if resp, body, _ := e.signInWithApple(f, page); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback: %d %s", resp.StatusCode, body)
	}
	if n := len(e.appleTokens()); n != 0 {
		t.Errorf("%d External Identities after a failed exchange", n)
	}
}

func TestAppleIDTokenWithoutExpFailsTheLogin(t *testing.T) {
	e := start(t)
	f := e.addApple()
	f.NoExp = true

	_, page := e.authorize("")
	if resp, body, _ := e.signInWithApple(f, page); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback: %d %s", resp.StatusCode, body)
	}
}

func TestUnbindingAppleRevokesItsToken(t *testing.T) {
	e := start(t)
	f := e.addApple()
	ctx := context.Background()
	_, page := e.authorize("")
	resp, _, code := e.signInWithApple(f, page)
	sub := e.idToken(e.code(resp))["sub"].(string)

	if err := e.providers().Unbind(ctx, sub, "apple", sub); err == nil || len(f.Revoked) != 0 {
		t.Fatalf("unbound the only way to sign in: %v, revoked %v", err, f.Revoked)
	}
	if err := sqlc.New(e.pool).AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: "phone", Value: "+8613900139000"}); err != nil {
		t.Fatal(err)
	}
	if err := e.providers().Unbind(ctx, sub, "apple", sub); err != nil {
		t.Fatal(err)
	}
	if len(f.Revoked) != 1 || f.Revoked[0].Get("token") != "rt-"+code ||
		f.Revoked[0].Get("client_id") != appletest.ServicesID || f.Revoked[0].Get("token_type_hint") != "refresh_token" {
		t.Errorf("revoked: %v", f.Revoked)
	}
	if n := len(e.appleTokens()); n != 0 {
		t.Errorf("%d External Identities left", n)
	}
}

func TestAppleRevokeFailureIsAuditedNotBlocking(t *testing.T) {
	e := start(t)
	f := e.addApple()
	ctx := context.Background()
	_, page := e.authorize("")
	resp, _, _ := e.signInWithApple(f, page)
	sub := e.idToken(e.code(resp))["sub"].(string)
	if err := sqlc.New(e.pool).AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: "phone", Value: "+8613900139000"}); err != nil {
		t.Fatal(err)
	}

	f.FailRevoke = true
	if err := e.providers().Unbind(ctx, sub, "apple", sub); err != nil {
		t.Fatal(err)
	}
	if len(f.Revoked) != 1 || len(e.appleTokens()) != 0 || e.audits("provider.unlink_failed") != 1 {
		t.Errorf("revoked %v, identities %d, audited %d", f.Revoked, len(e.appleTokens()), e.audits("provider.unlink_failed"))
	}
}

// appleChallenge is the iOS App handing the code Sign in with Apple gave it
// to the direct auth API.
func (e *env) appleChallenge(code string) challengeResp {
	e.t.Helper()
	return e.challenge(url.Values{"provider": {"apple"}, "authorization_code": {code}})
}

func TestSignInWithAppleInTheApp(t *testing.T) {
	e := start(t)
	f := e.addApple()

	code := f.NativeCode()
	resp := e.appleChallenge(code)
	if resp.Status != 200 || resp.Code == "" {
		t.Fatalf("challenge: %+v", resp)
	}
	claims := e.claims(e.exchange(clientID, "", resp.Code).IDToken)
	sub, _ := claims["sub"].(string)
	if sub == "" || sub == f.Sub || !slices.Equal(claims["amr"].([]any), []any{"fed"}) {
		t.Errorf("id_token: %v", claims)
	}
	if len(f.ClientSecrets) != 1 || f.ClientSecrets[0]["sub"] != appletest.BundleID {
		t.Errorf("client secrets: %v", f.ClientSecrets)
	}
	if tokens := e.appleTokens(); len(tokens) != 1 || strings.Contains(string(tokens[0]), "rt-"+code) {
		t.Errorf("stored refresh token: %q", tokens)
	}

	// Again: the same User.
	again := e.appleChallenge(f.NativeCode())
	if got := e.claims(e.exchange(clientID, "", again.Code).IDToken)["sub"]; got != sub {
		t.Errorf("second login: %v, want %s", got, sub)
	}

	// Unbinding revokes the latest token, as the Bundle ID it was issued to.
	ctx := context.Background()
	if err := sqlc.New(e.pool).AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: "phone", Value: "+8613900139000"}); err != nil {
		t.Fatal(err)
	}
	if err := e.providers().Unbind(ctx, sub, "apple", sub); err != nil {
		t.Fatal(err)
	}
	if len(f.Revoked) != 1 || f.Revoked[0].Get("client_id") != appletest.BundleID {
		t.Errorf("revoked: %v", f.Revoked)
	}
}

func TestAppleInTheAppGoesOnToTwoFactorAndPhone(t *testing.T) {
	e := start(t)
	f := e.addApple()
	first := e.appleChallenge(f.NativeCode())
	sub := e.claims(e.exchange(clientID, "", first.Code).IDToken)["sub"].(string)
	secret, _ := e.twoFactor(sub)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}

	resp := e.appleChallenge(f.NativeCode())
	if resp.Status != 403 || resp.Next != "totp" {
		t.Fatalf("want totp, got %+v", resp)
	}
	resp = e.challenge(url.Values{"auth_session": {resp.AuthSession}, "totp": {totpAt(secret, 0)}})
	if resp.Status != 403 || resp.Next != "phone" {
		t.Fatalf("want phone, got %+v", resp)
	}
	session := resp.AuthSession
	resp = e.challenge(url.Values{"auth_session": {session}, "identifier": {"+8613900139000"}, "altcha": {e.solve()}})
	if resp.Status != 403 || resp.Next != "code" {
		t.Fatalf("want code, got %+v", resp)
	}
	resp = e.challenge(url.Values{"auth_session": {session}, "code": {e.inbox.take("+8613900139000")}})
	claims := e.claims(e.exchange(clientID, "", resp.Code).IDToken)
	if claims["sub"] != sub || !slices.Equal(claims["amr"].([]any), []any{"fed", "otp", "mfa"}) {
		t.Errorf("after the steps: %v", claims)
	}
}

func TestAppleInTheAppRefusals(t *testing.T) {
	e := start(t)
	f := e.addApple()
	e.addGoogle()

	// A Provider an App cannot sign in with, or none at all.
	for _, id := range []string{"google", "nope"} {
		resp := e.challenge(url.Values{"provider": {id}, "authorization_code": {"x"}})
		if resp.Status != 400 || resp.Error != "invalid_request" {
			t.Errorf("%s: %+v", id, resp)
		}
	}

	// Apple turns the code down: a spent one, or an unknown one.
	if resp := e.appleChallenge("made-up"); resp.Status != 400 || resp.Error != "invalid_grant" {
		t.Errorf("unknown code: %+v", resp)
	}
	code := f.NativeCode()
	f.FailToken = true
	if resp := e.appleChallenge(code); resp.Status != 400 || resp.Error != "invalid_grant" {
		t.Errorf("failed exchange: %+v", resp)
	}
	if n := len(e.appleTokens()); n != 0 {
		t.Errorf("%d External Identities after failed exchanges", n)
	}

	// Disabled: refused before Apple is asked.
	f.FailToken = false
	if err := e.providers().SetEnabled(context.Background(), "apple", false, ""); err != nil {
		t.Fatal(err)
	}
	asked := len(f.ClientSecrets)
	if resp := e.appleChallenge(f.NativeCode()); resp.Status != 400 || resp.Error != "invalid_request" || len(f.ClientSecrets) != asked {
		t.Errorf("disabled: %+v", resp)
	}
}
