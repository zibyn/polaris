package login_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// challengeResp is any authorization challenge endpoint answer.
type challengeResp struct {
	Status      int
	Code        string          `json:"authorization_code"`
	Error       string          `json:"error"`
	Describe    string          `json:"error_description"`
	AuthSession string          `json:"auth_session"`
	Next        string          `json:"next"`
	Methods     []string        `json:"methods"`
	Options     json.RawMessage `json:"options"`
}

// challenge posts form to the direct auth API, as App clientID, with the
// terms version and PKCE every first request carries.
func (e *env) challenge(form url.Values) challengeResp {
	e.t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "scope": {"openid"}, "terms_version": {"1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range form {
		q[k] = v
	}
	for k, v := range q {
		if v[0] == "" {
			delete(q, k)
		}
	}
	resp, body := e.do("POST", "/v1/auth/challenge", q)
	out := challengeResp{Status: resp.StatusCode}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		e.t.Fatalf("challenge: %d %s", resp.StatusCode, body)
	}
	return out
}

// appCodeLogin sends a code to phone and enters it; it returns the
// authorization code.
func (e *env) appCodeLogin(phone string) string {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), "UPDATE sends SET sent_at = sent_at - interval '1 minute'"); err != nil {
		e.t.Fatal(err)
	}
	sent := e.challenge(url.Values{"identifier": {phone}, "altcha": {e.solve()}})
	code := e.inbox.take(phone)
	if sent.Status != 403 || sent.Error != "insufficient_authorization" || sent.Next != "code" || sent.AuthSession == "" || code == "" {
		e.t.Fatalf("send: %+v", sent)
	}
	done := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "code": {code}})
	if done.Status != 200 || done.Code == "" {
		e.t.Fatalf("verify: %+v", done)
	}
	return done.Code
}

// The App's tokens are the ones the OIDC flow issues: same claims, same
// refresh.
func TestDirectCodeLoginGetsOIDCTokens(t *testing.T) {
	e := start(t)
	const phone = "+8613800138000"

	app := e.exchange(clientID, "", e.appCodeLogin(phone))

	_, page := e.authorize("")
	resp, _ := e.codeLogin(page, phone, phone)
	web := e.exchange(clientID, callback, e.code(resp))

	appID, webID := e.claims(app.IDToken), e.claims(web.IDToken)
	delete(webID, "nonce")
	if !slices.Equal(slices.Sorted(maps.Keys(appID)), slices.Sorted(maps.Keys(webID))) ||
		appID["sub"] != webID["sub"] || !slices.Equal(appID["amr"].([]any), []any{"sms"}) {
		t.Errorf("id tokens differ:\napp %v\nweb %v", appID, webID)
	}
	appAT, webAT := e.claims(app.AccessToken), e.claims(web.AccessToken)
	if !slices.Equal(slices.Sorted(maps.Keys(appAT)), slices.Sorted(maps.Keys(webAT))) || appAT["aud"] != webAT["aud"] {
		t.Errorf("access tokens differ:\napp %v\nweb %v", appAT, webAT)
	}

	for _, pair := range [][2]string{{app.AccessToken, web.AccessToken}, {app.IDToken, web.IDToken}} {
		if a, w := header(t, pair[0]), header(t, pair[1]); a["typ"] != w["typ"] || a["alg"] != w["alg"] {
			t.Errorf("JWT headers differ: app %v, web %v", a, w)
		}
	}

	next, errCode := e.refresh(app.RefreshToken)
	if errCode != "" || next.AccessToken == "" || next.RefreshToken == app.RefreshToken {
		t.Fatalf("refresh: %q %+v", errCode, next)
	}
	if at := e.claims(next.AccessToken); !slices.Equal(slices.Sorted(maps.Keys(at)), slices.Sorted(maps.Keys(appAT))) {
		t.Errorf("refreshed access token: %v", at)
	}
}

// header decodes a JWT's header.
func header(t *testing.T, jwt string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(jwt, ".", 2)[0])
	var h map[string]any
	if err == nil {
		err = json.Unmarshal(raw, &h)
	}
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDirectPasswordLogin(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")

	_, body := e.do("GET", "/.well-known/openid-configuration", nil)
	var meta struct {
		Endpoint string `json:"authorization_challenge_endpoint"`
	}
	if _ = json.Unmarshal([]byte(body), &meta); meta.Endpoint != e.issuer+"/v1/auth/challenge" {
		t.Errorf("discovery: %q", meta.Endpoint)
	}

	_, body = e.do("GET", "/v1/auth/openapi.json", nil)
	var doc struct{ Paths map[string]any }
	if _ = json.Unmarshal([]byte(body), &doc); doc.Paths["/v1/auth/challenge"] == nil {
		t.Errorf("openapi: %.200s", body)
	}

	for name, form := range map[string]url.Values{
		"no PoW":           {"username": {"owner"}, "password": {"password1"}},
		"no response_type": {"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "response_type": {""}},
		"no PKCE":          {"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "code_challenge": {""}},
		"wrong password":   {"username": {"owner"}, "password": {"nope"}, "altcha": {e.solve()}},
		"unknown scope":    {"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "scope": {"openid admin"}},
	} {
		if r := e.challenge(form); r.Status != 400 || r.Code != "" || r.Error == "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := e.challenge(url.Values{"client_id": {"nobody"}, "username": {"owner"}}); r.Status != 401 || r.Error != "invalid_client" {
		t.Errorf("unknown client: %+v", r)
	}
	if r := e.challenge(url.Values{"auth_session": {"made-up"}, "code": {"123456"}}); r.Status != 400 || r.Error != "invalid_session" {
		t.Errorf("unknown auth_session: %+v", r)
	}

	// No terms set up: any version will do, the empty one too.
	r := e.challenge(url.Values{"username": {"owner"}, "password": {"password1"}, "altcha": {e.solve()}, "terms_version": {""}})
	if r.Status != 200 {
		t.Fatalf("password: %+v", r)
	}
	tok := e.exchange(clientID, "", r.Code)
	if claims := e.claims(tok.IDToken); !slices.Equal(claims["amr"].([]any), []any{"pwd"}) {
		t.Errorf("id token: %v", claims)
	}
	// The code is single use, and needs the PKCE verifier.
	if resp, _ := e.do("POST", "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {r.Code}, "client_id": {clientID}, "code_verifier": {verifier},
	}); resp.StatusCode != 400 {
		t.Errorf("code reused: %d", resp.StatusCode)
	}
}

// An App signs in like the hosted page: a User without the phone number the
// instance requires binds one first.
func TestDirectLoginBindsRequiredPhone(t *testing.T) {
	e := start(t)
	if _, err := e.pool.Exec(context.Background(), "UPDATE settings SET require_phone = true"); err != nil {
		t.Fatal(err)
	}
	sent := e.challenge(url.Values{"identifier": {"a@example.com"}, "altcha": {e.solve()}})
	bind := e.challenge(url.Values{"auth_session": {sent.AuthSession}, "code": {e.inbox.take("a@example.com")}})
	if sent.Next != "code" {
		t.Errorf("send: %+v", sent)
	}
	if bind.Status != 403 || bind.Error != "insufficient_authorization" || bind.Next != "phone" || bind.AuthSession != sent.AuthSession {
		t.Fatalf("want a bind step: %+v", bind)
	}
	if r := e.challenge(url.Values{"auth_session": {bind.AuthSession}, "identifier": {"b@example.com"}, "altcha": {e.solve()}}); r.Status != 400 {
		t.Errorf("bind an email: %+v", r)
	}
	const phone = "+8613900139000"
	if r := e.challenge(url.Values{"auth_session": {bind.AuthSession}, "identifier": {phone}, "altcha": {e.solve()}}); r.Next != "code" {
		t.Errorf("send to the phone to bind: %+v", r)
	}
	done := e.challenge(url.Values{"auth_session": {bind.AuthSession}, "code": {e.inbox.take(phone)}})
	if done.Status != 200 {
		t.Fatalf("after binding: %+v", done)
	}
	claims := e.claims(e.exchange(clientID, "", done.Code).IDToken)
	if !slices.Equal(claims["amr"].([]any), []any{"otp"}) {
		t.Errorf("id token: %v", claims)
	}
	if sub, _ := e.ids.SignIn(context.Background(), "phone", phone); sub != claims["sub"] {
		t.Errorf("phone bound to %s, want %v", sub, claims["sub"])
	}
	// The auth_session is spent.
	if r := e.challenge(url.Values{"auth_session": {bind.AuthSession}, "code": {"123456"}}); r.Error != "invalid_session" {
		t.Errorf("spent auth_session: %+v", r)
	}
}
