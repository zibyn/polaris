package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/oidcstore"
)

// fromOrigin sends a request as a browser page on origin would.
func (e *env) fromOrigin(method, path, origin string, form url.Values) *http.Response {
	e.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, e.issuer+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type, dpop")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

const spaOrigin = "https://rp.example" // the origin of callback

func TestTokenEndpointsAllowRedirectOrigins(t *testing.T) {
	e := start(t)

	// A bad code still comes back readable: the SPA needs the OAuth error.
	resp := e.fromOrigin(http.MethodPost, "/token", spaOrigin, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {"nope"},
		"redirect_uri": {callback}, "code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token status = %d, want 400", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != spaOrigin {
		t.Errorf("token Allow-Origin = %q, want %q", got, spaOrigin)
	}
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("token Vary = %q, want Origin", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("token Allow-Credentials = %q, want none", got)
	}

	for path, method := range map[string]string{"/token": "POST", "/revoke": "POST", "/userinfo": "GET"} {
		resp := e.fromOrigin(http.MethodOptions, path, spaOrigin, nil)
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight %s status = %d, want 204", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != spaOrigin {
			t.Errorf("preflight %s Allow-Origin = %q", path, got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(got, method) {
			t.Errorf("preflight %s Allow-Methods = %q, want %s", path, got, method)
		}
		headers := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
		for _, h := range []string{"authorization", "content-type", "dpop"} {
			if !strings.Contains(headers, h) {
				t.Errorf("preflight %s Allow-Headers = %q, want %s", path, headers, h)
			}
		}
	}

	// userinfo without a token: 401, still readable.
	if resp := e.fromOrigin(http.MethodGet, "/userinfo", spaOrigin, nil); resp.Header.Get("Access-Control-Allow-Origin") != spaOrigin {
		t.Errorf("userinfo %d Allow-Origin = %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestTokenEndpointsRefuseOtherOrigins(t *testing.T) {
	e := start(t)
	for _, origin := range []string{"https://evil.example", "https://rp.example.evil.example", "null"} {
		resp := e.fromOrigin(http.MethodPost, "/token", origin, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}})
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s: token Allow-Origin = %q, want none", origin, got)
		}
		for _, path := range []string{"/token", "/revoke", "/userinfo"} {
			resp := e.fromOrigin(http.MethodOptions, path, origin, nil)
			if resp.StatusCode/100 == 2 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s: preflight %s = %d %q, want refused", origin, path, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
			}
		}
	}
}

func TestNewRedirectOriginAppliesAtOnce(t *testing.T) {
	e := start(t)
	const origin = "http://localhost:5173"
	if resp := e.fromOrigin(http.MethodOptions, "/token", origin, nil); resp.StatusCode == http.StatusNoContent {
		t.Fatal("origin allowed before any Application names it")
	}
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "spa", Name: "SPA", RedirectURIs: []string{origin + "/callback", "com.example.app:/cb"},
	}); err != nil {
		t.Fatal(err)
	}
	if resp := e.fromOrigin(http.MethodOptions, "/token", origin, nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight after adding redirect URI = %d, want 204", resp.StatusCode)
	}
	if resp := e.fromOrigin(http.MethodOptions, "/token", "com.example.app:", nil); resp.StatusCode == http.StatusNoContent {
		t.Error("custom scheme redirect URI allowed as an origin")
	}
}

func TestDiscoveryAndJWKSAllowAnyOrigin(t *testing.T) {
	e := start(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks"} {
		resp := e.fromOrigin(http.MethodGet, path, "https://anyone.example", nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("GET %s = %d %q, want 200 *", path, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
		resp = e.fromOrigin(http.MethodOptions, path, "https://anyone.example", nil)
		if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("preflight %s = %d %q, want 204 *", path, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
	}
}

func TestBrowserEndpointsGetNoCORS(t *testing.T) {
	e := start(t)
	for _, path := range []string{"/authorize?client_id=" + clientID, "/logout", "/introspect"} {
		for _, method := range []string{http.MethodGet, http.MethodOptions} {
			resp := e.fromOrigin(method, path, spaOrigin, nil)
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s %s Allow-Origin = %q, want none", method, path, got)
			}
		}
	}
}
