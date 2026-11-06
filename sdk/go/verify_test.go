package polaris_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	polaris "github.com/zibyn/polaris/sdk/go"
)

func newVerifier(t *testing.T, op *fakeOP) *polaris.Verifier {
	t.Helper()
	v, err := polaris.NewVerifier(context.Background(), op.URL, api)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// call sends token (if any) to a handler guarded by Require(entitlements...).
func call(v *polaris.Verifier, token string, entitlements ...string) (int, *polaris.Claims) {
	var got *polaris.Claims
	h := v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = polaris.FromContext(r.Context())
	}), entitlements...)
	req := httptest.NewRequest("GET", "/orders", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, got
}

func TestValidAccessTokenPassesWithItsClaims(t *testing.T) {
	op := startFakeOP(t)
	v := newVerifier(t, op)
	code, c := call(v, op.accessToken(t, map[string]any{"entitlements": []string{"orders:read", "orders:write"}}), "orders:read", "orders:write")
	if code != 200 || c == nil {
		t.Fatalf("code %d, claims %v", code, c)
	}
	if c.Sub != "user-1" || c.ClientID != clientID || len(c.Entitlements) != 2 {
		t.Fatalf("claims %+v", c)
	}
}

func TestM2MTokenWithoutEntitlementsPasses(t *testing.T) {
	op := startFakeOP(t)
	code, c := call(newVerifier(t, op), op.accessToken(t, map[string]any{"sub": "m2m-app", "client_id": "m2m-app", "entitlements": nil}))
	if code != 200 || c.Sub != "m2m-app" || len(c.Entitlements) != 0 {
		t.Fatalf("code %d, claims %+v", code, c)
	}
}

func TestInvalidOrMissingAccessTokenIs401(t *testing.T) {
	op := startFakeOP(t)
	v := newVerifier(t, op)
	stranger := newKey(t, "k1") // same kid, key not in the JWKS
	now := time.Now().Unix()
	for name, tok := range map[string]string{
		"missing":       "",
		"garbage":       "not-a-jwt",
		"wrong aud":     op.accessToken(t, map[string]any{"aud": "https://other.example.com"}),
		"wrong iss":     op.accessToken(t, map[string]any{"iss": "https://evil.example.com"}),
		"wrong typ":     op.accessToken(t, map[string]any{"typ": "JWT"}),
		"logout token":  op.logoutToken(t, map[string]any{"aud": api}),
		"expired":       op.accessToken(t, map[string]any{"exp": now - 60}),
		"no client_id":  op.accessToken(t, map[string]any{"client_id": nil}),
		"bad signature": op.sign(t, "at+jwt", map[string]any{"iss": op.URL, "aud": api, "sub": "u", "client_id": "c", "exp": now + 600}, &stranger),
	} {
		if code, _ := call(v, tok, "orders:read"); code != 401 {
			t.Errorf("%s: code %d, want 401", name, code)
		}
	}
}

func TestMissingEntitlementIs403(t *testing.T) {
	op := startFakeOP(t)
	if code, _ := call(newVerifier(t, op), op.accessToken(t, nil), "orders:read", "orders:write"); code != 403 {
		t.Fatalf("code %d, want 403", code)
	}
}

func TestNewKeyIsFetchedAfterRotation(t *testing.T) {
	op := startFakeOP(t)
	v := newVerifier(t, op)
	if code, _ := call(v, op.accessToken(t, nil)); code != 200 { // caches k1
		t.Fatalf("before rotation: code %d", code)
	}
	op.rotate(t)
	if code, _ := call(v, op.accessToken(t, nil)); code != 200 {
		t.Fatalf("after rotation: code %d", code)
	}
}

func TestLogoutToken(t *testing.T) {
	op := startFakeOP(t)
	v := newVerifier(t, op)
	lt, err := v.VerifyLogoutToken(context.Background(), clientID, op.logoutToken(t, nil))
	if err != nil || lt.Sub != "user-1" || lt.Sid != "sess-1" {
		t.Fatalf("valid: %+v, %v", lt, err)
	}
	for name, set := range map[string]map[string]any{
		"wrong aud":     {"aud": "other-app"},
		"wrong typ":     {"typ": "JWT"},
		"expired":       {"exp": time.Now().Unix() - 60},
		"no events":     {"events": nil},
		"other event":   {"events": map[string]any{"https://example.com/other": map[string]any{}}},
		"event not obj": {"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": "x"}},
		"no sid":        {"sid": nil},
		"no sub":        {"sub": nil},
		"with nonce":    {"nonce": "n"},
		"no jti":        {"jti": nil},
	} {
		if _, err := v.VerifyLogoutToken(context.Background(), clientID, op.logoutToken(t, set)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := v.VerifyLogoutToken(context.Background(), clientID, op.accessToken(t, map[string]any{"aud": clientID})); err == nil {
		t.Error("access token accepted as logout token")
	}
}
