package authutil

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/oidc/goidc"
	"github.com/zibyn/polaris/internal/oidc/internal/timeutil"
	"github.com/zibyn/polaris/internal/oidcstore"
)

// TestEndingASessionQueuesTheLogoutToken checks that the harness signs a User
// in to a real Polaris Session (so the ID token names it as sid) and that
// ending it queues the Application's logout token (ADR 0022).
func TestEndingASessionQueuesTheLogoutToken(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, err := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	store := oidcstore.New(pool, keyring)
	UseSessions(store, pool)
	const (
		clientID = "app"
		sub      = "user@example.com"
	)
	if err := oidcstore.CreateApplication(ctx, pool, oidcstore.Application{
		ClientID: clientID, Name: clientID, Secret: "secret",
		RedirectURIs:         []string{"https://rp.example/callback"},
		BackchannelLogoutURI: "https://rp.example/backchannel_logout",
	}); err != nil {
		t.Fatal(err)
	}

	as := &goidc.AuthnSession{ClientID: clientID, Subject: sub,
		Store: map[string]any{paramAuthTime: timeutil.TimestampNow()}}
	w := httptest.NewRecorder()
	if status, err := (authenticator{}).createUserSession(w, httptest.NewRequest(http.MethodPost, "/authorize", nil), as); err != nil ||
		status != goidc.StatusSuccess {
		t.Fatalf("createUserSession: %v %v", status, err)
	}
	sid, _ := as.Store[oidcstore.SessionKey].(string)
	if sid == "" {
		t.Fatal("the Session id was not put in the authn store")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieUserSessionID {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no Session cookie")
	}

	// Another browser, same User: the User row it needs already exists.
	again := &goidc.AuthnSession{ClientID: clientID, Subject: sub,
		Store: map[string]any{paramAuthTime: timeutil.TimestampNow()}}
	if status, err := (authenticator{}).createUserSession(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/authorize", nil), again); err != nil ||
		status != goidc.StatusSuccess {
		t.Fatalf("second Session: %v %v", status, err)
	}

	// The token endpoint records the Session's Application; the ID token
	// names the Session by sid.
	if err := store.SaveGrant(ctx, &goidc.Grant{
		ID: "grant", ClientID: clientID, Subject: sub,
		Store: map[string]any{oidcstore.SessionKey: sid},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (authenticator{}).finishFlow(as); err != nil {
		t.Fatal(err)
	}
	if claims, _ := as.Store[paramIDTokenClaims].(map[string]any); claims["sid"] != sid {
		t.Fatalf("ID token sid = %v, want %s", claims["sid"], sid)
	}

	// Confirming the logout ends the Session.
	r := httptest.NewRequest(http.MethodPost, "/logout/x", nil)
	r.AddCookie(cookie)
	r.PostForm = url.Values{"logout": {"true"}}
	if status, err := LogoutPolicy().Logout(httptest.NewRecorder(), r, &goidc.LogoutSession{}); err != nil ||
		status != goidc.StatusSuccess {
		t.Fatalf("logout: %v %v", status, err)
	}

	var kind string
	var payload []byte
	if err := pool.QueryRow(ctx, "SELECT kind, payload FROM webhook_deliveries WHERE client_id = $1", clientID).
		Scan(&kind, &payload); err != nil {
		t.Fatal(err)
	}
	var got struct{ Sub, Sid string }
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if kind != "logout" || got.Sub != sub || got.Sid != sid {
		t.Fatalf("queued %s %s, want logout for %s in %s", kind, payload, sub, sid)
	}
}
