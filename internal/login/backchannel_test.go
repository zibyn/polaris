package login_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidcstore"
	"github.com/zibyn/polaris/internal/webhook"
)

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// rps are Web Applications with back-channel logout endpoints, and the
// logout tokens those endpoints got.
type rps struct {
	e      *env
	srv    *httptest.Server
	mu     sync.Mutex
	got    map[string][]string // path (the client_id) -> logout tokens
	failed bool                // answer 500 while set
}

func (e *env) rps() *rps {
	r := &rps{e: e, got: map[string][]string{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.failed {
			w.WriteHeader(500)
			return
		}
		body, _ := io.ReadAll(req.Body)
		form, _ := url.ParseQuery(string(body))
		if req.Method != "POST" || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || req.Header.Get("webhook-signature") != "" {
			e.t.Errorf("logout request: %s %v", req.Method, req.Header)
		}
		r.got[req.URL.Path[1:]] = append(r.got[req.URL.Path[1:]], form.Get("logout_token"))
	}))
	e.t.Cleanup(r.srv.Close)
	return r
}

// app registers a Web (confidential) Application; logout says whether it
// has a back-channel logout URI.
func (r *rps) app(id string, logout, refreshTokens bool) {
	r.e.t.Helper()
	ctx := context.Background()
	app := oidcstore.Application{ClientID: id, Name: id, Secret: id + "-secret", RedirectURIs: []string{callback}}
	if logout {
		app.BackchannelLogoutURI = r.srv.URL + "/" + id
	}
	if err := oidcstore.CreateApplication(ctx, r.e.pool, app); err != nil {
		r.e.t.Fatal(err)
	}
	if _, err := r.e.pool.Exec(ctx, "UPDATE applications SET refresh_tokens = $2 WHERE client_id = $1", id, refreshTokens); err != nil {
		r.e.t.Fatal(err)
	}
}

// signIn signs the browser in to Application id (with the password form
// unless the browser already has a Session) and returns its ID token's claims.
func (r *rps) signIn(id string) map[string]any {
	r.e.t.Helper()
	resp, page := r.e.authorizeAs(id, callback, "")
	if resp.StatusCode == 200 {
		resp, _ = r.e.submit(page, "owner", "password1")
	}
	resp, body := r.e.do("POST", "/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {r.e.code(resp)}, "redirect_uri": {callback},
		"client_id": {id}, "client_secret": {id + "-secret"}, "code_verifier": {verifier},
	})
	var tok tokens
	if err := json.Unmarshal([]byte(body), &tok); err != nil || resp.StatusCode != 200 {
		r.e.t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	return r.e.claims(tok.IDToken)
}

func (r *rps) fail(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = on
}

// deliver runs the delivery queue once.
func (r *rps) deliver() {
	r.e.t.Helper()
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err := webhook.New(r.e.pool, keyring, r.e.issuer).Deliver(context.Background()); err != nil {
		r.e.t.Fatal(err)
	}
}

// received returns the Applications that got a logout token, checking that
// each is valid for the Session sid of User sub.
func (r *rps) received(sub, sid string) []string {
	r.e.t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var apps []string
	for app, toks := range r.got {
		if len(toks) != 1 {
			r.e.t.Errorf("%s got %d logout tokens", app, len(toks))
		}
		c := r.e.claims(toks[0])
		events, _ := c["events"].(map[string]any)
		if _, ok := events[backchannelEvent]; !ok || c["iss"] != r.e.issuer || c["aud"] != app ||
			c["sub"] != sub || c["sid"] != sid || c["jti"] == nil || c["iat"] == nil || c["exp"] == nil || c["nonce"] != nil {
			r.e.t.Errorf("%s logout token: %v", app, c)
		}
		apps = append(apps, app)
	}
	r.got = map[string][]string{}
	slices.Sort(apps)
	return apps
}

// signedInEverywhere signs the owner in to web (refresh tokens),
// codeonly (no refresh token), plain (no logout URI) in one browser
// Session; idle has a logout URI but never signs in.
func signedInEverywhere(t *testing.T) (*env, *rps, string, string) {
	e := start(t)
	e.bootstrap("owner", "password1")
	r := e.rps()
	r.app("web", true, true)
	r.app("codeonly", true, false)
	r.app("plain", false, true)
	r.app("idle", true, true)
	id := r.signIn("web")
	sid, _ := id["sid"].(string)
	if sid == "" {
		t.Fatalf("ID token has no sid: %v", id)
	}
	for _, app := range []string{"codeonly", "plain"} {
		if c := r.signIn(app); c["sid"] != sid {
			t.Fatalf("%s: sid %v, want %s", app, c["sid"], sid)
		}
	}
	return e, r, id["sub"].(string), sid
}

func TestEndingASessionSendsLogoutTokens(t *testing.T) {
	want := []string{"codeonly", "web"}
	ends := map[string]func(e *env, sub, sid string) error{
		"admin ends it": func(e *env, sub, sid string) error {
			_, err := sqlc.New(e.pool).EndUserSession(context.Background(), sqlc.EndUserSessionParams{ID: sid, UserID: sub, By: "ADMIN"})
			return err
		},
		"User disabled": func(e *env, sub, _ string) error {
			_, err := sqlc.New(e.pool).SetUserDisabled(context.Background(), sqlc.SetUserDisabledParams{UserID: sub, Disabled: true, By: "ADMIN"})
			return err
		},
		"User deleted": func(e *env, sub, _ string) error {
			_, err := sqlc.New(e.pool).DeleteUser(context.Background(), sqlc.DeleteUserParams{UserID: sub, By: "ADMIN"})
			return err
		},
		"User signs out": func(e *env, _, _ string) error {
			resp, page := e.do("GET", "/logout", nil)
			if resp.StatusCode != 200 {
				t.Fatalf("logout: %d", resp.StatusCode)
			}
			e.post(page, url.Values{"logout": {"1"}})
			return nil
		},
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			e, r, sub, sid := signedInEverywhere(t)
			if err := end(e, sub, sid); err != nil {
				t.Fatal(err)
			}
			r.deliver()
			if got := r.received(sub, sid); !slices.Equal(got, want) {
				t.Errorf("logout tokens went to %v, want %v", got, want)
			}
		})
	}
}

// A Session that lapses (idle, or past its lifespan cap) was not ended by
// anyone: nothing is sent, even when the cleanup or deleting its User
// deletes it.
func TestExpiredSessionSendsNothing(t *testing.T) {
	for name, c := range map[string]struct{ lapse, by string }{
		"idle, cleaned up":     {"last_seen_at = now() - interval '100 days'", "cleanup"},
		"capped, cleaned up":   {"auth_time = now() - interval '200 days'", "cleanup"},
		"capped, User deleted": {"auth_time = now() - interval '91 days'", "delete"},
	} {
		t.Run(name, func(t *testing.T) {
			e, r, sub, sid := signedInEverywhere(t)
			ctx := context.Background()
			if _, err := e.pool.Exec(ctx, "UPDATE sessions SET "+c.lapse+" WHERE id = $1", sid); err != nil {
				t.Fatal(err)
			}
			q := sqlc.New(e.pool)
			var err error
			if c.by == "cleanup" {
				err = q.DeleteOldSessions(ctx)
			} else {
				_, err = q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: sub, By: "ADMIN"})
			}
			if err != nil {
				t.Fatal(err)
			}
			var n int
			if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE id = $1", sid).Scan(&n); err != nil || n != 0 {
				t.Fatalf("Session not deleted: %d %v", n, err)
			}
			r.deliver()
			if got := r.received(sub, sid); len(got) != 0 {
				t.Errorf("logout tokens went to %v", got)
			}
		})
	}
}

// A receiver that fails gets the logout token again later.
func TestLogoutTokenIsRetried(t *testing.T) {
	e, r, sub, sid := signedInEverywhere(t)
	ctx := context.Background()
	if _, err := sqlc.New(e.pool).EndUserSession(ctx, sqlc.EndUserSessionParams{ID: sid, UserID: sub, By: "ADMIN"}); err != nil {
		t.Fatal(err)
	}
	r.fail(true)
	r.deliver()
	r.fail(false)
	r.deliver()
	if got := r.received(sub, sid); len(got) != 0 {
		t.Fatalf("retried before the backoff: %v", got)
	}
	// The backoff is up.
	if _, err := e.pool.Exec(ctx, "UPDATE webhook_deliveries SET next_at = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	r.deliver()
	if got := r.received(sub, sid); !slices.Equal(got, []string{"codeonly", "web"}) {
		t.Errorf("after retry: %v", got)
	}
}

func TestDiscoveryAdvertisesBackchannelLogout(t *testing.T) {
	e := start(t)
	_, body := e.do("GET", "/.well-known/openid-configuration", nil)
	var meta map[string]any
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["backchannel_logout_supported"] != true || meta["backchannel_logout_session_supported"] != true {
		t.Errorf("discovery: %v", meta)
	}
}
