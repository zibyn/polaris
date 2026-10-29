package management_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidcstore"
)

// session starts a Session for sub: a browser one, or an App one for clientID.
func (e *env) session(sub, clientID string, browser bool) string {
	e.t.Helper()
	p := sqlc.CreateSessionParams{
		ClientID: clientID, UserID: sub, Amr: []string{"sms"},
		AuthTime: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	if browser {
		p.IDHash = []byte(sub + clientID)
	}
	p.DefaultIdleSecs, p.DefaultMaxSecs = oidcstore.SessionDefaults(browser)
	s, err := sqlc.New(e.pool).CreateSession(context.Background(), p)
	if err != nil {
		e.t.Fatal(err)
	}
	return s.ID
}

type session struct {
	ID, Kind, Application string
	Amr                   []string
	ExpiresAt             time.Time
	EndedAt               *time.Time
	Active                bool
}

func TestAdminEndsAUsersSession(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil)
	e.user("RO", []string{"readonly"})
	browser := e.session("ALICE", "polaris-console", true)
	app := e.session("ALICE", "polaris-console", false)
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)

	var list struct{ Sessions []session }
	if code := e.get(ro, "/users/ALICE/sessions", &list); code != 200 || len(list.Sessions) != 2 {
		t.Fatalf("list: %d %+v", code, list)
	}
	byID := map[string]session{}
	for _, s := range list.Sessions {
		byID[s.ID] = s
	}
	day := 24 * time.Hour
	if s := byID[browser]; s.Kind != "browser" || !s.Active || s.EndedAt != nil || time.Until(s.ExpiresAt).Round(day) != 30*day {
		t.Errorf("browser Session: %+v", s)
	}
	if s := byID[app]; s.Kind != "app" || s.Application != "polaris-console" || !s.Active || time.Until(s.ExpiresAt).Round(day) != 90*day {
		t.Errorf("App Session: %+v", s)
	}

	if code := e.call("DELETE", ro, "/users/ALICE/sessions/"+app, nil, nil); code != 403 {
		t.Errorf("readonly ends a Session: %d", code)
	}
	if code := e.call("DELETE", owner, "/users/ALICE/sessions/"+app, nil, nil); code != 204 {
		t.Fatalf("end Session: %d", code)
	}
	// Ended Sessions stay listed; ending one twice, or another User's, is a 404.
	e.get(owner, "/users/ALICE/sessions", &list)
	for _, s := range list.Sessions {
		if s.ID == app && (s.Active || s.EndedAt == nil) || s.ID == browser && !s.Active {
			t.Errorf("after ending %s: %+v", app, s)
		}
	}
	if code := e.call("DELETE", owner, "/users/ALICE/sessions/"+app, nil, nil); code != 404 {
		t.Errorf("end twice: %d", code)
	}
	if code := e.call("DELETE", owner, "/users/RO/sessions/"+browser, nil, nil); code != 404 {
		t.Errorf("end another User's Session: %d", code)
	}
	if code := e.get(owner, "/users/NOBODY/sessions", &list); code != 404 {
		t.Errorf("unknown User: %d", code)
	}
}

// An Application's sessionMaxLifetime caps the Sessions it starts, counted
// from auth_time; 0 means the default (App 180 days, browser 90 days). It
// cannot be shorter than the idle timeout in effect.
func TestApplicationSetsTheSessionLifespanCap(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil)
	owner := e.token(e.owner, nil)
	day := 24 * time.Hour
	settings := map[string]any{
		"name": "App", "redirectUris": []string{"com.example.app:/cb"}, "postLogoutRedirectUris": []string{},
		"refreshTokens": true, "appleAppIds": []string{}, "androidApps": []any{},
		"sessionIdleTimeout": 7 * 86400, "sessionMaxLifetime": 10 * 86400,
	}
	var created struct {
		Application struct {
			ClientID           string
			SessionMaxLifetime int
		}
	}
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "public", "settings": settings}, &created); code != 200 ||
		created.Application.SessionMaxLifetime != 10*86400 {
		t.Fatalf("create: %d %+v", code, created)
	}
	id := created.Application.ClientID
	expiry := func(sid string) time.Duration {
		var list struct{ Sessions []session }
		e.get(owner, "/users/ALICE/sessions", &list)
		for _, s := range list.Sessions {
			if s.ID == sid {
				return time.Until(s.ExpiresAt).Round(day)
			}
		}
		t.Fatalf("no Session %s", sid)
		return 0
	}
	// The idle timeout ends it first, then the cap once auth_time is old.
	sid := e.session("ALICE", id, false)
	if got := expiry(sid); got != 7*day {
		t.Errorf("new Session ends in %v, want 7 days", got)
	}
	if _, err := e.pool.Exec(t.Context(), "UPDATE sessions SET auth_time = now() - interval '5 days' WHERE id = $1", sid); err != nil {
		t.Fatal(err)
	}
	if got := expiry(sid); got != 5*day {
		t.Errorf("Session signed in 5 days ago ends in %v, want 5 days", got)
	}

	// 0: the default.
	settings["sessionIdleTimeout"], settings["sessionMaxLifetime"] = 0, 0
	if code := e.call("PUT", owner, "/applications/"+id, settings, nil); code != 204 {
		t.Fatalf("update: %d", code)
	}
	app, browser := e.session("ALICE", id, false), e.session("ALICE", id, true)
	if _, err := e.pool.Exec(t.Context(), "UPDATE sessions SET auth_time = now() - CASE WHEN id = $1 THEN interval '100 days' ELSE interval '85 days' END WHERE id IN ($1, $2)", app, browser); err != nil {
		t.Fatal(err)
	}
	if got := expiry(app); got != 80*day {
		t.Errorf("default App Session ends in %v, want 80 days", got)
	}
	if got := expiry(browser); got != 5*day {
		t.Errorf("default browser Session ends in %v, want 5 days", got)
	}

	// Shorter than the idle timeout in effect: the set one, or the App default.
	for name, st := range map[string][2]int{"set idle": {7 * 86400, 6 * 86400}, "default idle": {0, 60 * 86400}} {
		settings["sessionIdleTimeout"], settings["sessionMaxLifetime"] = st[0], st[1]
		if code := e.call("PUT", owner, "/applications/"+id, settings, nil); code != 422 {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}
	// A Web Application signs Users in through the browser: its default idle
	// timeout is the browser one.
	settings["redirectUris"], settings["sessionIdleTimeout"], settings["sessionMaxLifetime"] = []string{"https://web.example/cb"}, 0, 60*86400
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "confidential", "settings": settings}, nil); code != 200 {
		t.Errorf("Web Application with a 60-day cap: %d", code)
	}
}
