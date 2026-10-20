package management_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
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
