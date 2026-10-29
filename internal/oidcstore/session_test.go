package oidcstore

import (
	"context"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/oidc/goidc"
)

// An App Session is its refresh token chain: revoking the token ends it.
func TestRevokingAnAppSessionsRefreshTokenEndsIt(t *testing.T) {
	pool, keyring := setup(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	if err := q.CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	s := New(pool, keyring)
	sess, err := s.CreateSession(ctx, nil, "polaris-console", "ALICE", time.Now(), []string{"sms"})
	if err != nil {
		t.Fatal(err)
	}
	g := &goidc.Grant{ID: "g", Subject: "ALICE", ClientID: "polaris-console", RefreshToken: "rt",
		Store: map[string]any{SessionKey: sess.ID}}
	if err := s.SaveGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	g, err = s.GrantByRefreshToken(ctx, "rt")
	if err != nil {
		t.Fatal(err)
	}
	g.RevokedAt = int(time.Now().Unix())
	if err := s.SaveGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	rows, err := q.UserSessions(ctx, "ALICE")
	if err != nil || len(rows) != 1 || rows[0].Active || !rows[0].EndedAt.Valid {
		t.Errorf("App Session after revocation: %+v %v", rows, err)
	}
}

// CreateSession takes the 闲置时长 and 寿命上限 of the Session's kind unless
// the Application sets them, and the device from ctx.
func TestCreateSession(t *testing.T) {
	pool, keyring := setup(t)
	s := New(pool, keyring)
	q := sqlc.New(pool)
	ctx := WithDevice(context.Background(), "203.0.113.7", "Firefox")
	if err := q.CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	if err := CreateApplication(ctx, pool, Application{ClientID: "short", Name: "short", RedirectURIs: []string{"https://rp/cb"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE applications SET session_idle_timeout = '1 hour', session_max_lifetime = '2 hours' WHERE client_id = 'short'"); err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	for _, c := range []struct {
		name     string
		idHash   []byte
		clientID string
		age      time.Duration // auth_time this long ago, so the 寿命上限 comes first
		idle     time.Duration
		lapses   time.Duration // from auth_time
	}{
		{"browser", []byte("cookie"), "polaris-console", 85 * day, 30 * day, 90 * day},
		{"App", nil, "polaris-console", 170 * day, 90 * day, 180 * day},
		{"Application's", []byte("cookie2"), "short", 90 * time.Minute, time.Hour, 2 * time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			authTime := time.Now().Add(-c.age).Truncate(time.Second)
			sess, err := s.CreateSession(ctx, c.idHash, c.clientID, "ALICE", authTime, []string{"pwd"})
			if err != nil {
				t.Fatal(err)
			}
			if got := time.Duration(sess.IdleSecs) * time.Second; got != c.idle {
				t.Errorf("idle = %v, want %v", got, c.idle)
			}
			rows, err := q.UserSessions(ctx, "ALICE")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if r.ID != sess.ID {
					continue
				}
				if r.App != (c.idHash == nil) {
					t.Errorf("app = %v", r.App)
				}
				if want := authTime.Add(c.lapses); !r.ExpiresAt.Time.Equal(want) {
					t.Errorf("expires_at = %v, want %v", r.ExpiresAt.Time, want)
				}
				if r.Ip.String != "203.0.113.7" || r.UserAgent.String != "Firefox" {
					t.Errorf("device = %v %v", r.Ip, r.UserAgent)
				}
				return
			}
			t.Fatal("Session not listed")
		})
	}
}

// Whether a Session still lives is one rule (session_lapses_at): the
// live_sessions view, the console's list, the logout tokens sent when it is
// ended or deleted, and the cleanup must all agree on it.
func TestSessionLivenessAgrees(t *testing.T) {
	pool, keyring := setup(t)
	s := New(pool, keyring)
	q := sqlc.New(pool)
	ctx := context.Background()
	if err := q.CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	if err := CreateApplication(ctx, pool, Application{ClientID: "rp", Name: "rp", Secret: "rp-secret",
		RedirectURIs: []string{"https://rp/cb"}, BackchannelLogoutURI: "https://rp/logout"}); err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	// start makes a browser Session for rp in the given state and returns
	// its id and cookie hash.
	start := func(state string) (string, []byte) {
		t.Helper()
		n++
		idHash := []byte{byte(n)}
		sess, err := s.CreateSession(ctx, idHash, "rp", "ALICE", time.Now(), []string{"pwd"})
		if err != nil {
			t.Fatal(err)
		}
		exec("INSERT INTO session_applications (session_id, client_id) VALUES ($1, 'rp')", sess.ID)
		switch state {
		case "idle":
			exec("UPDATE sessions SET last_seen_at = now() - interval '31 days' WHERE id = $1", sess.ID)
		case "capped":
			exec("UPDATE sessions SET auth_time = now() - interval '91 days' WHERE id = $1", sess.ID)
		case "ended":
			exec("UPDATE sessions SET ended_at = now() WHERE id = $1", sess.ID)
		}
		exec("DELETE FROM webhook_deliveries")
		return sess.ID, idHash
	}
	logouts := func(id string) bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM webhook_deliveries WHERE kind = 'logout' AND payload->>'sid' = $1", id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	exists := func(sql, id string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS ("+sql+")", id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	for _, c := range []struct {
		state        string
		live         bool
		expiresIn    time.Duration // from now, to the day
		deletedLater bool          // by the cleanup 31 days on
	}{
		{"live", true, 30 * day, false},
		{"idle", false, -day, true},
		{"capped", false, -day, true},
		{"ended", false, 30 * day, true},
	} {
		t.Run(c.state, func(t *testing.T) {
			id, _ := start(c.state)
			if got := exists("SELECT 1 FROM live_sessions WHERE id = $1", id); got != c.live {
				t.Errorf("in live_sessions = %v", got)
			}
			rows, err := q.UserSessions(ctx, "ALICE")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if r.ID == id && (r.Active != c.live || time.Until(r.ExpiresAt.Time).Round(day) != c.expiresIn) {
					t.Errorf("UserSessions: active %v, expires in %v", r.Active, time.Until(r.ExpiresAt.Time))
				}
			}

			id, idHash := start(c.state)
			if err := q.EndBrowserSession(ctx, idHash); err != nil {
				t.Fatal(err)
			}
			if got := logouts(id); got != c.live {
				t.Errorf("ending sent a logout token: %v", got)
			}

			id, _ = start(c.state)
			exec("DELETE FROM sessions WHERE id = $1", id)
			if got := logouts(id); got != c.live {
				t.Errorf("deleting sent a logout token: %v", got)
			}

			id, _ = start(c.state)
			exec(`UPDATE sessions SET auth_time = auth_time - interval '31 days', last_seen_at = last_seen_at - interval '31 days',
				ended_at = ended_at - interval '31 days' WHERE id = $1`, id)
			if err := q.DeleteOldSessions(ctx); err != nil {
				t.Fatal(err)
			}
			if got := !exists("SELECT 1 FROM sessions WHERE id = $1", id); got != c.deletedLater {
				t.Errorf("deleted by the cleanup 31 days on: %v", got)
			}
		})
	}
}
