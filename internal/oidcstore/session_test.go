package oidcstore

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/dbtest"
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
	sess, err := s.CreateSession(ctx, nil, "polaris-console", "ALICE", time.Now(), []string{"sms"}, "sms")
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
			sess, err := s.CreateSession(ctx, c.idHash, c.clientID, "ALICE", authTime, []string{"pwd"}, "password")
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

// Whether a Session still lives is one rule (sessions.lapses_at, unended):
// the queries that check it, the console's list, the logout tokens sent when
// it is ended, and the cleanup must all agree on it.
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
		sess, err := s.CreateSession(ctx, idHash, "rp", "ALICE", time.Now(), []string{"pwd"}, "password")
		if err != nil {
			t.Fatal(err)
		}
		exec("INSERT INTO session_applications (session_id, client_id) VALUES ($1, 'rp')", sess.ID)
		switch state {
		case "idle":
			exec("UPDATE sessions SET last_seen_at = now() - interval '31 days' WHERE id = $1", sess.ID)
			exec(dbtest.Relapse)
		case "capped":
			exec("UPDATE sessions SET auth_time = now() - interval '91 days' WHERE id = $1", sess.ID)
			exec(dbtest.Relapse)
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
			if got := exists("SELECT 1 FROM sessions WHERE id = $1 AND ended_at IS NULL AND lapses_at > now()", id); got != c.live {
				t.Errorf("live = %v", got)
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
			exec(`UPDATE sessions SET auth_time = auth_time - interval '31 days', last_seen_at = last_seen_at - interval '31 days',
				ended_at = ended_at - interval '31 days' WHERE id = $1`, id)
			exec(dbtest.Relapse)
			if err := q.DeleteOldSessions(ctx, 30); err != nil {
				t.Fatal(err)
			}
			if got := !exists("SELECT 1 FROM sessions WHERE id = $1", id); got != c.deletedLater {
				t.Errorf("deleted by the cleanup 31 days on: %v", got)
			}
		})
	}
}

// Every query that ends a Session, or deletes its User, queues one logout
// token per Application it issued tokens to that has a logout URI (ADR
// 0030: no trigger does it for them). A lapsed Session was ended by nobody
// and sends nothing.
func TestEveryEndingQueuesLogoutTokens(t *testing.T) {
	pool, keyring := setup(t)
	s := New(pool, keyring)
	q := sqlc.New(pool)
	ctx := context.Background()
	for _, a := range []Application{
		{ClientID: "rp", Name: "rp", Secret: "rp-secret", RedirectURIs: []string{"https://rp/cb"}, BackchannelLogoutURI: "https://rp/logout"},
		{ClientID: "rp2", Name: "rp2", Secret: "rp2-secret", RedirectURIs: []string{"https://rp2/cb"}, BackchannelLogoutURI: "https://rp2/logout"},
		{ClientID: "quiet", Name: "quiet", Secret: "quiet-secret", RedirectURIs: []string{"https://quiet/cb"}},
	} {
		if err := CreateApplication(ctx, pool, a); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	// session makes a User with a Session (an App Session for app) that
	// issued tokens to rp2 and quiet; rp is the Application it is for.
	session := func(lapsed, app bool) (sub, id string, idHash []byte) {
		t.Helper()
		n++
		sub = fmt.Sprintf("U%d", n)
		if err := q.CreateUser(ctx, sub); err != nil {
			t.Fatal(err)
		}
		if !app {
			idHash = []byte{byte(n)}
		}
		sess, err := s.CreateSession(ctx, idHash, "rp", sub, time.Now(), []string{"pwd"}, "password")
		if err != nil {
			t.Fatal(err)
		}
		exec("INSERT INTO session_applications (session_id, client_id) VALUES ($1, 'rp2'), ($1, 'quiet')", sess.ID)
		if lapsed {
			exec("UPDATE sessions SET last_seen_at = now() - interval '100 days' WHERE id = $1", sess.ID)
			exec(dbtest.Relapse)
		}
		exec("DELETE FROM webhook_deliveries")
		return sub, sess.ID, idHash
	}
	ends := map[string]struct {
		app bool
		end func(sub, id string, idHash []byte) error
		// want for a live Session; a lapsed one always gets none.
		want []string
	}{
		"browser sign-out": {false, func(_, _ string, h []byte) error { return q.EndBrowserSession(ctx, h) }, []string{"rp2"}},
		"admin ends it": {false, func(sub, id string, _ []byte) error {
			_, err := q.EndUserSession(ctx, sqlc.EndUserSessionParams{ID: id, UserID: sub, ByID: "ADMIN", ByType: "user"})
			return err
		}, []string{"rp2"}},
		"User disabled": {false, func(sub, _ string, _ []byte) error {
			_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: sub, Disabled: true, ByID: "ADMIN", ByType: "user"})
			return err
		}, []string{"rp2"}},
		"User deleted": {false, func(sub, _ string, _ []byte) error {
			_, err := q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: sub, ByID: "ADMIN", ByType: "user"})
			return err
		}, []string{"rp2"}},
		// rp revokes: it gets one too, though its link lands in the same statement.
		"refresh token revoked": {true, func(sub, id string, _ []byte) error {
			g := &goidc.Grant{ID: "g-" + id, Subject: sub, ClientID: "rp", RefreshToken: "rt-" + id, Store: map[string]any{SessionKey: id}}
			if err := s.SaveGrant(ctx, g); err != nil {
				return err
			}
			exec("DELETE FROM session_applications WHERE session_id = $1 AND client_id = 'rp'", id)
			g.RevokedAt = int(time.Now().Unix())
			return s.SaveGrant(ctx, g)
		}, []string{"rp", "rp2"}},
		"refresh token reused": {false, func(sub, id string, _ []byte) error {
			exec("INSERT INTO oidc_grants (id, sealed, session_id) VALUES ($1, '\\x00', $2)", "g-"+id, id)
			exec("INSERT INTO oidc_spent_refresh_tokens (hash, grant_id) VALUES ($1, $2)", []byte("spent-"+id), "g-"+id)
			return q.EndReusedRefreshToken(ctx, []byte("spent-"+id))
		}, []string{"rp2"}},
	}
	for name, c := range ends {
		for _, lapsed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, lapsed %v", name, lapsed), func(t *testing.T) {
				sub, id, idHash := session(lapsed, c.app)
				if err := c.end(sub, id, idHash); err != nil {
					t.Fatal(err)
				}
				var got []string
				if err := pool.QueryRow(ctx, `SELECT COALESCE(array_agg(client_id ORDER BY client_id), '{}')
					FROM webhook_deliveries WHERE kind = 'logout' AND payload->>'sid' = $1 AND payload->>'sub' = $2`, id, sub).Scan(&got); err != nil {
					t.Fatal(err)
				}
				want := c.want
				if lapsed {
					want = []string{}
				}
				if !slices.Equal(got, want) {
					t.Errorf("logout tokens to %v, want %v", got, want)
				}
			})
		}
	}
}

// Every query that moves last_seen_at or auth_time keeps lapses_at to the
// one rule: idle timeout after last seen, never past auth_time + lifespan
// cap. Each step first scrambles lapses_at, so a query that forgets it
// leaves the rule broken.
func TestEveryWriterKeepsLapsesAt(t *testing.T) {
	pool, keyring := setup(t)
	s := New(pool, keyring)
	q := sqlc.New(pool)
	ctx := context.Background()
	if err := q.CreateUser(ctx, "ALICE"); err != nil {
		t.Fatal(err)
	}
	now := func(d time.Duration) pgtype.Timestamptz {
		return pgtype.Timestamptz{Time: time.Now().Add(d), Valid: true}
	}
	day := 24 * time.Hour
	hash := []byte{1}
	// Signed in 80 days ago: the cap (90 days) comes before the idle timeout.
	sess, err := s.CreateSession(ctx, hash, "polaris-console", "ALICE", time.Now().Add(-80*day), []string{"pwd"}, "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO oidc_grants (id, refresh_token_hash, sealed, session_id) VALUES ('g', '\\x01', '\\x00', $1)", sess.ID); err != nil {
		t.Fatal(err)
	}
	check := func(step string) {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, "SELECT lapses_at = LEAST(last_seen_at + idle_timeout, auth_time + max_lifetime) FROM sessions WHERE id = $1", sess.ID).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%s left lapses_at off the rule", step)
		}
		if _, err := pool.Exec(ctx, "UPDATE sessions SET lapses_at = now() + interval '1 minute', last_seen_at = now() - interval '1 hour' WHERE id = $1", sess.ID); err != nil {
			t.Fatal(err)
		}
	}
	check("CreateSession")
	if _, err := q.TouchSession(ctx, sqlc.TouchSessionParams{IDHash: hash}); err != nil {
		t.Fatal(err)
	}
	check("TouchSession")
	if _, err := q.RenewSession(ctx, sqlc.RenewSessionParams{NewHash: []byte{2}, AuthTime: now(-85 * day), Amr: []string{"pwd"},
		LoginMethod: "password", OldHash: hash, UserID: "ALICE"}); err != nil {
		t.Fatal(err)
	}
	check("RenewSession")
	if err := q.Reauthenticate(ctx, sqlc.ReauthenticateParams{Amr: []string{"pwd"}, ID: sess.ID, UserID: "ALICE"}); err != nil {
		t.Fatal(err)
	}
	check("Reauthenticate")
	if n, err := q.RotateRefreshToken(ctx, sqlc.RotateRefreshTokenParams{OldHash: []byte{1}, NewHash: []byte{2}, ExpiresAt: now(day),
		Sealed: []byte{0}, ID: "g"}); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	check("RotateRefreshToken")
	if n, err := q.GraceRotateRefreshToken(ctx, sqlc.GraceRotateRefreshTokenParams{OldHash: []byte{1}, GraceSecs: 60, NewHash: []byte{3},
		ExpiresAt: now(day), Sealed: []byte{0}}); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	check("GraceRotateRefreshToken")
}
