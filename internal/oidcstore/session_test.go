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
