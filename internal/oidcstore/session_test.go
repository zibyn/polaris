package oidcstore

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

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
	idle, maxLife := SessionDefaults(false)
	sess, err := q.CreateSession(ctx, sqlc.CreateSessionParams{
		ClientID: "polaris-console", UserID: "ALICE", Amr: []string{"sms"},
		AuthTime: pgtype.Timestamptz{Time: time.Now(), Valid: true}, DefaultIdleSecs: idle, DefaultMaxSecs: maxLife,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(pool, keyring)
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
