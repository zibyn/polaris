package identity

import (
	"context"
	"encoding/json"
	"maps"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Attempt is where a sign-in comes from, as login events record it
// (docs/spec/security-compliance.md#审计日志).
type Attempt struct {
	ClientID, IP, UA string
}

// UserAgent is how much of a User-Agent is kept, by a Session or a login
// event: 512 bytes, valid UTF-8 for a text column, a rune cut in half
// dropped.
func UserAgent(ua string) string {
	return strings.ToValidUTF8(ua[:min(len(ua), 512)], "")
}

// detail is a login event's detail: the Attempt and extra.
func (a Attempt) detail(extra map[string]any) []byte {
	d := map[string]any{"client_id": a.ClientID, "ip": a.IP, "ua": UserAgent(a.UA)}
	maps.Copy(d, extra)
	out, _ := json.Marshal(d)
	return out
}

// LoginSucceeded audits a login of sub, proved as amr.
func (s *Store) LoginSucceeded(ctx context.Context, a Attempt, sub string, amr []string) error {
	return s.q.Audit(ctx, sqlc.AuditParams{
		Event: "login.succeeded", Sub: pgtype.Text{String: sub, Valid: true}, Detail: a.detail(map[string]any{"amr": amr}),
	})
}

// LoginFailed audits err, if it is a wrong password, code, TOTP code or
// 恢复码 tried on sub by method, as login.failed; with no sub, or any other
// error, it audits nothing. It returns err, or the audit's own error.
func (s *Store) LoginFailed(ctx context.Context, a Attempt, sub, method string, err error) error {
	if sub == "" || !counted(err) {
		return err
	}
	if dbErr := s.q.Audit(ctx, sqlc.AuditParams{
		Event: "login.failed", Sub: pgtype.Text{String: sub, Valid: true}, Detail: a.detail(map[string]any{"method": method}),
	}); dbErr != nil {
		return dbErr
	}
	return err
}
