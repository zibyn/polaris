package identity

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Attempt is where a sign-in comes from, as login events record it
// (docs/spec/security-compliance.md#审计日志).
type Attempt struct {
	ClientID, IP, UA string
}

// AttemptFrom is where r, a sign-in to clientID, comes from.
func AttemptFrom(r *http.Request, clientID string) Attempt {
	return Attempt{ClientID: clientID, IP: ClientIP(r), UA: r.UserAgent()}
}

// ClientIP is the IP r comes from.
func ClientIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return strings.TrimSpace(r.RemoteAddr)
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

// Password checks a password typed to sign in, as CheckPassword does, from
// a.IP: refused while that IP is locked out, and a wrong one counted toward
// its lockout and audited as login.failed.
func (s *Store) Password(ctx context.Context, a Attempt, identifier, password string) (string, error) {
	if a.ClientID == "" {
		return "", errNoClientID
	}
	var sub string
	err := s.FromIP(ctx, a.IP, func() (err error) {
		sub, err = s.CheckPassword(ctx, a, identifier, password)
		return err
	})
	return sub, s.loginFailed(ctx, a, sub, "password", err)
}

// Code runs check, of a code sent to identifier, from a.IP: refused while
// that IP is locked out, and a wrong code counted toward its lockout and
// audited as login.failed on the User it would sign in: pending, else
// whoever holds identifier, if anyone.
func (s *Store) Code(ctx context.Context, a Attempt, identifier, pending string, check func() error) error {
	if a.ClientID == "" {
		return errNoClientID
	}
	err := s.FromIP(ctx, a.IP, check)
	if !counted(err) || pending != "" {
		return s.loginFailed(ctx, a, pending, "code", err)
	}
	u, dbErr := s.q.UserByIdentifier(ctx, identifier)
	if dbErr != nil && !errors.Is(dbErr, pgx.ErrNoRows) {
		return dbErr
	}
	return s.loginFailed(ctx, a, u.UserID, "code", err)
}

// SecondFactor runs check, of sub's TOTP code or, if recovery, 恢复码, from
// a.IP: refused while that IP is locked out, and a wrong one counted toward
// its lockout and audited as login.failed.
func (s *Store) SecondFactor(ctx context.Context, a Attempt, sub string, recovery bool, check func() error) error {
	if a.ClientID == "" {
		return errNoClientID
	}
	method := "totp"
	if recovery {
		method = "recovery_code"
	}
	return s.loginFailed(ctx, a, sub, method, s.FromIP(ctx, a.IP, check))
}

// errNoClientID is a caller's bug: a login event says which Application it
// was for.
var errNoClientID = errors.New("identity: Attempt has no ClientID")

// loginFailed audits err, if it is a wrong password, code, TOTP code or
// 恢复码 tried on sub by method, as login.failed; with no sub, or any other
// error, it audits nothing. It returns err, or the audit's own error.
func (s *Store) loginFailed(ctx context.Context, a Attempt, sub, method string, err error) error {
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
