// Package twofactor keeps a User's 两步验证: their TOTP Credential
// (RFC 6238 with SHA1, 6 digits and 30-second steps, accepting one step
// either side) and their 恢复码 (docs/spec/identity.md).
package twofactor

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

const (
	ErrOn           identity.Invalid = "两步验证已开启"
	ErrOff          identity.Invalid = "两步验证未开启"
	ErrNotBegun     identity.Invalid = "请先扫码添加验证器"
	ErrCode                          = identity.ErrWrongTOTP
	ErrRecoveryCode                  = identity.ErrWrongRecoveryCode
)

// recoveryCodes is how many 恢复码 a set has.
const recoveryCodes = 10

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Store struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	keyring *crypt.Keyring
}

func New(pool *pgxpool.Pool, keyring *crypt.Keyring) *Store {
	return &Store{pool: pool, q: sqlc.New(pool), keyring: keyring}
}

// On reports whether sub has 两步验证 on: a confirmed TOTP.
func (s *Store) On(ctx context.Context, sub string) (bool, error) {
	t, err := s.q.TOTP(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil && t.ConfirmedAt.Valid, err
}

func aad(sub string) []byte { return []byte("totp:" + sub) }

// URI is the otpauth:// URI an authenticator scans: its entry reads
// "issuer:account".
func URI(issuer, account, secret string) string {
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" +
		url.Values{"secret": {secret}, "issuer": {issuer}}.Encode()
}

// Begin gives the User a new 160-bit TOTP secret, in Base32, to add to an
// authenticator; it replaces one not yet confirmed. 两步验证 stays off until
// Confirm.
func (s *Store) Begin(ctx context.Context, sub string) (string, error) {
	secret := make([]byte, 20)
	_, _ = rand.Read(secret)
	sealed, err := s.keyring.Seal(secret, aad(sub))
	if err != nil {
		return "", err
	}
	n, err := s.q.BeginTOTP(ctx, sqlc.BeginTOTPParams{UserID: sub, Secret: sealed})
	if err == nil && n == 0 {
		err = ErrOn
	}
	return b32.EncodeToString(secret), err
}

// Confirm turns 两步验证 on with a code from the TOTP just begun, and
// returns the User's 恢复码: the only time anyone sees them.
func (s *Store) Confirm(ctx context.Context, sub, code string) ([]string, error) {
	var codes []string
	err := db.Retry(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		t, err := q.TOTP(ctx, sub)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotBegun
		} else if err != nil {
			return err
		}
		if t.ConfirmedAt.Valid {
			return ErrOn
		}
		step, err := s.match(sub, t.Secret, t.LastStep, code)
		if err != nil {
			return err
		}
		if n, err := q.ConfirmTOTP(ctx, sqlc.ConfirmTOTPParams{UserID: sub, Step: step, Secret: t.Secret}); err != nil {
			return err
		} else if n == 0 {
			return db.ErrConflict // read again: on now, or begun again
		}
		if codes, err = s.newRecoveryCodes(ctx, q, sub); err != nil {
			return err
		}
		return writeAudit(ctx, q, "mfa.enabled", sub, audit.User(sub))
	})
	return codes, err
}

// Disable turns 两步验证 off, deleting the TOTP and every 恢复码 and ending
// its lockout (ADR 0036); audited as event done by by.
func (s *Store) Disable(ctx context.Context, sub, event string, by audit.Actor) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.DeleteTOTP(ctx, sub); err != nil {
			return err
		} else if n == 0 {
			return notOn(ctx, q, sub)
		}
		if err := q.DeleteRecoveryCodes(ctx, sub); err != nil {
			return err
		}
		if err := q.ClearLockout(ctx, identity.TwoFactorLockKey(sub)); err != nil {
			return err
		}
		return writeAudit(ctx, q, event, sub, by)
	})
}

// RegenerateRecoveryCodes replaces the User's 恢复码 with a new set.
func (s *Store) RegenerateRecoveryCodes(ctx context.Context, sub string) ([]string, error) {
	var codes []string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.KeepTOTPOn(ctx, sub); err != nil {
			return err
		} else if n == 0 {
			return notOn(ctx, q, sub)
		}
		var err error
		if codes, err = s.newRecoveryCodes(ctx, q, sub); err != nil {
			return err
		}
		return writeAudit(ctx, q, "recovery_codes.regenerated", sub, audit.User(sub))
	})
	return codes, err
}

// notOn is why sub's 两步验证 is not on: never begun, or begun but not
// confirmed.
func notOn(ctx context.Context, q *sqlc.Queries, sub string) error {
	if _, err := q.TOTP(ctx, sub); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotBegun
	} else if err != nil {
		return err
	}
	return ErrOff
}

// Check takes sub's 恢复码 when one is given, else the TOTP code. Run it in
// identity's SecondFactor, which locks out and audits.
func (s *Store) Check(ctx context.Context, sub, totp, recoveryCode string) error {
	if recoveryCode != "" {
		return s.UseRecoveryCode(ctx, sub, recoveryCode)
	}
	return s.CheckTOTP(ctx, sub, totp)
}

// CheckTOTP accepts a code from the User's TOTP, while 两步验证 is on; each
// code works once.
func (s *Store) CheckTOTP(ctx context.Context, sub, code string) error {
	t, err := s.q.TOTP(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !t.ConfirmedAt.Valid {
		return ErrOff
	} else if err != nil {
		return err
	}
	step, err := s.match(sub, t.Secret, t.LastStep, code)
	if err != nil {
		return err
	}
	// Two requests with the same code: only one moves last_step.
	if n, err := s.q.AcceptTOTPStep(ctx, sqlc.AcceptTOTPStepParams{UserID: sub, Step: step}); err != nil || n == 0 {
		return cmp.Or(err, error(ErrCode))
	}
	return nil
}

// UseRecoveryCode uses up one of the User's 恢复码, typed in any case with or
// without the dash, while 两步验证 is on; audited as recovery_code.used.
func (s *Store) UseRecoveryCode(ctx context.Context, sub, code string) error {
	macs, err := s.q.UnusedRecoveryCodes(ctx, sub)
	if err != nil {
		return err
	}
	norm := []byte(NormalizeRecoveryCode(code))
	for _, mac := range macs {
		if s.keyring.MACEqual(mac, norm) {
			n, err := s.q.UseRecoveryCode(ctx, sqlc.UseRecoveryCodeParams{UserID: sub, Mac: mac})
			if err != nil || n == 0 { // used a moment ago by a concurrent request
				return cmp.Or(err, error(ErrRecoveryCode))
			}
			return nil
		}
	}
	return ErrRecoveryCode
}

// Satisfied is 两步验证或 Passkey: what 管理员必须启用两步验证或 Passkey asks of
// an admin. A confirmed TOTP always counts, a Passkey only while the
// instance offers Passkey login.
func Satisfied(totp, hasPasskey, passkeyLogin bool) bool {
	return totp || passkeyLogin && hasPasskey
}

// NormalizeRecoveryCode is a 恢复码 as kept: lowercase, no dash or spaces.
func NormalizeRecoveryCode(code string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(code)))
}

// match returns the time step code is for: within one step of now, after
// last.
func (s *Store) match(sub string, sealed []byte, last int64, code string) (int64, error) {
	secret, err := s.keyring.Open(sealed, aad(sub))
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix() / 30
	for step := now - 1; step <= now+1; step++ {
		if step > last && hmac.Equal([]byte(totp(secret, step)), []byte(strings.TrimSpace(code))) {
			return step, nil
		}
	}
	return 0, ErrCode
}

// totp is the RFC 6238 code for a time step.
func totp(secret []byte, step int64) string {
	mac := hmac.New(sha1.New, secret)
	_ = binary.Write(mac, binary.BigEndian, step)
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0xf:]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

// newRecoveryCodes replaces the User's 恢复码 with a new set, xxxx-xxxx in
// lowercase Base32 (40 bits each).
func (s *Store) newRecoveryCodes(ctx context.Context, q *sqlc.Queries, sub string) ([]string, error) {
	codes := make([]string, recoveryCodes)
	macs := make([][]byte, recoveryCodes)
	for i := range codes {
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		c := strings.ToLower(b32.EncodeToString(b))
		codes[i], macs[i] = c[:4]+"-"+c[4:], s.keyring.MAC([]byte(c))
	}
	if err := q.DeleteRecoveryCodes(ctx, sub); err != nil {
		return nil, err
	}
	return codes, q.AddRecoveryCodes(ctx, sqlc.AddRecoveryCodesParams{UserID: sub, Macs: macs})
}

func writeAudit(ctx context.Context, q *sqlc.Queries, event, sub string, by audit.Actor) error {
	detail := by.Detail(nil)
	return q.Audit(ctx, sqlc.AuditParams{Event: event, Sub: pgtype.Text{String: sub, Valid: true}, Detail: detail})
}
