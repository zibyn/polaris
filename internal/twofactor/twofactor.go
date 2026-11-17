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
	"slices"
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
	ErrOn       identity.Invalid = "两步验证已开启"
	ErrOff      identity.Invalid = "两步验证未开启"
	ErrNotBegun identity.Invalid = "请先扫码添加验证器"
	// ErrNoFactor is 两步验证 without a TOTP, from a User with no other
	// factor that counts.
	ErrNoFactor identity.Invalid = "请先添加 Passkey、短信验证或邮箱验证"
	// ErrOnlyWayIn is adding a phone number or email as a factor when it is
	// the User's only way to sign in (ADR 0038).
	ErrOnlyWayIn identity.Invalid = "这是你唯一的登录方式,用它做两步验证起不到保护作用,请先设置密码或绑定其他登录方式"
	// ErrNotAdded is a phone number or email not added as a factor.
	ErrNotAdded identity.Invalid = "没有添加这种验证方式"
	// ErrLastFactor is removing the phone number or email that is all
	// 两步验证 has besides the recovery codes.
	ErrLastFactor identity.Invalid = "这是你唯一的两步验证方式,请先添加其他方式或关闭两步验证"
	// ErrLastTOTP is removing the TOTP that is all 两步验证 has besides
	// the recovery codes.
	ErrLastTOTP identity.Invalid = "验证器是你唯一的两步验证方式,请先添加 Passkey 或关闭两步验证"
	// ErrNoTOTP is removing a TOTP the User has not added (or not confirmed).
	ErrNoTOTP       identity.Invalid = "没有验证器"
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

// On reports whether sub has 两步验证 on.
func (s *Store) On(ctx context.Context, sub string) (bool, error) {
	_, err := s.q.TwoFactorOn(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Factor is a way through 两步验证 besides a 恢复码.
type Factor string

const (
	FactorTOTP    Factor = "totp"
	FactorPasskey Factor = "passkey"
	// A code to the phone number, or to the email, the User added (ADR 0038).
	FactorSMS   Factor = "sms"
	FactorEmail Factor = "email"
)

// CodeFactor is the factor a code to an Identifier of kind (phone or email)
// is, or "" for another kind.
func CodeFactor(kind string) Factor {
	switch kind {
	case "phone":
		return FactorSMS
	case "email":
		return FactorEmail
	}
	return ""
}

// Kind is the kind of Identifier a code factor sends to, or "".
func (f Factor) Kind() string {
	switch f {
	case FactorSMS:
		return "phone"
	case FactorEmail:
		return "email"
	}
	return ""
}

// Factors is what a User has to pass 两步验证 with besides a 恢复码: the one
// place that weighs them (ADR 0037, 0038).
type Factors struct {
	// On: 两步验证 is on. TOTP: a confirmed one.
	On, TOTP bool
	// Passkey: the User has one; PasskeyLogin: the instance offers Passkey
	// login.
	Passkey, PasskeyLogin bool
	// SMS, Email: the User added their phone number, their email, and its
	// Channel is configured.
	SMS, Email bool
}

// Usable is what 两步验证 takes now, in this order: the TOTP, a Passkey
// while the instance offers Passkey login, a code to the phone number, to
// the email. A 恢复码 goes wherever a TOTP code does. Empty while 两步验证
// is on: no factor is left, which removing one must not lead to.
func (f Factors) Usable() []Factor {
	var u []Factor
	for _, c := range []struct {
		ok bool
		f  Factor
	}{{f.TOTP, FactorTOTP}, {f.Passkey && f.PasskeyLogin, FactorPasskey}, {f.SMS, FactorSMS}, {f.Email, FactorEmail}} {
		if c.ok {
			u = append(u, c.f)
		}
	}
	return u
}

// SecondStep is what the second step of a login whose first factor is amr
// offers: Usable, less a code over the first factor's channel, which would
// prove the same factor twice (ADR 0038).
func (f Factors) SecondStep(amr []string) []Factor {
	return slices.DeleteFunc(f.Usable(), func(u Factor) bool {
		return u == FactorSMS && slices.Contains(amr, "sms") || u == FactorEmail && slices.Contains(amr, "otp")
	})
}

// SecondFactors reads sub's Factors.
func (s *Store) SecondFactors(ctx context.Context, sub string) (Factors, error) {
	return SecondFactors(ctx, s.q, sub)
}

// SecondFactors reads sub's Factors with q, a transaction's for a check that
// must hold against concurrent changes (run it SERIALIZABLE).
func SecondFactors(ctx context.Context, q *sqlc.Queries, sub string) (Factors, error) {
	r, err := q.SecondFactorsOf(ctx, sub)
	return Factors{On: r.TwoFactor, TOTP: r.Totp, Passkey: r.Passkey, PasskeyLogin: r.PasskeyLogin, SMS: r.Sms, Email: r.Email}, err
}

// CodeTo is the phone number or email that f, a code factor, sends sub's
// code to; ErrNotAdded when sub has not added it.
func (s *Store) CodeTo(ctx context.Context, sub string, f Factor) (string, error) {
	v, err := s.q.SecondFactorIdentifier(ctx, sqlc.SecondFactorIdentifierParams{UserID: sub, Kind: f.Kind()})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotAdded
	}
	return v, err
}

// AddCode adds sub's phone number or email (kind) as a second factor,
// audited as sms.added or email.added; adding it again does nothing.
// identity.ErrNotBound without one; ErrOnlyWayIn when it is their only way
// to sign in, checked only now (ADR 0038).
func (s *Store) AddCode(ctx context.Context, sub, kind string) error {
	return db.Serializable(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		p, err := q.LoginPaths(ctx, sub)
		if err != nil {
			return err
		}
		if CodeFactor(kind) == "" || !slices.Contains(p.Identifiers, kind) {
			return identity.ErrNotBound
		}
		other := slices.ContainsFunc(p.Identifiers, func(k string) bool { return k != kind && CodeFactor(k) != "" })
		if !other && !p.PasswordCounts && !p.HasExternalIdentity {
			return ErrOnlyWayIn
		}
		if n, err := q.SetIdentifierSecondFactor(ctx, sqlc.SetIdentifierSecondFactorParams{UserID: sub, Kind: kind, Added: true}); err != nil || n == 0 {
			return err
		}
		return writeAudit(ctx, q, string(CodeFactor(kind))+".added", sub, audit.User(sub))
	})
}

// RemoveCode removes sub's phone number or email (kind) as a second factor,
// audited as sms.removed or email.removed: ErrNotAdded when it is not one,
// ErrLastFactor when 两步验证 is on and would have none left.
func (s *Store) RemoveCode(ctx context.Context, sub, kind string) error {
	return db.Serializable(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.SetIdentifierSecondFactor(ctx, sqlc.SetIdentifierSecondFactorParams{UserID: sub, Kind: kind, Added: false}); err != nil || n == 0 {
			return cmp.Or(err, error(ErrNotAdded))
		}
		// Weighed after the change: what is left once it is gone.
		if f, err := SecondFactors(ctx, q, sub); err != nil || f.On && len(f.Usable()) == 0 {
			return cmp.Or(err, error(ErrLastFactor))
		}
		return writeAudit(ctx, q, string(CodeFactor(kind))+".removed", sub, audit.User(sub))
	})
}

// confirmedTOTP is sub's TOTP, and whether it is there and confirmed.
func confirmedTOTP(ctx context.Context, q *sqlc.Queries, sub string) (sqlc.TOTPRow, bool, error) {
	t, err := q.TOTP(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, false, nil
	}
	return t, err == nil && t.ConfirmedAt.Valid, err
}

func aad(sub string) []byte { return []byte("totp:" + sub) }

// URI is the otpauth:// URI an authenticator scans: its entry reads
// "issuer:account".
func URI(issuer, account, secret string) string {
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" +
		url.Values{"secret": {secret}, "issuer": {issuer}}.Encode()
}

// Begin gives the User a new 160-bit TOTP secret, in Base32, to add to an
// authenticator; it replaces one not yet confirmed, and is refused while one
// is confirmed. The TOTP counts only after Confirm.
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

// Enable turns 两步验证 on without a TOTP, returning the User's 恢复码: the
// only time anyone sees them. ErrNoFactor unless the User has a factor that
// counts: a Passkey while the instance offers Passkey login (ADR 0037), or
// a phone number or email they added (ADR 0038).
func (s *Store) Enable(ctx context.Context, sub string) ([]string, error) {
	var codes []string
	// SERIALIZABLE: the last factor going meanwhile is refused here or
	// there (passkey.Remove, RemoveCode), not both let through.
	err := db.Serializable(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if f, err := SecondFactors(ctx, q, sub); err != nil || len(f.Usable()) == 0 {
			return cmp.Or(err, error(ErrNoFactor))
		}
		if n, err := q.EnableTwoFactor(ctx, sub); err != nil || n == 0 {
			return cmp.Or(err, error(ErrOn))
		}
		var err error
		if codes, err = s.newRecoveryCodes(ctx, q, sub); err != nil {
			return err
		}
		return writeAudit(ctx, q, "mfa.enabled", sub, audit.User(sub))
	})
	return codes, err
}

// RemoveTOTP removes the User's TOTP, leaving 两步验证 on by their others:
// ErrLastTOTP without one that counts, ErrNoTOTP without a TOTP.
func (s *Store) RemoveTOTP(ctx context.Context, sub string) error {
	return db.Serializable(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if n, err := q.DeleteConfirmedTOTP(ctx, sub); err != nil || n == 0 {
			return cmp.Or(err, error(ErrNoTOTP))
		}
		// Weighed after the delete: what is left once it is gone.
		if f, err := SecondFactors(ctx, q, sub); err != nil || len(f.Usable()) == 0 {
			return cmp.Or(err, error(ErrLastTOTP))
		}
		return writeAudit(ctx, q, "totp.removed", sub, audit.User(sub))
	})
}

// Confirm confirms the TOTP just begun with a code from it. With 两步验证
// off it turns it on, returning the User's 恢复码: the only time anyone sees
// them. With it on by a Passkey, the TOTP joins it and the 恢复码 stay.
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
		if n, err := q.EnableTwoFactor(ctx, sub); err != nil {
			return err
		} else if n == 0 {
			return writeAudit(ctx, q, "totp.added", sub, audit.User(sub))
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
		if n, err := q.DisableTwoFactor(ctx, sub); err != nil {
			return err
		} else if n == 0 {
			return notOn(ctx, q, sub)
		}
		if err := q.DeleteTOTP(ctx, sub); err != nil {
			return err
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
		if n, err := q.KeepTwoFactorOn(ctx, sub); err != nil {
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

// CheckMethod is the method identity's SecondFactor audits a Check by.
func CheckMethod(recoveryCode string) string {
	if recoveryCode != "" {
		return "recovery_code"
	}
	return "totp"
}

// CheckTOTP accepts a code from the User's confirmed TOTP; each code works
// once. Without one: ErrOff while 两步验证 is off, else a wrong code, so a
// User whose 两步验证 has only a Passkey is not let past it by any code.
func (s *Store) CheckTOTP(ctx context.Context, sub, code string) error {
	t, has, err := confirmedTOTP(ctx, s.q, sub)
	if err != nil {
		return err
	} else if !has {
		if on, err := s.On(ctx, sub); err != nil || on {
			return cmp.Or(err, error(ErrCode))
		}
		return ErrOff
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
// an admin. 两步验证 on always counts, a Passkey only while the instance
// offers Passkey login.
func Satisfied(twoFactor, hasPasskey, passkeyLogin bool) bool {
	return twoFactor || passkeyLogin && hasPasskey
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
