// Package identity owns Users, their Identifiers and Credentials, and the
// first-start bootstrap that creates the first owner.
package identity

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/stars-auth/internal/crypt"
	"github.com/zibyn/stars-auth/internal/db/sqlc"
)

// ManagementAPI is the built-in API whose Roles make a User an admin.
const ManagementAPI = "urn:stars-auth:management-api"

// AccountAPI is the built-in API the account center calls, where a User
// manages their own account.
const AccountAPI = "urn:stars-auth:account-api"

// Invalid is an error safe to show the person who caused it.
type Invalid string

func (e Invalid) Error() string { return string(e) }

const (
	ErrSetupToken       Invalid = "setup token 无效"
	ErrSetupClosed      Invalid = "引导已完成"
	ErrUsername         Invalid = "用户名须为 3–32 位字母、数字或 . _ -"
	ErrPasswordTooShort Invalid = "密码至少 8 位"
	ErrBadCredentials   Invalid = "用户名或密码错误"
	ErrDisabled         Invalid = "已被管理员禁用,无法登录"
)

type Store struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	keyring *crypt.Keyring
}

func New(pool *pgxpool.Pool, keyring *crypt.Keyring) *Store {
	return &Store{pool: pool, q: sqlc.New(pool), keyring: keyring}
}

var setupAAD = []byte("setup_token")

// SetupToken returns the one-time token that opens the setup page, creating
// it on first call; "" once the first owner exists.
func (s *Store) SetupToken(ctx context.Context) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	q := s.q.WithTx(tx)
	setup, err := q.LockSetup(ctx)
	if err != nil || setup.SetupDone {
		return "", err
	}
	if setup.SetupToken != nil {
		token, err := s.keyring.Open(setup.SetupToken, setupAAD)
		return string(token), err
	}
	token := rand.Text()
	sealed, err := s.keyring.Seal([]byte(token), setupAAD)
	if err != nil {
		return "", err
	}
	if err := q.SetSetupToken(ctx, sealed); err != nil {
		return "", err
	}
	return token, tx.Commit(ctx)
}

// Bootstrap creates the first owner with a username and password, then closes
// the setup page for good. It returns the new User's sub.
func (s *Store) Bootstrap(ctx context.Context, token, username, password string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	q := s.q.WithTx(tx)
	setup, err := q.LockSetup(ctx) // serialises concurrent bootstraps
	if err != nil {
		return "", err
	}
	if setup.SetupDone {
		return "", ErrSetupClosed
	}
	want, err := s.keyring.Open(setup.SetupToken, setupAAD)
	if err != nil || subtle.ConstantTimeCompare(want, []byte(token)) != 1 {
		return "", ErrSetupToken
	}
	if username, err = CheckUsername(username); err != nil {
		return "", err
	}
	if utf8.RuneCountInString(password) < 8 {
		return "", ErrPasswordTooShort
	}
	hash, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	sub := rand.Text()
	if err := q.CreateUser(ctx, sub); err != nil {
		return "", err
	}
	if err := q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: "username", Value: username}); err != nil {
		return "", err
	}
	if err := q.SetPassword(ctx, sqlc.SetPasswordParams{UserID: sub, Hash: hash}); err != nil {
		return "", err
	}
	if err := q.AssignRole(ctx, sqlc.AssignRoleParams{UserID: sub, Api: ManagementAPI, Role: "owner"}); err != nil {
		return "", err
	}
	if err := q.CloseSetup(ctx); err != nil {
		return "", err
	}
	return sub, tx.Commit(ctx)
}

// CheckPassword returns the sub of the User with this Identifier (username,
// phone or email) whose password matches, if the password login setting lets
// them in. Five wrong passwords in a row lock the User's password login.
func (s *Store) CheckPassword(ctx context.Context, identifier, password string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(identifier))
	if _, v, err := ParseIdentifier(identifier); err == nil {
		value = v // a phone number typed without +86
	}
	row, err := s.q.PasswordByIdentifier(ctx, value)
	if err != nil {
		_, _ = verifyPassword(dummyHash, password) // unknown Identifiers take as long as known ones
		return "", ErrBadCredentials
	}
	key := "sub:" + row.UserID
	if locked, err := s.q.LockedOut(ctx, key); err != nil || locked {
		return "", cmp.Or(err, error(ErrPasswordLocked))
	}
	if ok, err := verifyPassword(row.Hash, password); err != nil {
		return "", err
	} else if !ok {
		locked, err := s.failed(ctx, key, passwordTries, passwordWindow, passwordLock, sqlc.AuditParams{
			Event: "login.password_locked", Sub: pgtype.Text{String: row.UserID, Valid: true}, Detail: []byte("{}"),
		})
		if locked {
			return "", cmp.Or(err, error(ErrPasswordLocked))
		}
		return "", cmp.Or(err, error(ErrBadCredentials))
	}
	if err := s.q.ClearLoginFailures(ctx, key); err != nil {
		return "", err
	}
	if row.Disabled {
		return "", ErrDisabled
	}
	setting, err := s.q.PasswordLogin(ctx)
	if err != nil {
		return "", err
	}
	if setting == "off" {
		return "", ErrBadCredentials
	}
	return row.UserID, nil
}

var usernameRE = regexp.MustCompile(`^[a-z0-9._-]{3,32}$`)

// CheckUsername normalises a username. With no '@' or '+' it can never read
// as an email or phone number.
func CheckUsername(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !usernameRE.MatchString(s) {
		return "", ErrUsername
	}
	return s, nil
}

const (
	ErrIdentifier      Invalid = "请输入 +86 手机号或邮箱"
	ErrPhone           Invalid = "请输入 +86 手机号"
	ErrIdentifierTaken Invalid = "这个手机号或邮箱已属于另一个 User"
)

var (
	phoneRE = regexp.MustCompile(`^(?:\+?86)?(1[3-9]\d{9})$`)
	emailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// ParseIdentifier reads what a person typed as a phone number (+86 only,
// stored E.164) or an email (stored lowercase).
func ParseIdentifier(s string) (kind, value string, err error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "@") {
		s = strings.ToLower(s)
		if !emailRE.MatchString(s) || len(s) > 254 {
			return "", "", ErrIdentifier
		}
		return "email", s, nil
	}
	m := phoneRE.FindStringSubmatch(strings.NewReplacer(" ", "", "-", "").Replace(s))
	if m == nil {
		return "", "", ErrIdentifier
	}
	return "phone", "+86" + m[1], nil
}

// SignIn returns the User holding a phone number or email that was just
// verified, creating one if nobody does: logging in is signing up.
func (s *Store) SignIn(ctx context.Context, kind, value string) (string, error) {
	u, err := s.q.UserByIdentifier(ctx, value)
	if err == nil && u.Disabled {
		return "", ErrDisabled
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return u.UserID, err
	}
	sub := rand.Text()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.CreateUser(ctx, sub); err != nil {
			return err
		}
		return q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: kind, Value: value})
	})
	if isUniqueViolation(err) { // signed up a moment ago by a concurrent request
		return s.SignIn(ctx, kind, value)
	}
	return sub, err
}

// AddIdentifier binds a verified phone number or email to sub; never one
// another User holds (ADR 0003).
func (s *Store) AddIdentifier(ctx context.Context, sub, kind, value string) error {
	err := s.q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: kind, Value: value})
	if isUniqueViolation(err) {
		return ErrIdentifierTaken
	}
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreatePendingUser makes a User for an admin to hand over (ADR 0016), with
// an Identifier and an initial password of the admin's choosing, in 待激活.
// The Identifier is stored as verified, so it can also receive codes; the
// password is hashed here, never in the caller.
func (s *Store) CreatePendingUser(ctx context.Context, identifier, password string) (string, error) {
	if utf8.RuneCountInString(password) < 8 {
		return "", ErrPasswordTooShort
	}
	kind, value, err := ParseCreateIdentifier(identifier)
	if err != nil {
		return "", err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	return s.createPending(ctx, kind, value, func(q *sqlc.Queries, sub string) error {
		return q.SetPassword(ctx, sqlc.SetPasswordParams{UserID: sub, Hash: hash})
	})
}

// CreateInvitedUser makes a User for an admin to invite (ADR 0016): one email
// Identifier, in 待激活, with no credential at all — the invite link is the
// only way in until they set their own password.
func (s *Store) CreateInvitedUser(ctx context.Context, identifier string) (string, error) {
	kind, value, err := ParseCreateIdentifier(identifier)
	if err != nil {
		return "", err
	}
	if kind != "email" {
		return "", ErrInviteNeedsEmail
	}
	// No credential to write: an invited User has nothing to sign in with
	// until the link is accepted.
	return s.createPending(ctx, kind, value, func(*sqlc.Queries, string) error { return nil })
}

// createPending makes a User with one Identifier, in 待激活, running write for
// the credential in the same transaction: a User never outlives a failed
// Identifier, and a credential never lands on an account that stayed active.
func (s *Store) createPending(ctx context.Context, kind, value string, write func(*sqlc.Queries, string) error) (string, error) {
	sub := rand.Text()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.CreateUser(ctx, sub); err != nil {
			return err
		}
		if err := q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: kind, Value: value}); err != nil {
			if isUniqueViolation(err) {
				return ErrIdentifierTaken
			}
			return err
		}
		if err := write(q, sub); err != nil {
			return err
		}
		// CreateUser leaves the User active (it means "signed up"), so this
		// is the step that makes them 待激活.
		return q.SetUserPending(ctx, sub)
	})
	return sub, err
}

// ParseCreateIdentifier reads what an admin typed as an Identifier of any
// kind: a username, which ParseIdentifier would insist be a phone number or
// an email. The two can never disagree about a value's kind — a username
// may hold neither '@' nor '+', so nothing that reads as a phone number or
// an email can also read as one.
func ParseCreateIdentifier(s string) (kind, value string, err error) {
	if kind, value, err := ParseIdentifier(s); err == nil {
		return kind, value, nil
	}
	if value, err := CheckUsername(s); err == nil {
		return "username", value, nil
	}
	return "", "", ErrCreateIdentifier
}

// ErrCreateIdentifier is an Identifier an admin typed that is neither a
// phone number, an email nor a username.
const ErrCreateIdentifier Invalid = "请输入手机号、邮箱或用户名"
