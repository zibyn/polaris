package identity

import (
	"context"
	"errors"
	"slices"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/zibyn/stars-auth/internal/db/sqlc"
)

const (
	ErrLastLoginPath Invalid = "这是最后一个登录途径,不能解绑或删除"
	ErrNotBound      Invalid = "没有绑定这一项"
	ErrNoIdentifier  Invalid = "先绑定手机号、邮箱或用户名,才能设置密码"
)

// SetPassword sets or changes the User's password; they need an Identifier
// to sign in with it (invariant 5).
func (s *Store) SetPassword(ctx context.Context, sub, password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return ErrPasswordTooShort
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return s.changeLoginPaths(ctx, sub, func(q *sqlc.Queries) error {
		paths, err := q.LoginPaths(ctx, sub)
		if err != nil {
			return err
		}
		if len(paths.Identifiers) == 0 {
			return ErrNoIdentifier
		}
		return q.PutPassword(ctx, sqlc.PutPasswordParams{UserID: sub, Hash: hash})
	})
}

// RemovePassword deletes the User's password, unless it is their last way
// to sign in.
func (s *Store) RemovePassword(ctx context.Context, sub string) error {
	return s.changeLoginPaths(ctx, sub, func(q *sqlc.Queries) error {
		return bound(q.RemovePassword(ctx, sub))
	})
}

// RemoveIdentifier unbinds the User's Identifier of kind, unless it is their
// last way to sign in.
func (s *Store) RemoveIdentifier(ctx context.Context, sub, kind string) error {
	return s.changeLoginPaths(ctx, sub, func(q *sqlc.Queries) error {
		return bound(q.RemoveIdentifier(ctx, sqlc.RemoveIdentifierParams{UserID: sub, Kind: kind}))
	})
}

// RemoveExternalIdentity unbinds the User's External Identity at provider,
// unless it is their last way to sign in, and returns the Provider's subject
// and the binding's sealed token. Audited as done by by.
func (s *Store) RemoveExternalIdentity(ctx context.Context, sub, provider, by string) (subject string, sealedToken []byte, err error) {
	var row sqlc.RemoveExternalIdentityRow
	err = s.changeLoginPaths(ctx, sub, func(q *sqlc.Queries) error {
		var err error
		row, err = q.RemoveExternalIdentity(ctx, sqlc.RemoveExternalIdentityParams{UserID: sub, Provider: provider, By: by})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotBound
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) { // no such User
		err = ErrNotBound
	}
	return row.Subject, row.Token, err
}

func bound(n int64, err error) error {
	if err == nil && n == 0 {
		return ErrNotBound
	}
	return err
}

// OtherLoginPath reports whether the User can sign in without a password: a
// phone number or an email, or an External Identity at an enabled Provider. A
// username on its own does not count — it only works with a password. This is
// the whole of what a password-login switch must leave in place before it may
// go off (management.putSettings).
func (s *Store) OtherLoginPath(ctx context.Context, sub string) (bool, error) {
	paths, err := s.q.LoginPaths(ctx, sub)
	return otherLoginPath(paths), err
}

// otherLoginPath is the predicate shared by OtherLoginPath and
// changeLoginPaths' invariant-1 check.
func otherLoginPath(paths sqlc.LoginPathsRow) bool {
	if paths.HasExternalIdentity {
		return true
	}
	for _, kind := range paths.Identifiers {
		if kind != "username" {
			return true
		}
	}
	return false
}

// changeLoginPaths runs change with the User locked, and undoes it if it
// leaves them no way to sign in (invariant 1): a phone number, an email,
// a username with a password, or an External Identity at an enabled
// Provider.
func (s *Store) changeLoginPaths(ctx context.Context, sub string, change func(*sqlc.Queries) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if _, err := q.LockUser(ctx, sub); err != nil {
			return err
		}
		if err := change(q); err != nil {
			return err
		}
		paths, err := q.LoginPaths(ctx, sub)
		if err != nil {
			return err
		}
		if otherLoginPath(paths) || paths.HasPassword && slices.Contains(paths.Identifiers, "username") {
			return nil
		}
		return ErrLastLoginPath
	})
}

// ReplaceIdentifier binds value as the User's Identifier of kind, replacing
// the one they had; never one another User holds (ADR 0003). Audited as done
// by by.
func (s *Store) ReplaceIdentifier(ctx context.Context, sub, kind, value, by string) error {
	_, err := s.q.ReplaceIdentifier(ctx, sqlc.ReplaceIdentifierParams{UserID: sub, Kind: kind, Value: value, By: by})
	if isUniqueViolation(err) {
		return ErrIdentifierTaken
	}
	return err
}

const ErrLastOwner Invalid = "你是最后一个所有者,不能注销"

// GuardOwners runs change in a transaction that fails with ErrLastOwner if it
// takes the instance from having a usable owner to having none. Only an
// active owner counts: a 待激活 owner can sign in but gets no token, so they
// cannot administer the instance.
func (s *Store) GuardOwners(ctx context.Context, change func(*sqlc.Queries) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		if err := q.LockOwners(ctx); err != nil {
			return err
		}
		before, err := q.CountOwners(ctx)
		if err != nil {
			return err
		}
		if err := change(q); err != nil {
			return err
		}
		after, err := q.CountOwners(ctx)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return ErrLastOwner
		}
		return nil
	})
}

// Delete deletes the User's account with all their data, at their own
// request; never the last usable owner.
func (s *Store) Delete(ctx context.Context, sub string) error {
	return s.GuardOwners(ctx, func(q *sqlc.Queries) error {
		_, err := q.DeleteUser(ctx, sqlc.DeleteUserParams{UserID: sub, By: sub})
		return err
	})
}

// ErrNotPending is a password write that only a 待激活 User may make, on an
// account that is not 待激活 any more.
const ErrNotPending Invalid = "该账号已经激活,请重新登录"

// SetPasswordIfPending replaces a 待激活 User's password with their own and
// activates the account (ADR 0016).
//
// It is a password path of its own, deliberately not the account center's
// SetPassword above: that one is a sensitive action, and reauthenticating for
// one is refused to a User with 两步验证 on — a password or a code is turned
// down there, and a Passkey or TOTP they have not set up yet is nothing to
// fall back on. A 待激活 User would be stuck for good. Here their password
// itself is the proof they just gave, and nothing else is asked for.
func (s *Store) SetPasswordIfPending(ctx context.Context, sub, password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return ErrPasswordTooShort
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	// Only a row that is still pending takes the password, so replaying the
	// step of an account that has been activated since changes nothing.
	if n, err := s.q.ActivateUser(ctx, sqlc.ActivateUserParams{UserID: sub, Hash: hash}); err != nil {
		return err
	} else if n == 0 {
		return ErrNotPending
	}
	return nil
}

// Pending reports whether the User is 待激活: created by an admin, with a
// password of someone else's choosing they have not replaced yet. A disabled
// User is never 待激活 — they cannot sign in at all.
func (s *Store) Pending(ctx context.Context, sub string) (bool, error) {
	pending, err := s.q.UserPending(ctx, sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // no such User: nothing to hold back
	}
	return pending, err
}
