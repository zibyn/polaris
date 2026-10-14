package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/stars-auth/internal/db/sqlc"
)

const (
	// ErrInviteNeedsEmail: 注册邀请只走邮件, 所以创建时给的标识符必须是邮箱。
	ErrInviteNeedsEmail Invalid = "邀请只支持邮箱:请填一个邮箱地址,或改用初始密码"
	// ErrNoEmail: 一个没有邮箱的账号发不出邀请。
	ErrNoEmail Invalid = "这个 User 没有邮箱,发不了邀请"
	// ErrInviteSpent: 链接用过、被撤销或过期 —— 对本人是同一种情况。
	ErrInviteSpent Invalid = "这个邀请链接已失效或已过期,请联系管理员重新发送"
)

// MintInvite mints a 注册邀请 for sub and returns its plaintext token and the
// email address it goes to. Only the token's hash is stored, so the plaintext
// exists in that one email and nowhere else. An invite sub already had is
// replaced: an old link stops working the moment a new one is sent.
func (s *Store) MintInvite(ctx context.Context, sub string) (token, email string, err error) {
	ids, err := s.q.UserIdentifiers(ctx, sub)
	if err != nil {
		return "", "", err
	}
	for _, id := range ids {
		if id.Kind == "email" {
			email = id.Value
			break
		}
	}
	if email == "" {
		return "", "", ErrNoEmail
	}
	token = rand.Text()
	err = s.q.PutInvite(ctx, sqlc.PutInviteParams{TokenHash: tokenHash(token), UserID: sub})
	return token, email, err
}

// DropInvite deletes whatever invite sub has: a send that failed leaves no
// usable token behind.
func (s *Store) DropInvite(ctx context.Context, sub string) error {
	return s.q.DeleteInvite(ctx, sub)
}

// RevokeInvite drops sub's invite, audited as done by the admin, and reports
// whether there was one to drop.
func (s *Store) RevokeInvite(ctx context.Context, sub, by string) (bool, error) {
	n, err := s.q.RevokeInvite(ctx, sqlc.RevokeInviteParams{UserID: sub, By: by})
	return n > 0, err
}

// InviteLive reports whether an invite with this token can still be accepted:
// one that was used, revoked or has expired cannot.
func (s *Store) InviteLive(ctx context.Context, token string) (bool, error) {
	_, err := s.q.LiveInvite(ctx, tokenHash(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// AcceptInvite spends the invite named by token and writes password as the
// User's own, activating the account if it was 待激活; it returns their sub.
// Audited as done by the User, not by anyone else — this is the one place a
// password is set without the User's old one.
//
// It is also the way back in for a User who forgot their password (ADR 0016),
// which is why it does not stop at 待激活 accounts: an active User takes the
// new password just the same.
func (s *Store) AcceptInvite(ctx context.Context, token, password string) (string, error) {
	if utf8.RuneCountInString(password) < 8 {
		return "", ErrPasswordTooShort
	}
	hash, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	// Spending the token and writing the password are one statement: a link
	// is good once, and a second request finds nothing to spend.
	sub, err := s.q.AcceptInvite(ctx, sqlc.AcceptInviteParams{TokenHash: tokenHash(token), Hash: hash})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInviteSpent
	}
	return sub.String, err
}

// DeleteExpiredInvites drops the invites past their expiry; run by the hourly
// cleanup.
func DeleteExpiredInvites(ctx context.Context, pool *pgxpool.Pool) error {
	return sqlc.New(pool).DeleteExpiredInvites(ctx)
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
