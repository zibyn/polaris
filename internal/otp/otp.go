// Package otp makes, sends and checks verification codes, within the send
// limits of docs/spec/security-compliance.md. Channels only deliver them.
package otp

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/metrics"
)

const (
	ErrNoChannel  identity.Invalid = "暂不支持向这类手机号或邮箱发送验证码"
	ErrTooSoon    identity.Invalid = "发送太频繁,请 60 秒后再试"
	ErrTooMany    identity.Invalid = "发送次数过多,请稍后再试"
	ErrDailyCap   identity.Invalid = "今日发送量已达上限,请明天再试"
	ErrSendFailed identity.Invalid = "验证码发送失败,请稍后再试"
	ErrWrongCode                   = identity.ErrWrongCode
	// 注册邀请: 它只发邮件, 也只受实例每日上限约束 —— 按标识符、按 IP 的
	// 发码限流是防人刷码的, 而邀请是管理员主动发的, 一次就一条。
	ErrNoEmailChannel identity.Invalid = "这个实例还没有配置邮箱渠道,发不了邀请"
	ErrInviteFailed   identity.Invalid = "邀请邮件发送失败,请稍后再试"
)

const (
	ttl           = 5 * time.Minute
	auditDailyCap = "send.daily_cap_reached"
)

// channelKind names a Channel by what it is, for metrics labels.
var channelKind = map[string]string{"phone": "sms", "email": "email"}

type Service struct {
	pool     *pgxpool.Pool
	channels *channel.Store
	now      func() time.Time
}

func New(pool *pgxpool.Pool, channels *channel.Store) *Service {
	return &Service{pool: pool, channels: channels, now: time.Now}
}

// Send makes a code for value, an Identifier of kind (phone or email)
// already normalised, and sends it from a request by ip.
func (s *Service) Send(ctx context.Context, kind, value, ip string) error {
	ch, err := s.channels.Channel(ctx, kind)
	if errors.Is(err, channel.ErrNotConfigured) {
		return ErrNoChannel
	} else if err != nil {
		return err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return err
	}
	code := fmt.Sprintf("%06d", n)
	if err := s.reserve(ctx, value, ip, code); err != nil {
		return err
	}
	if err := ch.Send(ctx, value, code); err != nil {
		slog.Error("send code", "kind", kind, "err", err)
		metrics.CodeSendFailures.WithLabelValues(channelKind[kind]).Inc()
		return ErrSendFailed
	}
	return nil
}

// SendInvite delivers a 注册邀请 link to value, an email address. It counts
// against the instance daily send limit and nothing else: the per-Identifier
// and per-IP limits of the switch above exist to stop someone farming codes
// out of a mailbox or a number, and an invitation is the admin's own one-off
// (docs/spec/security-compliance.md#发送限制).
func (s *Service) SendInvite(ctx context.Context, value, link string) error {
	ch, err := s.channels.Channel(ctx, "email")
	if errors.Is(err, channel.ErrNotConfigured) {
		return ErrNoEmailChannel
	} else if err != nil {
		return err
	}
	if err := s.reserveInvite(ctx, value); err != nil {
		return err
	}
	if err := ch.SendLink(ctx, value, link); err != nil {
		slog.Error("send invite", "err", err)
		metrics.CodeSendFailures.WithLabelValues("email").Inc()
		return ErrInviteFailed
	}
	return nil
}

// reserveInvite counts an invitation against the instance daily limit and
// records it. It takes the sends lock like reserve does, so the day's total
// can never run past the limit.
func (s *Service) reserveInvite(ctx context.Context, value string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	q := sqlc.New(tx)
	if err := q.LockSends(ctx); err != nil {
		return err
	}
	now := s.now()
	// Only instance_day and daily_limit are read: an invitation matches none
	// of the per-Identifier or per-IP counts.
	c, err := q.SendCounts(ctx, sqlc.SendCountsParams{
		Identifier: value,
		MinuteAgo:  ts(now.Add(-time.Minute)),
		HourAgo:    ts(now.Add(-time.Hour)),
		DayAgo:     ts(now.Add(-24 * time.Hour)),
	})
	if err != nil {
		return err
	}
	if c.InstanceDay >= int64(c.DailyLimit) {
		if err := s.overDailyCap(ctx, tx, q, c, now); err != nil {
			return err
		}
		return ErrDailyCap
	}
	if err := q.RecordInviteSend(ctx, ts(now)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// reserve counts a send against the limits and stores its code.
func (s *Service) reserve(ctx context.Context, value, ip, code string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	q := sqlc.New(tx)
	if err := q.LockSends(ctx); err != nil {
		return err
	}
	now := s.now()
	c, err := q.SendCounts(ctx, sqlc.SendCountsParams{
		Identifier: value,
		Ip:         ip,
		MinuteAgo:  ts(now.Add(-time.Minute)),
		HourAgo:    ts(now.Add(-time.Hour)),
		DayAgo:     ts(now.Add(-24 * time.Hour)),
	})
	if err != nil {
		return err
	}
	switch {
	case c.IdentifierMinute >= 1:
		return ErrTooSoon
	case c.IdentifierHour >= 5, c.IdentifierDay >= 10, c.IpHour >= 20:
		return ErrTooMany
	case c.InstanceDay >= int64(c.DailyLimit):
		if err := s.overDailyCap(ctx, tx, q, c, now); err != nil {
			return err
		}
		return ErrDailyCap
	}
	if err := q.RecordSend(ctx, sqlc.RecordSendParams{Identifier: value, Ip: ip, SentAt: ts(now)}); err != nil {
		return err
	}
	if err := q.PutCode(ctx, sqlc.PutCodeParams{Identifier: value, Code: code, ExpiresAt: ts(now.Add(ttl))}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// overDailyCap audits the day's first refusal, which is the one worth an
// event: the rest are the same person pressing the button again. It commits
// the caller's transaction when it wrote that event, because the caller is
// about to roll it back to refuse the send.
func (s *Service) overDailyCap(ctx context.Context, tx pgx.Tx, q *sqlc.Queries, c sqlc.SendCountsRow, now time.Time) error {
	audited, err := q.AuditedSince(ctx, sqlc.AuditedSinceParams{Event: auditDailyCap, At: ts(now.Add(-24 * time.Hour))})
	if err != nil || audited {
		return err
	}
	if err := q.Audit(ctx, sqlc.AuditParams{Event: auditDailyCap, Detail: fmt.Appendf(nil, `{"limit": %d}`, c.DailyLimit)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Check spends value's code if it matches; five tries kill it.
func (s *Service) Check(ctx context.Context, value, code string) error {
	q := sqlc.New(s.pool)
	want, err := q.TryCode(ctx, sqlc.TryCodeParams{Identifier: value, Now: ts(s.now())})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrWrongCode
	} else if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(code)) != 1 {
		return ErrWrongCode
	}
	// Only one of two parallel right answers gets to delete it.
	if n, err := q.DeleteCode(ctx, sqlc.DeleteCodeParams{Identifier: value, Code: want}); err != nil || n != 1 {
		return cmp.Or(err, error(ErrWrongCode))
	}
	return nil
}

// DeleteExpired removes dead codes and day-old send counts; run by the
// hourly cleanup.
func DeleteExpired(ctx context.Context, pool *pgxpool.Pool) error {
	return sqlc.New(pool).DeleteExpiredOTP(ctx)
}

func ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
