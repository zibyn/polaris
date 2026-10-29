package identity

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Lockouts (docs/spec/security-compliance.md#失败锁定).
const (
	passwordTries = 5
	// In a row: a right password starts over; failures older than the
	// cleanup's day are forgotten.
	passwordWindow = 24 * time.Hour
	passwordLock   = 15 * time.Minute
	ipFailures     = 50
	ipWindow       = time.Hour
	ipLock         = time.Hour
	// startTries is how many sign-ins one IP may start an hour, and startLock
	// how long it is then refused: what bounds passkey=begin, which sends
	// nothing and checks nothing and so cannot be made to cost a PoW
	// (ADR 0014). It counts in login_failures under its own key, so it does
	// not spend the IP's password and code budget.
	startTries  = 100
	startWindow = time.Hour
	startLock   = time.Hour
)

const (
	ErrPasswordLocked Invalid = "密码错误次数过多,请 15 分钟后再试,或用验证码登录"
	ErrIPLocked       Invalid = "失败次数过多,请 1 小时后再试"
	// ErrWrongCode is otp's; FromIP counts it.
	ErrWrongCode Invalid = "验证码错误或已失效"
	// ErrWrongTOTP and ErrWrongRecoveryCode are twofactor's; FromIP counts
	// them.
	ErrWrongTOTP         Invalid = "验证码不正确或已用过"
	ErrWrongRecoveryCode Invalid = "恢复码不正确或已用过"
)

// FromIP runs check, a password or code check made from ip: refused while
// ip is locked out, and a wrong password, code, TOTP code or 恢复码, or a
// password tried on a locked User, counts toward locking it out.
func (s *Store) FromIP(ctx context.Context, ip string, check func() error) error {
	key := "ip:" + ip
	if locked, err := s.lockedOut(ctx, key); err != nil {
		return err
	} else if locked {
		return ErrIPLocked
	}
	err := check()
	if counted(err) {
		detail, _ := json.Marshal(map[string]string{"ip": ip})
		if _, dbErr := s.failed(ctx, key, ipFailures, ipWindow, ipLock, func(time.Time) sqlc.AuditParams { return sqlc.AuditParams{Event: "login.ip_locked", Detail: detail} }); dbErr != nil {
			return dbErr
		}
	}
	return err
}

// counted reports whether err is a failure FromIP counts.
func counted(err error) bool {
	return err == ErrBadCredentials || err == ErrPasswordLocked || err == ErrWrongCode || err == ErrWrongTOTP || err == ErrWrongRecoveryCode //nolint:errorlint // never wrapped
}

// Start counts a sign-in started from ip against the per-IP budget, and
// refuses it while the IP has started too many. A sign-in an App starts
// without sending or checking anything — passkey=begin — has no failure to
// count, so this stands in for the PoW it does not have to solve (ADR 0014).
// The budget has a key of its own, so begins do not spend the IP's password
// and code budget; one locked out on that shared key is refused here all the
// same.
func (s *Store) Start(ctx context.Context, ip string) error {
	key, start := "ip:"+ip, "start:ip:"+ip
	if locked, err := s.lockedOut(ctx, key, start); err != nil {
		return err
	} else if locked {
		return ErrIPLocked
	}
	detail, _ := json.Marshal(map[string]string{"ip": ip})
	_, err := s.failed(ctx, start, startTries, startWindow, startLock, func(time.Time) sqlc.AuditParams { return sqlc.AuditParams{Event: "login.ip_locked", Detail: detail} })
	return err
}

// lockedOut reports whether any of keys is locked out.
func (s *Store) lockedOut(ctx context.Context, keys ...string) (bool, error) {
	for _, key := range keys {
		switch locked, err := s.q.LockedOut(ctx, key); {
		case err != nil:
			return false, err
		case locked:
			return true, nil
		}
	}
	return false, nil
}

// failed counts a failure of key; the max-th within window locks key out
// for lock, audited as audit says given when the lockout ends. It reports
// whether it did.
// ponytail: concurrent failures can both miss the max; the next one locks.
func (s *Store) failed(ctx context.Context, key string, max int32, window, lock time.Duration, audit func(until time.Time) sqlc.AuditParams) (bool, error) {
	n, err := s.q.LoginFailed(ctx, sqlc.LoginFailedParams{Key: key, WindowSecs: window.Seconds()})
	if err != nil || n < max {
		return false, err
	}
	return true, pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		until, err := q.LockOut(ctx, sqlc.LockOutParams{Key: key, LockSecs: lock.Seconds()})
		if err != nil {
			return err
		}
		return q.Audit(ctx, audit(until.Time))
	})
}

// DeleteOldLoginFailures removes day-old failures and past lockouts; run
// by the hourly cleanup.
func DeleteOldLoginFailures(ctx context.Context, pool *pgxpool.Pool) error {
	return sqlc.New(pool).DeleteOldLoginFailures(ctx)
}
