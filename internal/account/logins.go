package account

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/zibyn/polaris/internal/db/sqlc"
)

// Login is one of the User's sign-ins, failed sign-ins or password
// lockouts, from the audit log (docs/spec/consoles.md「最近登录」).
type Login struct {
	At     time.Time `json:"at"`
	Result string    `json:"result" enum:"succeeded,failed,locked"`
	Method string    `json:"method,omitempty" enum:"password,code,passkey,provider,totp,recovery_code" doc:"The first factor of a sign-in, or the step that failed; none for a lockout"`
	// TwoFactor is only for a sign-in.
	TwoFactor   bool       `json:"twoFactor,omitempty" doc:"The sign-in passed 两步验证 too"`
	Application string     `json:"application" doc:"Name of the Application, or its client_id when it has none or is gone"`
	IP          string     `json:"ip,omitempty"`
	UserAgent   string     `json:"userAgent,omitempty"`
	LockedUntil *time.Time `json:"lockedUntil,omitempty" doc:"When a lockout ends"`
}

type listLoginsOutput struct {
	Body struct {
		Logins      []Login `json:"logins" nullable:"false" doc:"The last 30 days, newest first, at most 50"`
		FailedCount int64   `json:"failedCount" doc:"Failed sign-ins in the last 30 days, all of them; lockouts not counted"`
	}
}

func (s *Service) listLogins(ctx context.Context, _ *struct{}) (*listLoginsOutput, error) {
	sub := callerOf(ctx).sub
	rows, err := s.q.UserLogins(ctx, sub)
	if err != nil {
		return nil, err
	}
	out := &listLoginsOutput{}
	if out.Body.FailedCount, err = s.q.UserLoginFailures(ctx, sub); err != nil {
		return nil, err
	}
	out.Body.Logins = []Login{}
	for _, r := range rows {
		out.Body.Logins = append(out.Body.Logins, login(r))
	}
	return out, nil
}

func login(r sqlc.UserLoginsRow) Login {
	var d struct {
		IP, UA, Method string
		AMR            []string
		Until          *time.Time
	}
	_ = json.Unmarshal(r.Detail, &d) // written by identity.Attempt; a field it lacks stays empty
	l := Login{At: r.At.Time, Application: r.Application, IP: d.IP, UserAgent: d.UA}
	switch r.Event {
	case "login.succeeded":
		l.Result = "succeeded"
		l.Method, l.TwoFactor = loginMethod(d.AMR)
	case "login.failed":
		l.Result, l.Method = "failed", d.Method
	default:
		l.Result, l.LockedUntil = "locked", d.Until
	}
	return l
}

// loginMethod is the first factor amr names, and whether 两步验证 followed
// it. A Passkey carries mfa by itself (passkey.AMR), so that is no 两步验证.
func loginMethod(amr []string) (method string, twoFactor bool) {
	if len(amr) == 0 {
		return "", false
	}
	switch amr[0] {
	case "pwd":
		method = "password"
	case "otp", "sms":
		method = "code"
	case "hwk", "swk":
		return "passkey", false
	case "fed":
		method = "provider"
	}
	return method, slices.Contains(amr, "mfa")
}
