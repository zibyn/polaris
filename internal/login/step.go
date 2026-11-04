package login

import (
	"context"
	"encoding/json"
	"time"

	goidc "github.com/zibyn/polaris/internal/oidc/goidc"
)

// step is what still stands between a User past the first factor and a
// Session, in the order every login runs it (ADR 0016).
type step int

const (
	stepDone step = iota
	stepSetPassword
	stepTOTP
	stepPhone
	stepConsent
)

// nextStep reports what sub still has to do to get a Session: 待激活 first,
// then 两步验证, 同意协议 and 绑手机号. alreadySignedIn is a browser Session the
// User already had: it cannot belong to a 待激活 User and has passed 两步验证,
// so those two are skipped, while 同意协议 and 绑手机号 are still checked, as
// they always were for a Session that continues a login.
func (s *Service) nextStep(ctx context.Context, sub string, amr []string, alreadySignedIn bool) (step, error) {
	if !alreadySignedIn {
		pending, err := s.ids.Pending(ctx, sub)
		if err != nil {
			return stepDone, err
		}
		if pending {
			return stepSetPassword, nil
		}
		totp, err := s.needsTOTP(ctx, sub, amr)
		if err != nil {
			return stepDone, err
		}
		if totp {
			return stepTOTP, nil
		}
	}
	consent, err := s.q.NeedsConsent(ctx, sub)
	if err != nil {
		return stepDone, err
	}
	if consent {
		return stepConsent, nil
	}
	phone, err := s.q.NeedsPhone(ctx, sub)
	if err != nil {
		return stepDone, err
	}
	if phone {
		return stepPhone, nil
	}
	return stepDone, nil
}

// pendingLogin is a login past its first factor with a step still to take:
// the hosted page keeps it in the AuthnSession store, the direct auth API in
// its auth_session.
type pendingLogin struct {
	Sub      string   `json:"sub"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
	Method   string   `json:"method,omitempty"` // the login method (ADR 0027)
	// Session: the browser Session the User already had (hosted page only).
	Session string `json:"session,omitempty"`
	// TOTP: waiting for a TOTP code or a 恢复码, with Failures mistakes so far.
	TOTP     bool `json:"totp,omitempty"`
	Failures int  `json:"failures,omitempty"`
	// Password: 待激活, waiting for the User to replace the initial password
	// an admin set. Nothing else happens until they do (ADR 0016).
	Password bool `json:"password,omitempty"`
}

func newPending(sub string, authTime time.Time, amr []string, method string, what step) *pendingLogin {
	return &pendingLogin{Sub: sub, AuthTime: authTime.Unix(), AMR: amr, Method: method, TOTP: what == stepTOTP, Password: what == stepSetPassword}
}

func (p *pendingLogin) authTime() time.Time { return time.Unix(p.AuthTime, 0) }

// missed counts a wrong TOTP code or 恢复码, and reports whether that was
// the last of the totpTries the login has.
func (p *pendingLogin) missed() bool {
	p.Failures++
	return p.Failures >= totpTries
}

// pendingOf is the hosted page's pending login, or nil. The store comes back
// from JSON as plain maps, so it is decoded again.
func pendingOf(as *goidc.AuthnSession) *pendingLogin {
	v, ok := as.Store[storePending]
	if !ok {
		return nil
	}
	if p, ok := v.(*pendingLogin); ok {
		return p
	}
	b, err := json.Marshal(v)
	var p pendingLogin
	if err != nil || json.Unmarshal(b, &p) != nil || p.Sub == "" {
		return nil
	}
	return &p
}
