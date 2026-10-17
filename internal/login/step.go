package login

import "context"

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
