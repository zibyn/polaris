package login

import (
	"context"

	"github.com/zibyn/polaris/internal/identity"
	"github.com/zibyn/polaris/internal/twofactor"
)

// errNotOffered is a code factor the second step of this login does not
// offer: not added, its Channel gone, or the first factor's own channel.
const errNotOffered identity.Invalid = "这次登录不能用这种方式完成两步验证"

// sendSecondFactorCode sends sub the second step's code by f, from ip: only
// when asked, within the send limits login codes count toward too.
func (s *Service) sendSecondFactorCode(ctx context.Context, sub string, amr []string, f twofactor.Factor, ip string) error {
	to, err := s.twoFactor.OfferedCodeTo(ctx, sub, amr, f, errNotOffered)
	if err != nil {
		return err
	}
	return s.codes.Send(ctx, f.Kind(), to, ip)
}

// checkSecondFactorCode checks code against the one sent by f. Run it in
// identity's SecondFactor with method "code" (what login.failed and the
// account center's 最近登录 know), which locks out and audits: a wrong one
// counts as a wrong TOTP code does.
func (s *Service) checkSecondFactorCode(ctx context.Context, sub string, amr []string, f twofactor.Factor, code string) error {
	to, err := s.twoFactor.OfferedCodeTo(ctx, sub, amr, f, errNotOffered)
	if err != nil {
		return err
	}
	return s.codes.Check(ctx, to, code)
}

// codeFactors are the second step's code factors, with where each sends to
// as the page shows it.
func (s *Service) codeFactors(ctx context.Context, sub string, offered []twofactor.Factor) ([]codeFactor, error) {
	var out []codeFactor
	for _, f := range offered {
		if f.Kind() == "" {
			continue
		}
		to, err := s.twoFactor.CodeTo(ctx, sub, f)
		if err != nil {
			return nil, err
		}
		out = append(out, codeFactor{Factor: string(f), To: identity.Mask(f.Kind(), to)})
	}
	return out, nil
}

// codeFactor is a code factor on the 两步验证 step: 发送验证码到 To.
type codeFactor struct{ Factor, To string }
