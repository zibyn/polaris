package login

import (
	"context"
	"slices"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

// methods are the login methods open on one Application (ADR 0027): the
// hosted page and the direct auth API both ask here, and nowhere else reads
// the instance's switches to decide what a login may use.
type methods sqlc.LoginMethodsRow

func (s *Service) methods(ctx context.Context, clientID string) (methods, error) {
	m, err := s.q.LoginMethods(ctx, clientID)
	return methods(m), err
}

// offers reports whether a login may use method now: the instance has it on
// and the Application, unless it follows the instance, names it.
func (m methods) offers(method string) bool { return slices.Contains(m.Open, method) }

// admits reports whether method is within the Application's own set; one
// that follows the instance admits any. A Session (单点登录) is checked this
// way, as turning a method off later does not end the Sessions it made; so is
// the direct auth API, whose methods report their own instance switch.
func (m methods) admits(method string) bool { return !m.Own || m.offers(method) }

// none reports whether the Application's own set and the instance's have
// nothing in common: nobody can sign in to it.
func (m methods) none() bool { return m.Own && len(m.Open) == 0 }

var errMethodNotAllowed = identity.Invalid("该应用不支持这种登录方式")

const errNoMethod = "该应用没有可用的登录方式，请联系管理员"
