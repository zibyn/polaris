package login

import (
	"context"
	"slices"

	"github.com/zibyn/polaris/internal/db/sqlc"
	"github.com/zibyn/polaris/internal/identity"
)

// Login methods, in the terms of applications.login_methods and
// sessions.login_method (ADR 0027); a Provider is providerMethod(id).
const (
	methodSMS      = "sms"
	methodEmail    = "email"
	methodPassword = "password"
	methodPasskey  = "passkey"
)

func providerMethod(id string) string { return "provider:" + id }

// codeMethod is the login method a code to an Identifier of kind is.
func codeMethod(kind string) string {
	if kind == "email" {
		return methodEmail
	}
	return methodSMS
}

// methods are the login methods open on one Application: the hosted page and
// the direct auth API both ask here.
type methods sqlc.LoginMethodsRow

func (s *Service) methods(ctx context.Context, clientID string) (methods, error) {
	m, err := s.q.LoginMethods(ctx, clientID)
	return methods(m), err
}

// allows reports whether method may sign in to the Application. One that
// follows the instance leaves that to each method's own switch, as it
// always did.
func (m methods) allows(method string) bool { return !m.Own || slices.Contains(m.Open, method) }

// none reports whether the Application's own set and the instance's have
// nothing in common: nobody can sign in to it.
func (m methods) none() bool { return m.Own && len(m.Open) == 0 }

var errMethodNotAllowed = identity.Invalid("该应用不支持这种登录方式")

const errNoMethod = "该应用没有可用的登录方式，请联系管理员"
