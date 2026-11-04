package identity

import "strings"

// Login methods (登录方式), in the terms of applications.login_methods and
// sessions.login_method (ADR 0027); a Provider is ProviderMethod(id).
const (
	MethodSMS      = "sms"
	MethodEmail    = "email"
	MethodPassword = "password"
	MethodPasskey  = "passkey"
)

const providerPrefix = "provider:"

// ProviderMethod is the login method of the Provider id.
func ProviderMethod(id string) string { return providerPrefix + id }

// MethodProvider is the Provider id of method, if it is a Provider's.
func MethodProvider(method string) (id string, ok bool) {
	return strings.CutPrefix(method, providerPrefix)
}

// CodeMethod is the login method a code to an Identifier of kind is.
func CodeMethod(kind string) string {
	if kind == "email" {
		return MethodEmail
	}
	return MethodSMS
}
