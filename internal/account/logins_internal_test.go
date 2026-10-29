package account

import "testing"

// A login's amr comes out as its first factor and whether 两步验证 followed.
func TestLoginMethod(t *testing.T) {
	for _, c := range []struct {
		amr       []string
		method    string
		twoFactor bool
	}{
		{[]string{"pwd"}, "password", false},
		{[]string{"otp"}, "code", false},
		{[]string{"sms"}, "code", false},
		{[]string{"hwk", "mfa"}, "passkey", false},
		{[]string{"swk", "mfa"}, "passkey", false},
		{[]string{"fed"}, "provider", false},
		{[]string{"pwd", "otp", "mfa"}, "password", true},
		{[]string{"otp", "mfa"}, "code", true},
		{[]string{"fed", "otp", "mfa"}, "provider", true},
	} {
		method, twoFactor := loginMethod(c.amr)
		if method != c.method || twoFactor != c.twoFactor {
			t.Errorf("%v: %q %v, want %q %v", c.amr, method, twoFactor, c.method, c.twoFactor)
		}
	}
}
