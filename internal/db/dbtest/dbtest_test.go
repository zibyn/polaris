package dbtest

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Postgres cuts names at 63 bytes; two long tests differing past that must
// still get their own database.
func TestDBNameStaysUniqueWithin63Bytes(t *testing.T) {
	short := "t_login_TestSignIn"
	if got := dbName(short); got != short {
		t.Errorf("short name changed: %q", got)
	}
	prefix := "t_login_TestExpiredSessionSendsNothing/闲置很久的_Session_被清理"
	a, b := dbName(prefix+"_一"), dbName(prefix+"_二")
	for _, n := range []string{a, b} {
		if len(n) > 63 || !utf8.ValidString(n) || !strings.HasPrefix(n, "t_login_TestExpiredSession") {
			t.Errorf("%q: %d bytes", n, len(n))
		}
	}
	if a == b {
		t.Errorf("collide: %q", a)
	}
}
