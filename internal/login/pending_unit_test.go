package login

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/zibyn/polaris/internal/oidc/goidc"
)

// The hosted page's pending login survives the AuthnSession store's trip
// through JSON, failures included.
func TestPendingOfRoundTrip(t *testing.T) {
	p := newPending("u1", time.Unix(100, 0), []string{"pwd"}, "password", stepTOTP)
	p.Session = "s1"
	if p.missed() {
		t.Fatal("first miss ended the login")
	}
	b, err := json.Marshal(map[string]any{storePending: p})
	if err != nil {
		t.Fatal(err)
	}
	as := &goidc.AuthnSession{}
	if err := json.Unmarshal(b, &as.Store); err != nil {
		t.Fatal(err)
	}
	got := pendingOf(as)
	if got == nil || got.Sub != "u1" || got.Session != "s1" || !got.TOTP || got.Password || got.Failures != 1 ||
		!got.authTime().Equal(time.Unix(100, 0)) || !slices.Equal(got.AMR, []string{"pwd"}) || got.Method != "password" {
		t.Fatalf("pendingOf = %+v", got)
	}
	for range totpTries - 2 {
		if got.missed() {
			t.Fatal("ended before totpTries")
		}
	}
	if !got.missed() {
		t.Fatal("totpTries misses did not end the login")
	}
	if pendingOf(&goidc.AuthnSession{Store: map[string]any{"other": 1}}) != nil {
		t.Fatal("pending without one")
	}
}
