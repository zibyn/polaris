package login

import "testing"

// A follow-instance Application admits any Session but offers only what the
// instance has on; one with its own set does both only within it.
func TestMethodsOffersAdmits(t *testing.T) {
	follow := methods{Open: []string{"sms"}}
	own := methods{Open: []string{"sms"}, Own: true}
	for _, c := range []struct {
		m              methods
		method         string
		offers, admits bool
	}{
		{follow, "sms", true, true},
		{follow, "password", false, true},
		{own, "sms", true, true},
		{own, "password", false, false},
	} {
		if c.m.offers(c.method) != c.offers || c.m.admits(c.method) != c.admits {
			t.Errorf("%+v %s: offers %v admits %v", c.m, c.method, c.m.offers(c.method), c.m.admits(c.method))
		}
	}
	if follow.none() || !(methods{Own: true}).none() {
		t.Error("none")
	}
}
