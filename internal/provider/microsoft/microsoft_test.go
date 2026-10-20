package microsoft_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/microsoft"
	"github.com/zibyn/polaris/internal/provider/oidc/oidctest"
)

// Two tenants, as Microsoft writes them.
const (
	tenant1 = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
	tenant2 = "9f8e7d6c-5b4a-3210-fedc-ba9876543210"
)

// fakeMicrosoft points the Microsoft type at a fake upstream: Microsoft's
// endpoints are written into the type, so a test moves the endpoint.
func fakeMicrosoft(t *testing.T) *oidctest.Issuer {
	t.Helper()
	up := oidctest.Start(t)
	microsoft.Endpoint = up.URL
	t.Cleanup(func() { microsoft.Endpoint = "https://login.microsoftonline.com" })
	return up
}

func newMicrosoft(t *testing.T, tenant string) provider.Redirect {
	t.Helper()
	p, err := provider.GetType("microsoft").New(map[string]string{"tenant": tenant, "client_id": "cid", "client_secret": "shh"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestMicrosoftTakesDiscoveryTemplate covers the spike's finding: discovery
// for common reports the tenant template, not the configured issuer.
func TestMicrosoftTakesDiscoveryTemplate(t *testing.T) {
	up := fakeMicrosoft(t)
	up.Reported = up.URL + "/{tenantid}/v2.0"
	if _, err := newMicrosoft(t, "common").AuthURL(context.Background(), "https://auth.example/cb", "st", "n", "verifier"); err != nil {
		t.Fatalf("common discovery: %v", err)
	}
}

// TestMicrosoftCommonAnchorsTheIssuerToTheToken covers the aliases common
// and organizations: any tenant may sign in, but its id_token's iss must
// name the tenant its tid claim does (ADR 0013).
func TestMicrosoftCommonAnchorsTheIssuerToTheToken(t *testing.T) {
	for name, tc := range map[string]struct {
		reported func(base string) string // what discovery and the id_token name
		tid      string                   // the id_token's tid claim
		signIn   bool
	}{
		"the token's own tenant": {reported: tenantIssuer(tenant1), tid: tenant1, signIn: true},
		"a second tenant":        {reported: tenantIssuer(tenant2), tid: tenant2, signIn: true},
		"tid of another tenant":  {reported: tenantIssuer(tenant1), tid: tenant2},
		"no tid":                 {reported: tenantIssuer(tenant1)},
		"the discovery template": {reported: template, tid: tenant1},
		"not a tenant issuer":    {reported: func(string) string { return "https://evil.example/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9/v2.0" }, tid: tenant1},
	} {
		t.Run(name, func(t *testing.T) {
			up := fakeMicrosoft(t) // discovery is remembered per issuer: one fake per case
			up.Reported = tc.reported(up.URL)
			up.Claims = map[string]any{"tid": tc.tid}
			id, err := newMicrosoft(t, "common").Callback(context.Background(),
				url.Values{"code": {"good"}}, "https://auth.example/cb", "n", "verifier")
			oidctest.CheckSignIn(t, id, err, tc.signIn)
		})
	}
}

// TestMicrosoftConcreteTenantIsStrict: the tenant GUID is the issuer, as the
// tenant writes it, and nothing else is.
func TestMicrosoftConcreteTenantIsStrict(t *testing.T) {
	for name, tc := range map[string]struct {
		tenant   string // as the admin typed it
		reported func(base string) string
		signIn   bool
	}{
		"its own tenant": {tenant: tenant1, reported: tenantIssuer(tenant1), signIn: true},
		"uppercase, as an admin may type it": {
			tenant: strings.ToUpper(tenant1), reported: tenantIssuer(tenant1), signIn: true},
		"another tenant": {tenant: tenant1, reported: tenantIssuer(tenant2)},
		"a template":     {tenant: tenant1, reported: template},
	} {
		t.Run(name, func(t *testing.T) {
			up := fakeMicrosoft(t)
			up.Reported = tc.reported(up.URL)
			up.Claims = map[string]any{"tid": tenant1}
			id, err := newMicrosoft(t, tc.tenant).Callback(context.Background(),
				url.Values{"code": {"good"}}, "https://auth.example/cb", "n", "verifier")
			oidctest.CheckSignIn(t, id, err, tc.signIn)
		})
	}
}

// TestMicrosoftTenantMustBeOne: the tenant anchors the External Identities,
// and only the aliases common and organizations anchor a working issuer.
// consumers is not one of them: its discovery reports the consumer tenant's
// own GUID, which the strict comparison would refuse.
func TestMicrosoftTenantMustBeOne(t *testing.T) {
	for _, tenant := range []string{"", "contoso.onmicrosoft.com", "consumers", "common/../evil"} {
		if _, err := provider.GetType("microsoft").New(map[string]string{
			"tenant": tenant, "client_id": "cid", "client_secret": "shh"}); err == nil {
			t.Errorf("accepted tenant %q", tenant)
		}
	}
}

// tenantIssuer is the issuer a tenant's endpoints report.
func tenantIssuer(tenant string) func(base string) string {
	return func(base string) string { return base + "/" + tenant + "/v2.0" }
}

// template is the issuer discovery reports for the aliases.
func template(base string) string { return base + "/{tenantid}/v2.0" }
