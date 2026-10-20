// Package microsoft is the Microsoft Provider type: the generic OIDC flow
// (internal/provider/oidc) with Microsoft's endpoints written in and the
// issuer built from the tenant the admin picks (ADR 0013).
package microsoft

import (
	"errors"
	"regexp"
	"strings"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/oidc"
)

// Endpoint is where Microsoft's endpoints live; tests point it at a fake.
// The tenant goes between it and /v2.0.
var Endpoint = "https://login.microsoftonline.com"

// tenantID is a tenant GUID, as Microsoft writes it.
var tenantID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// template is the tenant discovery reports for common and organizations:
// it is filled in per user, so it is not the issuer signing in.
const template = "{tenantid}"

func init() {
	provider.Register(oidc.Type(oidc.Options{
		Key:  "microsoft",
		Name: "Microsoft",
		Fields: []provider.ConfigField{
			// Which tenants may sign in, and so which tenant their
			// External Identities belong to: never changed after adding.
			{Field: channel.Field{Key: "tenant", Label: "租户", Type: "text",
				Help: "common、organizations 或租户 GUID"}, Immutable: true},
			{Field: channel.Field{Key: "client_id", Label: "Client ID", Type: "text"}},
			{Field: channel.Field{Key: "client_secret", Label: "Client secret", Type: "text", Secret: true}},
		},
		Issuer: func(c map[string]string) (string, error) {
			t := c["tenant"]
			if !isAlias(t) && !tenantID.MatchString(t) {
				return "", errors.New("租户须为 common、organizations 或租户 GUID")
			}
			return Endpoint + "/" + t + "/v2.0", nil
		},
		IssuerMatches: microsoftIssuer,
	}))
}

// isAlias is a tenant several tenants sign in through.
func isAlias(tenant string) bool { return tenant == "common" || tenant == "organizations" }

// microsoftIssuer accepts the issuer a Microsoft endpoint reports for the
// configured tenant. common and organizations let any tenant sign in, so
// there discovery's {tenantid} template is taken, and any other issuer only
// when its tenant GUID is the id_token's tid — the shape alone would take a
// token any tenant signed (ADR 0013). A tenant GUID is reported back as the
// tenant writes it.
func microsoftIssuer(configured, reported string, claims map[string]any) bool {
	tenant, ok := strings.CutPrefix(configured, Endpoint+"/")
	if !ok {
		return false
	}
	if tenant, ok = strings.CutSuffix(tenant, "/v2.0"); !ok {
		return false
	}
	if !isAlias(tenant) {
		return strings.EqualFold(configured, reported)
	}
	signed := tenantOf(reported)
	if claims == nil { // discovery, and the callback's iss: no id_token to anchor with yet
		return reported == Endpoint+"/"+template+"/v2.0" || signed != ""
	}
	tid, _ := claims["tid"].(string)
	return signed != "" && strings.EqualFold(tid, signed)
}

// tenantOf is the tenant GUID an issuer names, "" for anything else.
func tenantOf(issuer string) string {
	id, ok := strings.CutPrefix(issuer, Endpoint+"/")
	if !ok {
		return ""
	}
	if id, ok = strings.CutSuffix(id, "/v2.0"); !ok || !tenantID.MatchString(id) {
		return ""
	}
	return id
}
