// Package google is the Google Provider type: the generic OIDC flow
// (internal/provider/oidc) with Google's issuer and brand written in, so the
// admin only brings a client ID and secret
// (docs/spec/architecture.md#通用-oidc-provider-类型).
package google

import (
	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/oidc"
)

// Issuer is where Google's discovery and id_tokens are; tests point it at a
// fake.
var Issuer = "https://accounts.google.com"

func init() {
	provider.Register(oidc.Type(oidc.Options{
		Key:  "google",
		Name: "Google",
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "client_id", Label: "Client ID", Type: "text"}},
			{Field: channel.Field{Key: "client_secret", Label: "Client secret", Type: "text", Secret: true}},
		},
		Issuer:        func(map[string]string) (string, error) { return Issuer, nil },
		IssuerMatches: googleIssuer,
	}))
}

// googleIssuer accepts the two forms Google documents for the id_token's
// iss — with the scheme and without it — and nothing else.
func googleIssuer(configured, reported string, _ map[string]any) bool {
	return reported == configured || reported == "accounts.google.com"
}
