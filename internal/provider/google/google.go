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
		// Google's light theme: the colour G, never a monochrome one, and its own wording.
		Button: &provider.LoginButton{Label: "使用 Google 账号登录", LabelEN: "Sign in with Google",
			// #747775 hairline, #1F1F1F text, and Google's own 10px logo-to-text spacing.
			Style: "border-color:#747775;color:#1f1f1f;gap:10px",
			Icon:  `<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24s.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`},
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
