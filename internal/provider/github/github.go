// Package github is the GitHub Provider type: the generic OAuth2 flow
// (internal/provider/oauth2) with GitHub's endpoints, scope and user ID
// field written in, so the admin only brings a client ID and secret
// (ADR 0013).
package github

import (
	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
	"github.com/zibyn/polaris/internal/provider/oauth2"
)

// Endpoint is where GitHub's OAuth endpoints live and API where its user
// API is: two hosts, so the userinfo is not under Endpoint. Tests point
// both at a fake.
var (
	Endpoint = "https://github.com"
	API      = "https://api.github.com"
)

func init() {
	provider.Register(oauth2.Type(oauth2.Options{
		Key:  "github",
		Name: "GitHub",
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "client_id", Label: "Client ID", Type: "text"}},
			{Field: channel.Field{Key: "client_secret", Label: "Client secret", Type: "text", Secret: true}},
		},
		Presets: func() map[string]string {
			return map[string]string{
				"authorization_endpoint": Endpoint + "/login/oauth/authorize",
				"token_endpoint":         Endpoint + "/login/oauth/access_token",
				"userinfo_endpoint":      API + "/user",
				// read:user is the profile the numeric id comes in;
				// user:email is not asked for, the email is dropped anyway.
				"scope": "read:user",
				// The login is the user's to rename, so it is not the
				// anchor: the id never changes.
				"user_id_field": "id",
			}
		},
	}))
}
