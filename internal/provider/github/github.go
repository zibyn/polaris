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
		// GitHub allows its mark in black on a light button; the wording is ours.
		Button: &provider.LoginButton{Label: "使用 GitHub 登录", LabelEN: "Sign in with GitHub",
			Icon: `<svg viewBox="0 0 16 16" aria-hidden="true" style="fill:#181717"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>`},
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
