// Package oauth2 is the generic OAuth2 Provider type: any upstream without
// discovery and without an id_token, signed in to by authorization code +
// PKCE, its identity read from the userinfo the access token opens
// (docs/spec/architecture.md#通用-oauth2-provider-类型). GitHub is the named
// provider built on the same implementation through Type (ADR 0013).
package oauth2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
)

func init() {
	provider.Register(Type(Options{
		Key:  "oauth2",
		Name: "通用 OAuth2",
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "authorization_endpoint", Label: "Authorization endpoint", Type: "url"}},
			{Field: channel.Field{Key: "token_endpoint", Label: "Token endpoint", Type: "url"}},
			{Field: channel.Field{Key: "userinfo_endpoint", Label: "Userinfo endpoint", Type: "url"}},
			{Field: channel.Field{Key: "scope", Label: "Scope", Type: "text", Optional: true,
				Help: "按服务商要求填写,多个以空格分隔"}},
			{Field: channel.Field{Key: "client_id", Label: "Client ID", Type: "text"}},
			{Field: channel.Field{Key: "client_secret", Label: "Client secret", Type: "text", Secret: true}},
			// The anchor: which External Identity a login is, so a field the
			// upstream may change must not be it.
			{Field: channel.Field{Key: "user_id_field", Label: "用户 ID 字段", Type: "text",
				Help: "userinfo 顶层表示用户 ID 的字段,例如 GitHub 的数字 id。填上游会变的字段(如 login)的话,用户一改名就变成另一个人"},
				Immutable: true},
		},
	}))
}

// Options describe a Provider type that signs in with the generic OAuth2
// flow: what the admin is asked for, and any settings written into the type.
type Options struct {
	Key, Name string
	Fields    []provider.ConfigField
	// Presets are settings written into the type rather than asked of the
	// admin: a named provider's endpoints, scope and user ID field. Read
	// per New, so a test can move the endpoint.
	Presets func() map[string]string
}

// Type builds the Provider type the Options describe.
func Type(o Options) provider.Type {
	return provider.Type{
		Key: o.Key, Name: o.Name, Fields: o.Fields,
		New: func(c map[string]string) (provider.Redirect, error) {
			if o.Presets != nil {
				for k, v := range o.Presets() {
					c[k] = v
				}
			}
			return &upstream{
				authorizationEndpoint: c["authorization_endpoint"],
				tokenEndpoint:         c["token_endpoint"],
				userinfoEndpoint:      c["userinfo_endpoint"],
				scope:                 c["scope"],
				clientID:              c["client_id"],
				secret:                c["client_secret"],
				userIDField:           c["user_id_field"],
			}, nil
		},
	}
}

// upstream is an OAuth2 Provider. There is no id_token and no discovery:
// every setting is the admin's, and the userinfo the access token opens is
// the only thing that says who signed in.
type upstream struct {
	authorizationEndpoint, tokenEndpoint, userinfoEndpoint string
	scope, clientID, secret, userIDField                   string
}

// NoReauthPrompt: a standard OAuth2 upstream has no prompt=login and no
// max_age to ask it for, so a reauthentication through one carries neither
// and only proves the External Identity is still signed in there (ADR 0013).
func (u *upstream) NoReauthPrompt() {}

// AuthURL sends the browser to the authorization endpoint with PKCE. No
// nonce: there is no id_token to carry one, and state and PKCE guard the
// code without it.
func (u *upstream) AuthURL(_ context.Context, redirectURI, state, _, verifier string) (string, error) {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {u.clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if u.scope != "" {
		q.Set("scope", u.scope)
	}
	sep := "?"
	if strings.Contains(u.authorizationEndpoint, "?") {
		sep = "&"
	}
	return u.authorizationEndpoint + sep + q.Encode(), nil
}

// Callback exchanges the code and asks the upstream who it was, which is
// all there is: the answer comes back over TLS from the endpoint the admin
// configured, with no signature of the upstream's on it (ADR 0013).
func (u *upstream) Callback(ctx context.Context, params url.Values, redirectURI, _, verifier string) (provider.Identity, error) {
	if e := params.Get("error"); e != "" {
		return provider.Identity{}, fmt.Errorf("oauth2: %s", e)
	}
	access, err := u.exchange(ctx, params.Get("code"), redirectURI, verifier)
	if err != nil {
		return provider.Identity{}, err
	}
	subject, err := u.subject(ctx, access)
	if err != nil {
		return provider.Identity{}, err
	}
	return provider.Identity{Subject: subject}, nil
}

// exchange trades the code for an access token. The client authenticates
// with client_secret_post: with no discovery there is no saying which way
// the endpoint wants (ADR 0013).
func (u *upstream) exchange(ctx context.Context, code, redirectURI, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {u.clientID},
		"client_secret": {u.secret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := fetch(req, &tok); err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("token endpoint: no access_token")
	}
	return tok.AccessToken, nil
}

// subject is the User's ID at the upstream: the field the admin named, and
// no other. Falling back to another one would sign somebody in as whoever
// that field says (ADR 0013).
func (u *upstream) subject(ctx context.Context, access string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.userinfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	var info map[string]any
	if err := fetch(req, &info); err != nil {
		return "", fmt.Errorf("userinfo: %w", err)
	}
	v, ok := info[u.userIDField]
	if !ok {
		return "", fmt.Errorf("userinfo 没有 %q 字段:检查这个 Provider 的用户 ID 字段", u.userIDField)
	}
	switch v := v.(type) {
	case string:
		if v != "" {
			return v, nil
		}
	case json.Number:
		return v.String(), nil
	}
	return "", fmt.Errorf("userinfo 的 %q 不是用户 ID:须为字符串或数字", u.userIDField)
}

var client = &http.Client{Timeout: 10 * time.Second}

// fetch sends req and decodes a 200 JSON answer into out. Numbers are kept
// as written: an ID they were rounded would name nobody.
func fetch(req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %.200s", resp.Status, body)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(out)
}
