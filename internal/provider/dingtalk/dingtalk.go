// Package dingtalk is the DingTalk Provider type, for an internal app the
// operator builds in its own organization, signed in to by DingTalk's
// "login to a third-party website" flow. OAuth2 in shape only: a required
// prompt, a camelCase JSON token request, the access token in a header of
// its own, no PKCE and no OIDC, so a package of its own
// (docs/spec/architecture.md#钉钉-provider-类型).
//
// The code is bound to neither the redirect URI nor a PKCE verifier: the
// token request carries neither. What guards it is state, checked by the
// store, and DingTalk using each code once.
package dingtalk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
)

// Login is where the browser signs in and API where the code is exchanged
// and the User read; tests point both at a fake.
var (
	Login = "https://login.dingtalk.com"
	API   = "https://api.dingtalk.com"
	// OAPI is the older API that the organization's directory is still read at.
	OAPI = "https://oapi.dingtalk.com"
)

func init() {
	provider.Register(provider.Type{
		Key:  "dingtalk",
		Name: "钉钉",
		// Neither is immutable: the unionId is the same across one
		// developer organization's apps.
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "client_id", Label: "Client ID(AppKey)", Type: "text",
				Help: "企业内部应用的 AppKey。应用需开通 Contact.User.Read、成员信息读权限和企业员工手机号信息权限，并将回调 URL 添加为重定向 URL。仅本组织成员可登录"}},
			{Field: channel.Field{Key: "client_secret", Label: "Client Secret(AppSecret)", Type: "text", Secret: true}},
		},
		New: func(c map[string]string) (provider.Redirect, error) {
			return &upstream{clientID: c["client_id"], secret: c["client_secret"]}, nil
		},
	})
}

type upstream struct{ clientID, secret string }

// NoReauthPrompt: DingTalk's only prompt is consent, and it has no max_age.
func (u *upstream) NoReauthPrompt() {}

// AuthURL carries the prompt DingTalk requires, and no PKCE: DingTalk has
// none, and what it does with one sent anyway is unknown.
func (u *upstream) AuthURL(_ context.Context, redirectURI, state, _, _ string) (string, error) {
	return Login + "/oauth2/auth?" + url.Values{
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"client_id":     {u.clientID},
		"scope":         {"openid"},
		"prompt":        {"consent"},
		"state":         {state},
	}.Encode(), nil
}

// Callback exchanges the code and reads the unionId, and not the openId,
// which is per app.
func (u *upstream) Callback(ctx context.Context, params url.Values, _, _, _ string) (provider.Identity, error) {
	if e := params.Get("error"); e != "" {
		return provider.Identity{}, fmt.Errorf("钉钉: %s", e)
	}
	// DingTalk's two pages disagree on the name; the newer says both come.
	code := params.Get("authCode")
	if code == "" {
		code = params.Get("code")
	}
	body, _ := json.Marshal(map[string]string{
		"clientId": u.clientID, "clientSecret": u.secret, "code": code, "grantType": "authorization_code",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, API+"/v1.0/oauth2/userAccessToken", bytes.NewReader(body))
	if err != nil {
		return provider.Identity{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := fetch(req, &tok); err != nil {
		return provider.Identity{}, fmt.Errorf("钉钉换取 token: %w", err)
	}
	if tok.AccessToken == "" {
		return provider.Identity{}, errors.New("钉钉换取 token: 没有 accessToken")
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, API+"/v1.0/contact/users/me", nil)
	if err != nil {
		return provider.Identity{}, err
	}
	req.Header.Set("x-acs-dingtalk-access-token", tok.AccessToken)
	var me struct {
		UnionID string `json:"unionId"`
	}
	if err := fetch(req, &me); err != nil {
		return provider.Identity{}, fmt.Errorf("钉钉用户信息: %w", err)
	}
	if me.UnionID == "" {
		return provider.Identity{}, errors.New("钉钉用户信息: 没有 unionId")
	}
	return provider.Identity{Subject: me.UnionID}, nil
}

// Profile reads the member's entry in the organization's directory with the
// app's own token: the name, org_email and phone there, not the account's
// nickname and personal email users/me has. org_email is a mailbox the
// organization hosts; the employee email beside it is whatever an admin
// typed in.
func (u *upstream) Profile(ctx context.Context, id provider.Identity) (provider.Identity, error) {
	body, _ := json.Marshal(map[string]string{"appKey": u.clientID, "appSecret": u.secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, API+"/v1.0/oauth2/accessToken", bytes.NewReader(body))
	if err != nil {
		return id, err
	}
	req.Header.Set("Content-Type", "application/json")
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := fetch(req, &tok); err != nil {
		return id, fmt.Errorf("钉钉应用 token: %w", err)
	}
	var member struct {
		oapiReply
		Result struct {
			UserID string `json:"userid"`
		} `json:"result"`
	}
	if err := oapi(ctx, "/topapi/user/getbyunionid", tok.AccessToken, map[string]string{"unionid": id.Subject}, &member); err != nil {
		return id, fmt.Errorf("钉钉成员: %w", err)
	}
	var user struct {
		oapiReply
		Result struct {
			Name      string `json:"name"`
			Avatar    string `json:"avatar"`
			OrgEmail  string `json:"org_email"`
			Mobile    string `json:"mobile"`
			StateCode string `json:"state_code"`
		} `json:"result"`
	}
	if err := oapi(ctx, "/topapi/v2/user/get", tok.AccessToken, map[string]string{"userid": member.Result.UserID}, &user); err != nil {
		return id, fmt.Errorf("钉钉成员信息: %w", err)
	}
	r := user.Result
	id.Name, id.Picture, id.Email = r.Name, r.Avatar, r.OrgEmail
	if r.StateCode == "" || r.StateCode == "86" { // mobile carries no country code
		id.Phone = r.Mobile
	}
	return id, nil
}

// oapiReply is how every oapi answer says it failed, over HTTP 200.
type oapiReply struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// oapi posts body as JSON to an oapi path with the app's token and decodes
// a successful answer into out, which embeds oapiReply.
func oapi(ctx context.Context, path, token string, body any, out interface{ reply() oapiReply }) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OAPI+path+"?"+url.Values{"access_token": {token}}.Encode(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := fetch(req, out); err != nil {
		var ue *url.Error // the URL carries the token: keep it out of the error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return err
	}
	if r := out.reply(); r.ErrCode != 0 {
		return fmt.Errorf("%s(%d)", r.ErrMsg, r.ErrCode)
	}
	return nil
}

func (r oapiReply) reply() oapiReply { return r }

var client = &http.Client{Timeout: 10 * time.Second}

// fetch sends req and decodes a 200 JSON answer into out; anything else
// is an error carrying DingTalk's {code, message}.
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
		var e struct{ Code, Message string }
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			return fmt.Errorf("%s(%s)", e.Message, e.Code)
		}
		return fmt.Errorf("%s: %.200s", resp.Status, body)
	}
	return json.Unmarshal(body, out)
}
