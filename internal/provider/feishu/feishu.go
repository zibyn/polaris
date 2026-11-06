// Package feishu is the Feishu and Lark Provider types, for an app the
// operator builds in its own tenant: authorization code + PKCE as in
// OAuth2, but no OIDC, a JSON token request, and the userinfo's user ID in
// data.union_id with success told by its code. Two differences too many for
// the generic OAuth2 presets (ADR 0013), so a package of its own
// (docs/spec/architecture.md#飞书--lark-provider-类型).
package feishu

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
	"github.com/zibyn/polaris/internal/provider/oauth2"
)

// Endpoints are where one of the two brands signs in.
type Endpoints struct{ Authorize, Token, Userinfo string }

// Feishu and Lark are the two brands' endpoints; tests point them at a
// fake. Lark has no v3 token endpoint, so it keeps v2; both take JSON.
var (
	Feishu = Endpoints{
		Authorize: "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		Token:     "https://accounts.feishu.cn/oauth/v3/token",
		Userinfo:  "https://open.feishu.cn/open-apis/authen/v1/user_info",
	}
	Lark = Endpoints{
		Authorize: "https://accounts.larksuite.com/open-apis/authen/v1/authorize",
		Token:     "https://open.larksuite.com/open-apis/authen/v2/oauth/token",
		Userinfo:  "https://open.larksuite.com/open-apis/authen/v1/user_info",
	}
)

func init() {
	register("feishu", "飞书", "使用飞书登录", "Sign in with Feishu", &Feishu)
	register("lark", "Lark", "使用 Lark 登录", "Sign in with Lark", &Lark)
}

// icon is Feishu's and Lark's bird.
const icon = `<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#00d6b9" d="M10 8c0 1 7 3.5 14.745 16.744 0 0 4.184-4.363 6.255-5.744 1.5-1 2.712-1.332 2.712-1.332C33.712 15.156 29.5 8 28 8z"/><path fill="#163c9a" d="M43.5 18.5c-1-.667-3.65-1.771-6.5-1.5a15 15 0 0 0-3.288.668S32.5 18 31 19c-2.07 1.38-6.255 5.744-6.255 5.744-1.428 1.397-3.05 2.732-5.245 3.756 0 0 7 3 11.5 3 5.063 0 7-3.5 7-3.5 1.5-3.305 3.5-7 5.5-9.5"/><path fill="#3370ff" d="M4 17.5v17c0 1 6 5.5 15 5.5 10 0 17.05-7.705 19-12 0 0-1.937 3.5-7 3.5-4.5 0-11.5-3-11.5-3-5.117-2.239-10.03-6.577-12.906-9.117C4.974 17.953 4 17.093 4 17.5"/></svg>`

// register adds a brand's type. Neither field is immutable: union_id is the
// same across one developer's apps, so another app keeps the identities.
func register(key, name, label, labelEN string, e *Endpoints) {
	provider.Register(provider.Type{
		Key: key, Name: name,
		// Lark keeps Feishu's bird and class.
		Button: &provider.LoginButton{Label: label, LabelEN: labelEN, Class: "feishu", Icon: icon},
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "client_id", Label: "App ID", Type: "text",
				Help: "企业自建应用的 App ID。仅本租户且在应用可用范围内的成员可登录，否则报错 20010。应用需开通 contact:user.employee:readonly(企业邮箱)与 contact:user.phone:readonly(手机号)两个权限，否则报错 20027"}},
			{Field: channel.Field{Key: "client_secret", Label: "App Secret", Type: "text", Secret: true}},
		},
		New: func(c map[string]string) (provider.Redirect, error) {
			return &upstream{name: name, endpoints: *e, clientID: c["client_id"], secret: c["client_secret"]}, nil
		},
	})
}

type upstream struct {
	name             string
	endpoints        Endpoints
	clientID, secret string
}

// NoReauthPrompt: Feishu's only prompt is consent, which shows the
// authorization page again but does not sign the User in afresh.
func (u *upstream) NoReauthPrompt() {}

// scope is what a new User brings besides the union_id, which needs none:
// the enterprise email and the phone number.
const scope = "contact:user.employee:readonly contact:user.phone:readonly"

func (u *upstream) AuthURL(_ context.Context, redirectURI, state, _, verifier string) (string, error) {
	return oauth2.AuthURL(u.endpoints.Authorize, u.clientID, scope, redirectURI, state, verifier), nil
}

// Callback exchanges the code and reads the union_id, and no other ID:
// open_id is per app, user_id per tenant. Of the emails only
// enterprise_email, a mailbox the tenant hosts: email is whatever an admin
// typed in.
func (u *upstream) Callback(ctx context.Context, params url.Values, redirectURI, _, verifier string) (provider.Identity, error) {
	if e := params.Get("error"); e != "" {
		return provider.Identity{}, fmt.Errorf("%s: %s", u.name, e)
	}
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     u.clientID,
		"client_secret": u.secret,
		"code":          params.Get("code"),
		"redirect_uri":  redirectURI,
		"code_verifier": verifier,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoints.Token, bytes.NewReader(body))
	if err != nil {
		return provider.Identity{}, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	var tok struct {
		Code             int    `json:"code"`
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	status, err := fetch(req, &tok)
	switch {
	case err != nil:
		return provider.Identity{}, fmt.Errorf("%s 换取 token: %w", u.name, err)
	case tok.Code != 0 || status != http.StatusOK:
		return provider.Identity{}, fmt.Errorf("%s 换取 token 失败(%d %s): %s", u.name, tok.Code, tok.Error, tok.ErrorDescription)
	case tok.AccessToken == "":
		return provider.Identity{}, fmt.Errorf("%s 换取 token: 没有 access_token", u.name)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.endpoints.Userinfo, nil)
	if err != nil {
		return provider.Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	var info struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			UnionID         string `json:"union_id"`
			Name            string `json:"name"`
			AvatarBig       string `json:"avatar_big"`
			EnterpriseEmail string `json:"enterprise_email"`
			Mobile          string `json:"mobile"`
		} `json:"data"`
	}
	if _, err := fetch(req, &info); err != nil {
		return provider.Identity{}, fmt.Errorf("%s 用户信息: %w", u.name, err)
	}
	switch info.Code {
	case 0:
	case 20021:
		return provider.Identity{}, fmt.Errorf("%s: 该成员已离职", u.name)
	case 20022:
		return provider.Identity{}, fmt.Errorf("%s: 该成员已被冻结", u.name)
	default:
		return provider.Identity{}, fmt.Errorf("%s 用户信息失败(%d): %s", u.name, info.Code, info.Msg)
	}
	if info.Data.UnionID == "" {
		return provider.Identity{}, errors.New(u.name + " 用户信息: 没有 union_id")
	}
	d := info.Data
	return provider.Identity{Subject: d.UnionID, Email: d.EnterpriseEmail, Phone: d.Mobile, Name: d.Name, Picture: d.AvatarBig}, nil
}

var client = &http.Client{Timeout: 10 * time.Second}

// fetch sends req and decodes its JSON answer into out whatever the status:
// Feishu says what went wrong in the body of a 400 too.
func fetch(req *http.Request, out any) (int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return 0, fmt.Errorf("%s: %.200s", resp.Status, body)
	}
	return resp.StatusCode, nil
}
