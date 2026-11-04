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
	register("feishu", "飞书", &Feishu)
	register("lark", "Lark", &Lark)
}

// register adds a brand's type. Neither field is immutable: union_id is the
// same across one developer's apps, so another app keeps the identities.
func register(key, name string, e *Endpoints) {
	provider.Register(provider.Type{
		Key: key, Name: name,
		Fields: []provider.ConfigField{
			{Field: channel.Field{Key: "client_id", Label: "App ID", Type: "text",
				Help: "企业自建应用的 App ID。仅本租户且在应用可用范围内的成员可登录，否则报错 20010"}},
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

// AuthURL asks for no scope: the union_id needs none.
func (u *upstream) AuthURL(_ context.Context, redirectURI, state, _, verifier string) (string, error) {
	return oauth2.AuthURL(u.endpoints.Authorize, u.clientID, "", redirectURI, state, verifier), nil
}

// Callback exchanges the code and reads the union_id, and no other ID:
// open_id is per app, user_id per tenant.
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
			UnionID string `json:"union_id"`
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
	return provider.Identity{Subject: info.Data.UnionID}, nil
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
