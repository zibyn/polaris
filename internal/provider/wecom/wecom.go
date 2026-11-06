// Package wecom is the WeCom (企业微信) Provider type, for an app the
// operator builds in its own corp, signed in to by WeCom's web login (QR
// code or the desktop client). Not OAuth2: the code is not exchanged for a
// User's token but read, with the app's own access token, into the
// member's userid. No PKCE, nonce, prompt or id_token
// (docs/spec/architecture.md#企业微信-provider-类型).
package wecom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zibyn/polaris/internal/channel"
	"github.com/zibyn/polaris/internal/provider"
)

// Login is where the browser signs in and API where the code is read;
// tests point both at a fake.
var (
	Login = "https://login.work.weixin.qq.com"
	API   = "https://qyapi.weixin.qq.com"
)

func init() {
	provider.Register(provider.Type{
		Key:  "wecom",
		Name: "企业微信",
		// WeCom's mark in its own colours.
		Button: &provider.LoginButton{Label: "使用企业微信登录", LabelEN: "Sign in with WeCom", Class: "wecom",
			Icon: `<svg viewBox="5 5 36 36" aria-hidden="true"><path fill="#fb6500" d="M28.856 31.647a.483.483 0 0 0 .06.738 6.2 6.2 0 0 1 1.911 3.725 2.02 2.02 0 1 0 2.16-2.54 6.2 6.2 0 0 1-3.448-1.922.483.483 0 0 0-.683-.001"/><path fill="#0082ef" d="M37.057 28.448a2 2 0 0 0-.58 1.215 6.2 6.2 0 0 1-1.918 3.454.484.484 0 1 0 .738.616 6.2 6.2 0 0 1 3.725-1.91 2.02 2.02 0 1 0-1.96-3.376z"/><path fill="#2dbc00" d="M31.366 22.75a2.02 2.02 0 0 0 1.215 3.435 6.2 6.2 0 0 1 3.454 1.918.483.483 0 0 0 .829-.27.48.48 0 0 0-.212-.468 6.2 6.2 0 0 1-1.911-3.726 2.02 2.02 0 0 0-3.375-.889"/><path fill="#fc0" d="m30.374 25.907-.037.037a6.2 6.2 0 0 1-3.78 1.978 2.007 2.007 0 0 0-.895 3.374 2.02 2.02 0 0 0 3.435-1.216 6.2 6.2 0 0 1 1.923-3.453.484.484 0 0 0-.646-.72"/><path fill="#0082ef" d="M18.17 8.471c-3.624.4-6.908 1.948-9.266 4.367-.938.956-1.7 2.032-2.262 3.182a11.08 11.08 0 0 0 .78 11.188c.64.968 1.693 2.178 2.654 3.037l-.435 3.423-.048.145c-.012.042-.012.09-.018.133l-.012.108.012.11a1.1 1.1 0 0 0 1.657.852h.018l.067-.049 1.04-.52 3.102-1.56a16 16 0 0 0 4.537.623c1.897.004 3.78-.323 5.564-.968a2.014 2.014 0 0 1-1.373-2.11 13.7 13.7 0 0 1-5.721.568l-.309-.042a14 14 0 0 1-2.056-.43 1.4 1.4 0 0 0-1.1.116l-.085.042-2.552 1.5-.109.066c-.06.036-.09.048-.12.048a.176.176 0 0 1-.164-.181l.097-.393.115-.43.181-.707.212-.787a1.07 1.07 0 0 0-.387-1.19 11.2 11.2 0 0 1-2.577-2.686 8.730 8.730 0 0 1-.629-8.818c.46-.92 1.065-1.773 1.815-2.54 1.935-1.997 4.657-3.267 7.669-3.593a14.3 14.3 0 0 1 3.132 0c2.994.344 5.704 1.633 7.627 3.617a10 10 0 0 1 1.796 2.551 8.7 8.7 0 0 1 .901 3.84c0 .14-.012.279-.018.412a2.015 2.015 0 0 1 2.48.29l.09.109a11 11 0 0 0-1.1-5.733 12.3 12.3 0 0 0-2.238-3.182 15.18 15.18 0 0 0-9.229-4.397 17 17 0 0 0-3.739-.01"/></svg>`},
		Fields: []provider.ConfigField{
			// A userid is unique only within its corp.
			{Field: channel.Field{Key: "corp_id", Label: "企业 ID", Type: "text"}, Immutable: true},
			{Field: channel.Field{Key: "agent_id", Label: "AgentId", Type: "text",
				Help: "应用需开启「企业微信授权登录」，并将 Polaris 域名设为可信域名（须 ICP 备案，端口一致）。仅可见范围内的成员可登录。修改成员 userid 后会被视为另一个外部账号"}},
			{Field: channel.Field{Key: "secret", Label: "Secret", Type: "text", Secret: true,
				Help: "2022-06-20 之后创建的应用，需将 Polaris 服务器出口 IP 加入「企业可信 IP」"}},
		},
		New: func(c map[string]string) (provider.Redirect, error) {
			return &upstream{corpID: c["corp_id"], agentID: c["agent_id"], secret: c["secret"]}, nil
		},
	})
}

// upstream is a WeCom app. Its access token is cached: WeCom limits
// gettoken, and a wrong secret retried too often locks the whole corp out
// of it for an hour. A changed config builds a new upstream, dropping it.
type upstream struct {
	corpID, agentID, secret string

	mu      sync.Mutex
	token   string
	expires time.Time
	// failed and failure hold the last gettoken error, returned again for a
	// minute rather than asking WeCom.
	failed  time.Time
	failure error
}

// NoReauthPrompt: WeCom has no way to ask for a fresh sign-in.
func (u *upstream) NoReauthPrompt() {}

// AuthURL is the new web login; the old qrConnect is on its way out.
func (u *upstream) AuthURL(_ context.Context, redirectURI, state, _, _ string) (string, error) {
	return Login + "/wwlogin/sso/login?" + url.Values{
		"login_type":   {"CorpApp"},
		"appid":        {u.corpID},
		"agentid":      {u.agentID},
		"redirect_uri": {redirectURI},
		"state":        {state},
	}.Encode(), nil
}

// Callback reads the code into a member's userid, retrying once with a
// fresh access token when WeCom says the cached one is no good.
func (u *upstream) Callback(ctx context.Context, params url.Values, _, _, _ string) (provider.Identity, error) {
	code := params.Get("code")
	if code == "" {
		return provider.Identity{}, errors.New("企业微信: 回调没有 code")
	}
	var info struct {
		errorReply
		UserID string `json:"userid"`
		OpenID string `json:"openid"`
	}
	for retry := true; ; retry = false {
		token, err := u.accessToken(ctx)
		if err != nil {
			return provider.Identity{}, err
		}
		if err := get(ctx, "/cgi-bin/auth/getuserinfo", url.Values{"access_token": {token}, "code": {code}}, &info); err != nil {
			return provider.Identity{}, fmt.Errorf("企业微信用户身份: %w", err)
		}
		if retry && (info.ErrCode == 42001 || info.ErrCode == 40014) {
			u.mu.Lock()
			if u.token == token {
				u.token = ""
			}
			u.mu.Unlock()
			continue
		}
		break
	}
	switch {
	case info.ErrCode == 40029:
		return provider.Identity{}, errors.New("企业微信: code 无效或已用过,请重新登录")
	case info.ErrCode == 50001:
		return provider.Identity{}, errors.New("企业微信: 回调域名与应用的可信域名不符(须完全一致,含端口)")
	case info.ErrCode != 0:
		return provider.Identity{}, info.err("企业微信用户身份")
	case info.UserID == "" && info.OpenID != "":
		return provider.Identity{}, errors.New("企业微信: 不是本企业成员")
	case info.UserID == "":
		return provider.Identity{}, errors.New("企业微信用户身份: 没有 userid")
	}
	// WeCom's userids ignore case: one member must not become two.
	return provider.Identity{Subject: strings.ToLower(info.UserID)}, nil
}

// Profile reads the member's name with the app's token. Since 2022-06 an app
// gets no email, phone or avatar from user/get, only through a consent the
// web login has no way to ask for.
func (u *upstream) Profile(ctx context.Context, id provider.Identity) (provider.Identity, error) {
	token, err := u.accessToken(ctx)
	if err != nil {
		return id, err
	}
	var user struct {
		errorReply
		Name string `json:"name"`
	}
	// shortcut: asks with the userid lowercased, as Subject keeps it; WeCom
	// checks userids unique ignoring case, but whether user/get looks them up
	// so is untested. If not, carry the original userid in Identity.
	if err := get(ctx, "/cgi-bin/user/get", url.Values{"access_token": {token}, "userid": {id.Subject}}, &user); err != nil {
		return id, fmt.Errorf("企业微信成员: %w", err)
	}
	if user.ErrCode != 0 {
		return id, user.err("企业微信成员")
	}
	id.Name = user.Name
	return id, nil
}

// accessToken is the app's cached access token, fetched when there is none
// or it is about to expire. The lock is held across the fetch so that
// logins arriving together fetch it once.
func (u *upstream) accessToken(ctx context.Context) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.token != "" && time.Now().Before(u.expires) {
		return u.token, nil
	}
	if time.Since(u.failed) < time.Minute {
		return "", u.failure
	}
	token, expiresIn, err := u.getToken(ctx)
	if err != nil {
		// A login given up on is no failure of WeCom's to remember.
		if ctx.Err() == nil {
			u.failed, u.failure = time.Now(), err
		}
		return "", err
	}
	// A margin so a token is never used in its last minutes, and a floor so
	// a missing expires_in does not mean a gettoken per login.
	u.token, u.expires = token, time.Now().Add(max(time.Duration(expiresIn)*time.Second*9/10, time.Minute))
	return u.token, nil
}

func (u *upstream) getToken(ctx context.Context) (string, int, error) {
	var tok struct {
		errorReply
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := get(ctx, "/cgi-bin/gettoken", url.Values{"corpid": {u.corpID}, "corpsecret": {u.secret}}, &tok); err != nil {
		return "", 0, fmt.Errorf("企业微信 access_token: %w", err)
	}
	if tok.ErrCode != 0 || tok.AccessToken == "" {
		return "", 0, tok.err("企业微信 access_token(检查企业 ID 与 Secret)")
	}
	return tok.AccessToken, tok.ExpiresIn, nil
}

// errorReply is how every qyapi answer says it failed, over HTTP 200.
type errorReply struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func (e errorReply) err(what string) error {
	return fmt.Errorf("%s 失败(%d): %s", what, e.ErrCode, e.ErrMsg)
}

var client = &http.Client{Timeout: 10 * time.Second}

// get calls a qyapi path with q and decodes its 200 JSON answer into out.
func get(ctx context.Context, path string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, API+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		// The URL carries the secret or the token: keep it out of the error.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
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
	return json.Unmarshal(body, out)
}
