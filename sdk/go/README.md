# Polaris Go SDK

`github.com/zibyn/polaris/sdk/go`:给 Go 写的 API 后端校验 Polaris 的 access token,按 Entitlement 拦截请求;外加校验 Back-Channel Logout 的 logout token。底层是 `go-oidc`。范围见 [ADR 0035](../../docs/adr/0035-node-and-go-sdk-scope.md)。

SDK 0.x 支持服务端 API v1,tag 为 `sdk/go/v0.x.y`。Go 1.24+。

```sh
go get github.com/zibyn/polaris/sdk/go
```

## 校验 access token

```go
import polaris "github.com/zibyn/polaris/sdk/go"

// audience 是 API 的标识符,签给别的 API 的 token 一律拒绝
v, err := polaris.NewVerifier(ctx, "https://auth.example.com", "api://orders")

mux.Handle("/orders", v.Require(ordersHandler, "orders:read"))

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := polaris.FromContext(r.Context()) // Sub、ClientID、Entitlements
	// ...
}
```

- 校验签名(RS256)、`iss`、`aud`、`typ: at+jwt`、`exp`。JWKS 缓存在进程里,遇到没见过的 `kid` 会重新拉取,Polaris 轮换密钥后不用重启。
- `Require` 要求列出的 Entitlement **全部**持有。token 缺失或无效返回 `401`,缺 Entitlement 返回 `403`。要「任一即可」,用 `FromContext` 自己判断。
- 权限只看 `entitlements`,不看 `roles`。M2M Application 的 token 照常通过,一般不带 Entitlement。
- 不经过中间件时用 `v.VerifyAccessToken(ctx, rawJWT)`。

## 校验 logout token

Web Application 在 Polaris 里配了 `backchannel_logout_uri` 后,Session 被终止时会收到 `POST`(表单字段 `logout_token`):

```go
http.HandleFunc("/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
	lt, err := v.VerifyLogoutToken(r.Context(), clientID, r.PostFormValue("logout_token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	endLocalSession(lt.Sid) // lt.Sub 是 User
})
```

按 OIDC Back-Channel Logout 1.0 校验:`typ: logout+jwt`、`aud` 等于 `clientID`、`events` 带 back-channel logout 事件、同时有 `sub` 和 `sid`、没有 `nonce`。

## 不在 SDK 里的

- **Web 登录**:用 `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`:

  ```go
  provider, _ := oidc.NewProvider(ctx, "https://auth.example.com")
  conf := oauth2.Config{
  	ClientID: clientID, ClientSecret: clientSecret,
  	Endpoint:    provider.Endpoint(),
  	RedirectURL: "https://app.example.com/auth/callback",
  	Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
  }
  pkce := oauth2.GenerateVerifier() // 与 state、nonce 一起存进登录前的 cookie
  // 登录:conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce))
  // 回调:tok, _ := conf.Exchange(ctx, code, oauth2.VerifierOption(pkce))
  //      idt, _ := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, tok.Extra("id_token").(string))
  //      再核对 idt.Nonce == nonce
  ```

- **Management API**:用 OpenAPI 生成 client,例如 `oapi-codegen`(#179)。
- **Webhook 验签**:用 Standard Webhooks 官方 Go 库 `github.com/standard-webhooks/standard-webhooks/libraries/go`。
