# 协议面

## 两个面,一套令牌

```
原生 App ──(直连认证 API: challenge 端点)──┐
                                          ├─ authorization code ─→ /token ─→ access / ID / refresh token
Web / RP ──(OIDC: /authorize + 托管登录页)──┘
```

直连认证 API 不签发自己的令牌。它按 IETF *OAuth 2.0 for First-Party Applications*(-04)实现 `authorization_challenge_endpoint`,认证完成后写入一条 Grant 并返回 authorization code,App 再到同一个 `/token` 兑换。(ADR 0002)

## OIDC Provider

- **端点**:discovery、JWKS、`/authorize`、`/token`、`/userinfo`、revocation(RFC 7009)、RP-Initiated Logout、Back-Channel Logout(见下面一节)。
- **认证目标**:Basic OP + Config OP;RP-Initiated Logout 可选。Implicit、Hybrid、Dynamic 不做。
- **不支持**:Front-Channel Logout、设备授权流程、DPoP、introspection、RFC 8707 `resource` 参数、`acr_values`。
- **客户端类型**:public(必须 PKCE)与 confidential 都支持。
- **同意页**:不做,也没有 Consent 概念,请求的 scope 直接授予。`prompt=consent` 接受但忽略;`offline_access` 接受但不改变行为。
- **已有浏览器 Session 时**:静默通过,直接带 code 跳回。一个浏览器 Session 对应一个 User,所以不做账号选择器。`prompt=select_account` 按 `login` 处理;`prompt=none` / `login` 与 `max_age` 按 Core 实现。
- **`client_credentials`**:只开给 M2M Application(ADR 0015),让它以自身身份调用 API,不签发 refresh token;scope 被忽略,令牌的 `aud` 固定为它的默认 API。接入见 [Management API 接入指南](../management-api.md)。

### Back-Channel Logout

按 OIDC Back-Channel Logout 1.0 实现(ADR 0022)。发现文档声明 `backchannel_logout_supported` 与 `backchannel_logout_session_supported`;`backchannel_logout_session_required` 对所有 Application 恒为真,不做成选项。

- **配置**:只有 Web Application(confidential)可以选配一个 `backchannel_logout_uri`,在管理端和 Management API 里设置或清除。原生 App 和 M2M Application 没有。
- **何时发**:Session 被**主动**终止时:管理员终止单个 Session、禁用 User(终止其全部 Session)、删除或注销 User、User 自己退出登录(RP-Initiated Logout,账户中心退出也走它),refresh token 重放,以及同一浏览器换成另一个 User 登录。闲置到期不发。
- **发给谁**:这个 Session 签发过令牌、且配了 `backchannel_logout_uri` 的每个 Application,各一个。Session 在签发 authorization code 时记下 Application,所以只走 code flow、不拿 refresh token 的也收得到。
- **logout token**:RS256 JWT,`typ: logout+jwt`,带 `iss`、`aud`(client_id)、`iat`、`exp`(2 分钟)、`jti`、`events`(`http://schemas.openid.net/event/backchannel-logout`),并且总是同时带 `sub` 和 `sid`;`sid` 与这个 Session 签发的 ID token、access token 里的一致;不带 `nonce`。每次投递时现签。
- **投递**:按规范 `POST`,`application/x-www-form-urlencoded`,`logout_token=<JWT>`,不带 Standard Webhooks 签名。与 Webhook 共用投递队列和退避重试:非 2xx 时从 1 分钟起翻倍、最长 12 小时,约一天后放弃并记审计 `webhook.failed`。User 被删除后,已排队的 logout token 照样发出。

## 直连认证 API

- **路径与版本**:路径带 `/v1` 前缀,主版本内只做向后兼容的改动。challenge 端点为 `POST /v1/auth/challenge`,OpenAPI 在 `/v1/auth/openapi.json`。
- **challenge 输入**:
  - 一期:手机号或邮箱(请求发码)、验证码、Identifier + 密码;
  - 二期起:WebAuthn 断言、TOTP、Provider ID + 客户端令牌:`provider` + `authorization_code`,只接受启用中、类型声明了客户端令牌型的 Provider(目前只有 Apple:App 只转交 Sign in with Apple 给的 `authorization_code`,服务端以 Bundle ID 换码,见 ADR 0011)。Provider 不是这一类或已停用时返回 `400 invalid_request`;上游换码失败返回 `400 invalid_grant`,App 须让 User 重新用 Apple 登录。之后的两步验证、绑手机号与验证码登录相同,按 `next` 继续;`amr` 为 `fed`。
  - Passkey:见下面一节。
- **未开放注册**:实例关闭开放注册时,发码请求的目标不属于任何 User,或 Provider 客户端令牌对应的 External Identity 没有绑定过,返回 `400 registration_closed`(非标准错误码),`error_description` 为"本实例未开放注册";不发验证码。错误码集合只新增,不改名(ADR 0010、ADR 0021)。
- **多步认证**:用草案中的 `auth_session` 串联各步。`403 insufficient_authorization` 多带一个非标准字段 `next`,指明下一步:`code`(输入刚发出的验证码)、`password`(账号待激活:在同一 `auth_session` 里提交新的 `password`)、`phone`(先绑定手机号)、`totp`(开了两步验证:在同一 `auth_session` 里提交 `totp` 或 `recovery_code`;先于 `phone`)。`next: "password"` 排在所有步之前,连带两步验证;那一步提交的密码不带 PoW——密码本身就是证明。待激活的 User 也可以带 `delete` 注销账号。`totp` / `recovery_code` 输错时返回 `400 invalid_request` 并带回原 `auth_session`;第 5 次输错后返回 `invalid_session`,须从头登录。以后只新增取值,不改名、不删除;客户端遇到不认识的取值按失败处理。(ADR 0010)
- **每个请求必须携带**:
  - 所同意的协议版本号,见 [security-compliance.md](security-compliance.md#协议同意);
  - 发码请求和密码登录请求还要附带 PoW 解答。`next: "password"` 那一步的改密请求不带:它是同一次登录已经在进行的下一步,密码本身就是证明。取 Passkey challenge(`passkey=begin`)不带 PoW:它不发码也不验密码,只按 IP 限流兜底(ADR 0014)。
- **其他用途**:注销账号也有对应接口。
- **用户资料**:App 用签发给本人的 access token(鉴权与注销接口相同,只能改本人;无效或缺失返回 `401`)调用:`PATCH /v1/auth/profile` 改昵称(`{"nickname": ""}` 清除),`PUT /v1/auth/profile/avatar` 上传头像(请求体就是图片:JPEG/PNG/WebP、≤ 5 MB,按内容识别;超限 `413`,不是图片 `400`),`DELETE /v1/auth/profile/avatar` 移除。都返回当前的 `{nickname, picture}`。头像统一裁成 512×512 JPEG、去掉 EXIF,经 `GET /avatars/{key}` 公开提供(不鉴权,`Cache-Control: public, max-age=31536000, immutable`)。

### 直连认证 API 的 Passkey 登录

分两次往返(ADR 0014):

1. 首次参数(`response_type=code`、`client_id`、PKCE、`scope`、`terms_version`)加 `passkey=begin`,返回 `200 {auth_session, options}`。`options` 是标准断言 options(`PublicKeyCredentialRequestOptionsJSON` 放在 `publicKey` 下),直接交给 Credential Manager / ASAuthorization;不用 ALTCHA。
2. 带 `auth_session` 和 `passkey=<AuthenticationResponseJSON>`(系统凭证 API 的返回值)再请求一次,成功返回 `{authorization_code}`。

通过后进的就是验证码、密码登录那套:Passkey 已自带 `mfa`,所以跳过两步验证;仍可能按 `next=phone` 要求先绑定手机号,或记录协议同意。`amr` 为 `["hwk", "mfa"]`(凭证仅存本机)或 `["swk", "mfa"]`(可跨设备同步)。断言不通过(凭证不存在、签名错、缺 UV、计数器回退)返回 `400 invalid_request`,该 `auth_session` 随之作废,App 须重新 `begin`。Passkey 不能注册新 User。

允许的 origin = issuer 的 origin,加上所有 Application 的 `android_apps` 签名指纹换算出的 `android:apk-key-hash:<base64url>`;每次校验时现查,未登记的指纹被拒。过期的 challenge 由每小时一次的清理任务删除。

## 令牌

| 令牌 | 形态 | 寿命 | 要点 |
|---|---|---|---|
| access token | JWT,RFC 9068(`typ: at+jwt`),RS256 | 10 分钟 | `aud` 为 API 标识符;带 `client_id`、`roles`、`entitlements`(只限当前 API) |
| ID token | JWT,RS256 | — | `sub`、`amr`、`sid`(签发它的 Session);scope 为 `phone` / `email` / `profile` 时带对应 claim(`profile`:`nickname`、`picture`,只发有值的,与 userinfo 相同);不带角色 |
| refresh token | 不透明 | 跟随 Session | 每次刷新都轮换;最近换下的那个 60 秒内再来,再轮换一次签发新令牌(宽限,审计 `refresh_token.grace`);其余重用终止整个 Session |

- **`amr`**:按 RFC 8176 取 `sms`、`otp`、`pwd`、`hwk` / `swk`;做过两步验证(TOTP 或恢复码)时为 `[第一因素, "otp", "mfa"]`(第一因素的值加上 `otp`、`mfa`,不重复:邮箱验证码登录为 `["otp", "mfa"]`,短信为 `["sms", "otp", "mfa"]`);Passkey 登录为 `["swk", "mfa"]`(凭证可跨设备同步)或 `["hwk", "mfa"]`(仅本机),Passkey 本身已验证持有与本人,不再加 `otp`;Application 以 `mfa` 判断是否做过两步验证;Provider 登录一律为自定义值 `fed`;接受注册邀请建立的那次会话为 `["otp"]`(链接证明邮箱控制权,与邮箱验证码同一种证据,见 [authentication.md](authentication.md#注册邀请))。
- **业务后端校验**:用 JWKS 本地验签,检查签名、`aud`、`typ`,权限读 `entitlements`。
- **签名**:只用 RS256;每 90 天自动轮换(每小时的清理任务检查最新 key 的创建时间),管理员也可以手动轮换。最新的 key 签发新 token;旧 key 在它的下一把 key 创建后继续留在 JWKS 里 1 小时(最长 token 寿命 10 分钟加上 RP 缓存 JWKS 的余量),期满即不再发布,随后由每小时的清理任务删除。只剩一把 key 时它一直有效。
- **吊销**:最多滞后一个 access token 的寿命。

## Session

Session 是一个 User 在一台设备或一个浏览器上的一次登录。

- **App Session**:由 refresh token 链承载,只属于一个 Application。闲置 90 天过期。
- **浏览器 Session**:由 cookie 承载,跨 Application 单点登录。经 OIDC 签发的 refresh token 挂在它下面,随之终止。闲置 30 天过期。
- **过期规则**:滑动过期,没有绝对上限;管理员可按 Application 调整。
- **设备数**:不限;User 可以在账号中心逐个下线。
- **跨原生 App 共享 Session**:暂不设计,倾向 Token Exchange(RFC 8693)。

## Webhook

- **配置**:每个 Application 可以选配一个 URL 和签名共享密钥。
- **收件方**:每个配置了 Webhook 的 Application 都收到每一条事件,不看 User 用没用过它,也不能按类型订阅。
- **事件**:都是薄事件(ADR 0022),只带 `sub`,不带新值;要新值就调 Management API。payload 统一为 `{"type", "timestamp", "data"}`,`timestamp` 是 UTC 的 RFC 3339 时间。
  - `user.deleted`,`data: {sub}`:User 注销或被管理员删除。
  - `user.disabled` / `user.enabled`,`data: {sub}`:User 被禁用或恢复;状态本来就是这样时不发。
  - `user.updated`,`data: {sub, changed}`:`changed` 是非空数组,取 `phone`、`email`、`username`、`profile`、`roles` 的子集,列出这次变了哪几项。不论是管理员改、User 在账号中心自己改,还是登录时绑定了已验证的 Identifier,都会发。改某个 User 的 Role 分配算 `roles`;强制删除 Role 或 API 时,原来持有其 Role 的每个 User 各发一条。
  - 不发事件的:只改 Role 里的 Permission;Credential 变更(密码、Passkey、两步验证、恢复码);从待激活转为 active;External Identity 绑定或解绑;Session 终止(走 Back-Channel Logout)。
- **事务**:事件和触发它的变更在同一个事务里排进投递队列;变更回滚,事件也不产生。
- **顺序**:不保证投递顺序。接收方应按 `timestamp` 丢弃过时事件,或调 Management API 取当前状态。
- **兼容**:接收方必须忽略不认识的 `type`,以后可能加新事件。
- **签名与重试**:用共享密钥签名;失败会重试。
- **Session 终止**:不走 Webhook,走 [Back-Channel Logout](#back-channel-logout)。
