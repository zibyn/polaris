# 直连认证复用 OIDC token 端点,access token 为 JWT

直连认证 API 不签发自己的令牌:它按 IETF *OAuth 2.0 for First-Party Applications*(-04)实现 challenge 端点,认证完成后返回 authorization code,App 到 OIDC 面同一个 `/token` 端点兑换。因此两条路径签发的 access token / ID token / refresh token 完全相同,刷新、吊销与多设备管理只实现一遍。Access token 采用 RFC 9068 JWT(`typ: at+jwt`,RS256,10 分钟),`aud` 为 API 标识符而非 client_id,业务后端以 JWKS 本地验签,一期不提供 introspection。

## Considered Options

- **直连 API 自有一套会话令牌**:业务后端要认两种令牌,刷新与吊销各写一遍。
- **不透明 access token + introspection**:可即时吊销,但每个业务请求都回查 Polaris,使其成为单点与瓶颈。
- **`aud` 填 client_id**:省掉 API 概念,但 access token 与 ID token 形态几乎一致,不校验 `typ` 的后端会混用两者。

## Consequences

- 吊销最多滞后一个 access token 寿命(10 分钟);终止 Session 即吊销其 refresh token 链。
- 依赖一份未定稿的草案;端点为自有代码,草案变动时自行跟进。
- 需新增 API 概念:每个 Application 配一个默认 API,一期不支持 RFC 8707 `resource` 参数。
