# 支持标准 OAuth2 作为 Provider 上游

除 OIDC 之外新增通用的「标准 OAuth2」Provider 类型,并把 GitHub 做成它的一个预设。这类上游没有 discovery、没有 id_token,身份只能来自拿 access token 调 userinfo,因此**不带上游的签名背书**;我们接受这个取舍,代价是身份的可信度依赖"授权码只换给了我们、userinfo 走 TLS",而不是上游对身份的签名。类型因此要求管理员指定 userinfo 里哪个字段是用户 ID,并把它当作 External Identity 的锚点——该字段必须上游不会变,改个昵称就换人的字段不能用。

## Considered Options

- **只写一个 GitHub 类型**(照 Apple 的模板把 endpoint 写死):省一个通用类型,但每接一家非 OIDC 服务都要发版,而 GitHub 与别家的差异其实只是三个 endpoint 加一个字段名。
- **放宽通用 OIDC 让它兼容非 OIDC 上游**(discovery 可选、没有 id_token 就退回 userinfo):改动最小,但把"通用 OIDC"这条严格路径的核心校验变成可选项,日后分不清哪个 Provider 校验过签名。拒绝。
- **不支持非 OIDC 上游**(`architecture.md` 原先的立场):要接 GitHub 就 fork 自编译。GitHub 是最常被要求的供应商之一,不值得为它要求所有人 fork。

## Consequences

- 修订 ADR 0004:免写代码的路从两条(通用 OIDC Provider、Webhook Channel)变成三条,加上通用 OAuth2 Provider。
- `docs/spec/architecture.md` 里"只接真正的 OIDC 上游……纯 OAuth2 服务(如 GitHub)不支持"的措辞作废。
- **重新认证打了折扣**:OAuth2 没有 `prompt=login`、`max_age`,也不返回 `auth_time`,上游记着登录状态时不必再输密码。用它重新认证只证明"此刻仍控制这个外部账号"。我们接受这一点,而不是禁止它重新认证:偷到 Polaris Session 的人多半也在同一浏览器里登着上游,禁止换来的安全有限,却会让只绑了 GitHub 的 User 连注销都做不了。
- 上游没有 discovery,无从得知 token 端点要哪种 client 认证,固定用 `client_secret_post`;请求都带 `Accept: application/json`。用户 ID 字段只取 userinfo 的顶层字段,数字按原样转成字符串。
- 非 OIDC 上游拿不到邮箱;而认证结果里的邮箱本来就被丢弃(`provider.Identity` 只有 Subject / AuthTime / Token),所以不受影响。
- 通用 OAuth2 只做重定向型,不做客户端令牌型。
- Microsoft 的 issuer 不是常量,由类型里的不可改字段 `tenant` 拼出;填 `common` / `organizations` 时放宽为接受 `https://login.microsoftonline.com/<租户 GUID>/v2.0`,**且 GUID 必须等于 id_token 的 `tid`**,否则任意租户签出的令牌只要形状对就能通过;其余值严格校验。discovery 返回的 issuer 是带 `{tenantid}` 的模板,对 discovery 的 issuer 校验也要按同一规则放宽。
