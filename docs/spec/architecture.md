# 架构

## 部署形态

- **单个 Go 二进制**:内嵌并托管管理端、账号中心、托管登录页的静态资源;以单镜像形式发布。
- **唯一外部依赖**:PostgreSQL 15+。不使用 Redis。(ADR 0005)
- **进程无状态**:进程内不保存任何需要在副本间共享的状态,允许多个副本连同一个 PG;主流场景是单实例。
- **只监听 HTTP**:部署在反向代理之后,只信任已配置代理传来的 `X-Forwarded-*`;issuer 必须是 https,启动时检查。
- **规模假设**:约一万 User。

## 存储

- 只支持 PostgreSQL。数据访问用 sqlc 从手写 SQL 生成代码,不用 ORM;go-oidc 的存储接口实现在这一层之上。
- 短命数据(验证码、PoW 题目、限流计数、登录过程中的临时状态、Grant 记录)也放 PG,带过期时间,由每小时一次的定时任务清理。
- 迁移用 goose,脚本嵌入二进制,启动时自动执行;只能向前升级。多副本时用 PG advisory lock 保证只有一个副本执行迁移。

## OIDC 协议层

- 以 `luikyv/go-oidc` v0.25.0 为起点并入仓库(保留 MIT 版权声明,记录上游 commit),按目录删除用不上的部分:Federation、VC、CIBA、device、PAR、JAR、JARM、token exchange、jwt-bearer、pre-auth code、DCR、mTLS、FAPI。每删一块都跑一次 conformance 回归。(ADR 0001)
- JOSE 与密码学只依赖 `go-jose/v4` 和标准库,不手写。

## 插件

两类插件,都是仓库内的 Go 包,实现接口后在 `init` 中注册,随二进制发布;内部接口不承诺稳定。(ADR 0004)

| 类型 | 职责 | 产出 | 实例数 |
|---|---|---|---|
| **Channel** | 把 Polaris 生成的验证码或一次性链接投递到手机号或邮箱 | 投递结果 | 每种 Identifier(短信、邮件)同时只启用一个,不做故障切换 |
| **Provider** | 由外部服务证明"这是谁" | 一个已验证的 Identifier(如一键登录给出的手机号),**或**一个 External Identity | 可以添加多个 Provider,同一 Provider 类型也可以添加多个,各自的 External Identity 互不相通 |

- **核心能力不做成插件**:验证码登录、密码、Passkey、TOTP。
- **三个免写代码的通用插件**:
  - **Webhook Channel**:把 `{"to": 目标, "code": 验证码}` POST 到管理员指定的 URL,返回 2xx 即视为送达;注册邀请不带验证码,送的是 `{"to": 目标, "link": 链接}`;请求头 `X-Stars-Signature: t=<秒>,v1=<hex HMAC-SHA256(密钥, "<t>.<body>")>`,接收方应拒绝过旧的 `t` 以防重放;
  - **通用 OIDC Provider 类型**:填 issuer、client_id、secret 即可接入,见下文;
  - **通用 OAuth2 Provider 类型**:填 authorization、token、userinfo 三个 endpoint、scope 与用户 ID 字段即可接入,见下文。
- **Provider 的交互形态**:每个 Provider 类型声明自己支持哪种,或两种都支持。
  - **重定向型**:托管登录页跳到服务商,再接收回调;
  - **客户端令牌型**:客户端从平台拿到令牌,提交到直连 API,并带上 Provider ID。
- **Provider 的可选回调**:解绑或注销时触发,用于吊销第三方令牌(Apple 必需)。
- **配置 schema**:每个插件声明自己的配置字段(类型、是否为密钥字段),管理端据此自动渲染表单。
- **服务商附带的信息**:Provider 返回的邮箱等附带信息一律忽略,不据此关联 User。
- **内置插件**:
  - Channel:阿里云短信认证、SMTP、Webhook;
  - Provider 类型:通用 OIDC、通用 OAuth2、Apple,以及 Google、Microsoft、GitHub 三个具名供应商——具名供应商与通用类型共用同一份实现,差别只在端点、scope、品牌是否预填。

### Provider 的配置与身份

- **Provider ID**:管理员创建时填写的 slug(如 `google`),出现在回调 URL `/login/providers/{id}/callback` 和直连 API 的请求里,创建后不可改。
- **身份锚点**:External Identity 是 (Provider, 上游的用户 ID)——通用 OIDC 是 id_token 的 `sub`,通用 OAuth2 是配置里指定的 userinfo 字段。锚定它的字段创建后不可改:Provider ID、通用 OIDC 的 issuer、通用 OAuth2 的用户 ID 字段、Microsoft 的租户;client_id 和密钥可以改。
- **停用与删除**:停用后托管页不再显示,已绑定的 User 也不能用它登录。还有 External Identity 绑定时只能停用,不能删除。
- **请求的信息**:OIDC 只请求 `openid`;Apple 不请求 `name email`,首次登录返回的姓名直接丢弃;通用 OAuth2 的 scope 由管理员按服务商要求填写(GitHub 预设已写死)。

### 通用 OIDC Provider 类型

- 只接真正的 OIDC 上游:必须提供 discovery(`/.well-known/openid-configuration`),校验 id_token。Google、Microsoft 是照它实现的具名供应商:issuer 写死在类型里(微软的是模板,见 ADR 0013),管理员只填 client_id 与 client secret。
- 只支持重定向型:authorization code + PKCE + `state` + `nonce`。原生 App 要接时,再加客户端令牌型(届时需要"额外接受的 `aud`")。

### 通用 OAuth2 Provider 类型

- 接不走 OIDC 的服务(如 GitHub):没有 discovery,也没有 id_token,身份只能来自拿 access token 调 userinfo,所以**不带上游的签名背书**(ADR 0013)。管理员因此必须指定 userinfo 里哪个字段是用户 ID,而且该字段必须上游不会变。
- **配置**:authorization、token、userinfo 三个 endpoint,scope,client_id,client secret,用户 ID 字段名。
- 只支持重定向型,与通用 OIDC 一样。GitHub 是它的具名供应商:endpoints 与 scope 写死,用户 ID 取数字 `id`。不请求邮箱——GitHub 的邮箱要么私密、要么要另调 `/user/emails`,而认证结果里的邮箱本来就被丢弃。

### Apple Provider 类型

- **配置**:Team ID、Key ID、`.p8` 私钥(密钥字段)、Services ID(Web)、Bundle ID(原生);issuer 固定为 `https://appleid.apple.com`。client secret 是用 `.p8` 自签的 JWT。
- **重定向型**:Web 用 Services ID,回调为 `form_post`(跨站 POST,浏览器不会带 SameSite=Lax 的 cookie,登录状态按 `state` 存在服务端;回调 POST 先 303 到同一路径的 GET,在带得上 Lax cookie 的 GET 上核对发起登录的浏览器:托管页登录核对 `__Host-login` 绑定 cookie(第一步之后的 TOTP、同意协议、绑手机号也只认这个浏览器),个人中心绑定/重新验证核对当前 Session,防登录 CSRF)。
- **客户端令牌型**:原生 App 只提交 `authorization_code`,服务端以 Bundle ID 换码,以换回的 id_token 为认证结果,不需要 identity token 和 nonce(ADR 0011)。
- **refresh token**:两种形态都在换码时拿到 refresh token,用主密钥加密后存在 External Identity 上;换码失败,这次登录就失败。
- **撤销**:解绑和注销时调用 Apple `/auth/revoke`,尽力而为,失败只记审计日志,不阻塞解绑或注销。不接 Apple 的服务器到服务器通知。

## 配置与密钥

- **环境变量**只放启动必需项,不使用配置文件:
  - PG 连接串;
  - 主密钥:`STARS_AUTH_MASTER_KEY` 或 `STARS_AUTH_MASTER_KEY_FILE`;
  - 对外 URL(即 issuer);
  - 监听地址;
  - 信任的代理。
- **其余配置全部存 PG**,由管理端经 Management API 修改,包括插件配置、登录策略、Application、API、Role 等。多副本之间以秒级缓存同步。
- **加密**:插件的密钥字段、OIDC 签名私钥、TOTP 密钥用主密钥做 AES-256-GCM 加密后入库,密文带密钥版本号。密码和恢复码只做哈希。
- **主密钥轮换**:离线命令 `stars-auth rotate-master-key`,同时给出新旧两把密钥,一次性重新加密全部数据(二期)。
- **主密钥丢失**:所有加密数据都无法还原,部署文档须醒目提示备份。
- **签名私钥**:首次启动时自动生成 RS256 私钥,不支持导入;由管理员在管理端手动轮换,轮换期间 JWKS 新旧两把密钥并存。

## 首次启动引导

1. 没有任何管理员时,启动后在日志中打印一次性 setup token。
2. 带 token 打开引导页,设置用户名和密码,创建第一个 User,并赋予 Management API 的「所有者」Role。全程不需要任何 Channel。
3. 引导完成后,引导页永久关闭,token 失效。

没有后门:所有管理员都无法登录时,只能直接改数据库。(ADR 0006、0007)
