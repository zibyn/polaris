# 飞书 / Lark 登录作为 Provider 类型

调研日期：2026-11-04。范围：用飞书（含国际版 Lark）账号登录 Polaris 需要的协议细节、用户标识、应用类型门槛、端内与原生 App 形态，以及对 Polaris Provider 类型的建议。

**阅读须知**

- 只用飞书开放平台（open.feishu.cn）与 Lark 开放平台（open.larksuite.com）的官方文档作一手来源。
- 本次调研环境里 **open.feishu.cn 无法直接抓取**（连接被断开）；open.larksuite.com 的文档页是前端渲染的，正文通过它自己的文档接口 `https://open.larksuite.com/document_portal/v1/document/get_detail?fullPath=<路径>` 读到。所以：
  - **[已验证]**：读到了 Lark 官方文档正文，结论来自原文。飞书与 Lark 是同一套开放平台的两个部署，接口路径一致，只换域名（见第 7 节）；把 Lark 的结论用到飞书上时，若没有单独验证，会另外说明。
  - **[未验证]**：只看到搜索引擎对 open.feishu.cn 页面的摘要，或者完全没找到原文。写进 ADR 之前要点开原页复核。
  - **[推断]**：本文作者的判断，不是来源原话。
- 页面由抓取工具的摘要模型转述，引号里的文字可能有轻微出入。

## 1. 网页登录流程（浏览器跳转 / 扫码）

### 1.1 结论

当前推荐的流程就是标准 OAuth 2.0 授权码流程加 PKCE：浏览器跳到 `accounts.{feishu.cn|larksuite.com}/open-apis/authen/v1/authorize`，回调拿到 `code`，服务端 POST JSON 到 `open.{feishu.cn|larksuite.com}/open-apis/authen/v2/oauth/token` 换 `user_access_token`，再拿它 GET `/open-apis/authen/v1/user_info` 取身份。**没有 OIDC**：没有 discovery，没有 id_token。

### 1.2 授权端点

- URL：`https://accounts.larksuite.com/open-apis/authen/v1/authorize`，方法 GET；支持自建应用（custom）和商店应用（isv），调用不需要任何权限。[已验证] [Lark：获取授权码](https://open.larksuite.com/document/common-capabilities/sso/api/obtain-oauth-code)
- 飞书对应的是 `https://accounts.feishu.cn/open-apis/authen/v1/authorize`。[推断：Lark 是 `accounts.larksuite.com`，按域名对称；飞书页面没能直接读到] [飞书：获取授权码](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
- 参数 [已验证，同上 Lark 页]：
  - `client_id`（必填）：应用的 App ID，形如 `cli_a5d611352af9d00b`。
  - `redirect_uri`（必填）：URL 编码，必须在重定向 URL 白名单里（见 1.6）。
  - `scope`（可选）：空格分隔、区分大小写，一次最多 50 个；要 refresh_token 时加 `offline_access`。scope 里有应用没开通的权限会报 20027。
  - `state`（可选）：原样带回，文档要求校验它防 CSRF。
  - `code_challenge`（可选）：PKCE。
  - `code_challenge_method`（可选）：默认 `plain`，推荐 `S256`（verifier 的 SHA-256 再做 Base64URL）。
  - 文档没有列 `response_type`。[已验证] 我们多带一个 `response_type=code` 预计会被忽略。[推断，需实测]
- 飞书版文档另有 `prompt` 参数，`prompt=consent` 会强制展示授权页。[未验证：搜索摘要] Lark 版页面没有列出 `prompt`。[已验证]
- 回调：成功时带 `code` 和 `state`；用户拒绝时带 `error=access_denied` 和 `state`，`error` 目前只有这一个值。`redirect_uri` 里有 `#` 时，`code` 会放在 fragment 前面。[已验证，同上 Lark 页]
- 授权码有效期 5 分钟，只能用一次；字符集是 `A-Z a-z 0-9 - _`，建议预留至少 64 个字符的长度。[已验证，同上 Lark 页]
- 在飞书 / Lark 客户端里打开网页应用时，可以跳过确认页直接回跳。[已验证，同上 Lark 页]
- 用户授过的权限会累积，之后签发的 token 包含以前授过的全部 scope。[已验证，同上 Lark 页]

### 1.3 Token 端点（v2，当前推荐）

- URL：`https://open.larksuite.com/open-apis/authen/v2/oauth/token`，POST。[已验证] [Lark：获取 user_access_token](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/get-user-access-token)
- 飞书是 `https://open.feishu.cn/open-apis/authen/v2/oauth/token`。[未验证：搜索摘要] [飞书：获取 user_access_token](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token)
- **请求体是 JSON**：`Content-Type` 写的是固定值 `application/json; charset=utf-8`。[已验证，同上 Lark 页] 是否也接受 `application/x-www-form-urlencoded`，文档没说。[未验证，需实测]
- 字段 [已验证，同上]：
  - `grant_type=authorization_code`、`client_id`、`client_secret`、`code`，均必填。
  - `redirect_uri`：网页应用必填，必须和授权时完全一致，不一致报 20071。
  - `code_verifier`：用了 PKCE 就必填，43–128 个字符。校验失败报 20049。
  - `scope`：可选，用来缩小 token 的权限。
- **Client 认证**：文档只写了 body 里放 `client_id` 和 `client_secret`，也就是 client_secret_post。错误码 20070 是「同时提供了多种认证方式」，提示只用 body 里的 client_id 和 secret；可见服务端认得 Basic 头，但文档不推荐。[已验证，同上]
- 响应：**字段在顶层，不在 `data` 里**：`code`（成功时为 0）、`access_token`、`expires_in`（示例 7200）、`token_type=Bearer`、`scope`；授予了 `offline_access` 才另有 `refresh_token` 和 `refresh_token_expires_in`。失败时返回 `code`、`error`、`error_description`，HTTP 状态是 400 / 500 / 503，不是 200。[已验证，同上]
- 限流：1000 次/分钟、50 次/秒。[已验证，同上]
- 旧版 v1 接口（`/open-apis/authen/v1/oidc/access_token`）已标为「历史版本，不推荐使用」。它要在 `Authorization` 头里带 app_access_token，返回值包在 `data` 里，名字带 oidc，但**不返回 id_token**。[已验证] [Lark：v1 oidc access_token](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/oidc-access_token/create) 更老的 `passport.feishu.cn/suite/passport/oauth/authorize` 那套也已归入「deprecated-guide」。[未验证：搜索摘要] [飞书：旧登录流程](https://open.feishu.cn/document/deprecated-guide/app-login/web-app-login/web-app-overview?lang=zh-CN)

### 1.4 用户信息端点

- URL：`https://open.larksuite.com/open-apis/authen/v1/user_info`，GET，请求头 `Authorization: Bearer <user_access_token>`；不需要权限，部分字段要另外开通权限才返回。[已验证] [Lark：获取用户信息](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get)
- 飞书是 `https://open.feishu.cn/open-apis/authen/v1/user_info`。[推断：按域名对称]
- **响应嵌套在 `data` 里**：`{"code":0,"msg":"...","data":{...}}`。[已验证，同上]
- `data` 里的字段：`open_id`、`union_id`、`tenant_key`、`name`、`en_name`、`avatar_*` 不需要权限；`user_id` 要 `contact:user.employee_id:readonly`（仅自建应用）；`email` 要 `contact:user.email:readonly`（仅自建应用）；`mobile` 要 `contact:user.phone:readonly`（仅自建应用）。[已验证，同上]
- 错误码里有 20021（用户已离职）和 20022（用户被冻结），这类用户登不进来。[已验证，同上]

### 1.5 OIDC

- 没有 OIDC：`https://open.larksuite.com/.well-known/openid-configuration` 返回「页面不存在」。[已验证：直接请求]
- 飞书域名下的 discovery 没能请求。[未验证]
- v2 token 响应和 user_info 都不含 `id_token`，也不含 `auth_time`。[已验证，见 1.3、1.4]
- 飞书官网营销页说 SSO 支持 OIDC/SAML。那是飞书**作为 SP** 接入企业 IdP 的能力，和开放平台的应用登录无关。[推断]

### 1.6 重定向 URL 白名单

在开发者后台「应用详情 > 开发配置 > 安全设置」里配置重定向 URL，可以配多个；不在列表里的 URL 通不过安全校验。[已验证] [Lark：获取授权码](https://open.larksuite.com/document/common-capabilities/sso/api/obtain-oauth-code)、[Lark：浏览器网页接入指南](https://open.larksuite.com/document/common-capabilities/sso/web-application-end-user-consent/guide)

## 2. 能否用现有通用 OAuth2 类型以预设覆盖

**不能原样覆盖**，差两处，外加一处要注意：

| 环节 | 通用 OAuth2（ADR 0013） | 飞书 v2 | 兼容？ |
|---|---|---|---|
| 授权 URL | code + PKCE S256 + state + scope | 同上 | 兼容 [已验证] |
| Token 请求体 | `application/x-www-form-urlencoded` | 写明固定 `application/json` | **不兼容**（是否也接受 form 未验证，需实测） |
| Client 认证 | client_secret_post | body 里放 client_id/secret | 兼容 [已验证] |
| Token 响应 | 顶层 `access_token` | 顶层 `access_token` | 兼容 [已验证] |
| Userinfo 用户 ID | 顶层字段 | 在 `data.union_id` / `data.open_id` 里 | **不兼容**：ADR 0013 规定只取顶层字段 |
| Userinfo 成败 | HTTP 200 即成功 | 有 `code` 字段，非 0 表示失败 | 要注意：非 0 时 `data` 里没有 ID，现有代码会报「没有该字段」，不会误判成别人，但错误信息不对 [推断] |
| 重新认证 | NoReauthPrompt | 没有 prompt=login / max_age | 兼容 |

依据：[Lark：获取 user_access_token](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/get-user-access-token)、[Lark：获取用户信息](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get)

要让通用类型覆盖飞书，得给它加两个开关（JSON 请求体，以及嵌套的 ID 路径）。这会把 ADR 0013 里「固定 form、只取顶层字段」的两条决定变成可配置项。

## 3. 用户标识

| 标识 | 唯一范围 | 会不会变 | 获取条件 |
|---|---|---|---|
| `open_id`（前缀 `ou_`） | 每个应用一个；同一用户在不同应用里不同 | 系统在用户首次使用应用时生成，对开发者只读 | user_info 直接返回，不需要权限 |
| `union_id` | 同一「应用开发商」的所有应用之间统一。开发商是组织层面的概念，不是开发者个人 | 同上，只读 | user_info 直接返回，不需要权限 |
| `user_id` | 每个租户一个；同一用户在租户 A、B 里不同；同一租户内所有应用一致 | 可以由创建用户接口或企业管理员**指定**，不指定才随机生成 | 只有自建应用能取，需要「获取用户 user ID」权限 `contact:user.employee_id:readonly` |

来源：[Lark：用户身份概述](https://open.larksuite.com/document/home/user-identity-introduction/introduction)（定义、只读、可指定）[已验证]；[Lark：如何选择 ID](https://open.larksuite.com/document/home/user-identity-introduction/user-id)（官方推荐「优先使用 Union ID」，user_id 仅自建应用可申请）[已验证]；[Lark：获取用户信息](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get)（权限）[已验证]。

- 一个飞书用户可以同时加入多个租户，每个租户里的身份在逻辑上独立，数据相互隔离。所以同一个自然人在两个租户里是两个 open_id / union_id。[已验证：前半句是原文，「所以」是推断] 同上，用户身份概述。
- `user_id` 不适合做锚点：它由租户管理员指定，是工号一类的业务字段，文档没说不能改，而且商店应用拿不到。[推断]
- `open_id` 和 `union_id` 都由平台生成、对开发者只读，都可以做锚点。区别在于：
  - 用 `open_id`，就绑死在这一个 App ID 上，换应用就全部变成新人；
  - 用 `union_id`，换成同一开发商（企业自建场景下就是同一企业）下的另一个应用，身份仍然连续。[推断]
- `tenant_key` 是租户的唯一标识，user_info 会返回它。[已验证] [Lark：通用参数](https://open.larksuite.com/document/server-docs/getting-started/terminology)

## 4. 应用类型与谁能登录

- **企业自建应用**：用户必须在应用的「可用范围」里（全员，或指定部门和成员）。范围由开发者在发版时设置，企业管理员可以在管理后台改；管理员可以开启「允许不在可用范围内的成员申请使用应用」。[已验证] [Lark：应用可用范围](https://open.larksuite.com/document/home/introduction-to-scope-and-authorization/availability)
  - 范围外的用户换 token 时报 20010（用户没有该应用的使用权限）；租户没装这个应用报 20009。[已验证] [Lark：获取 user_access_token](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/get-user-access-token)
  - 实际效果是**只有本租户成员能登录**。[推断：可用范围的对象只有本租户的组织、用户组和个人]
  - 不需要飞书审核，版本由本企业管理员审核（可以设免审规则），不收费。[未验证：搜索摘要] [飞书：企业自建应用开发流程](https://open.feishu.cn/document/develop-process/self-built-application-development-process?lang=zh-CN)
- **商店应用（ISV）**：其他租户的管理员安装后，该租户的成员才能用。上架分三种：
  - 全量：所有 Lark 用户（个人版和团队版租户）可见，从应用中心安装；
  - 非公开：同样可见，但要有安装链接才能装；
  - 定向：只对灰度范围内的团队版租户可见，最多 30 个。
  [已验证] [Lark：应用可用范围](https://open.larksuite.com/document/home/introduction-to-scope-and-authorization/availability)
  - 上架要经过平台审核；ISV 入驻要求企业成立 1 年以上、完成企业租户认证，申请人必须是企业管理员身份的正式员工；全量公开上架要交保证金（金额没写）；审核 3 个工作日内完成。[已验证：Lark 版] [Lark：服务商入驻](https://open.larksuite.com/document/isv-guides/publish-your-app/step1-complete-the-entry) 飞书版的入驻门槛可能不同。[未验证] [飞书：服务商入驻](https://open.feishu.cn/document/isv-guides/publish-your-app/step1-complete-the-entry?lang=zh-CN)
- **个人用户（没有企业）**：只能用商店应用（全量或非公开上架），不能用自建应用。[已验证：Lark 可用范围页明确全量 / 非公开上架包含个人版租户；「个人版只能用商店应用」这句来自飞书页的搜索摘要，未验证] [飞书：应用类型与能力](https://open.feishu.cn/document/platform-overveiw/overview?lang=zh-CN)
- **对 Polaris 的含义** [推断]：
  - 绝大多数 Operator 会用企业自建应用，这样「用飞书登录」等于「本企业员工登录」，正好是 B 端内部系统的场景。
  - 想让任意飞书用户（包括个人版）登录，就得以 ISV 身份上架商店应用，门槛是企业资质加审核。
  - 两种应用走的是同一套授权和 token 接口，Polaris 的代码不用区分。

## 5. 客户端内网页与原生 App

- **端内网页（H5 / 网页应用免登）**：
  - Lark 5.1 起推荐的新方案：前端调 JSAPI `tt.requestAccess` 拿临时授权码，后端用它调「获取 user_access_token」，再调「获取用户信息」。平台校验的是「当前访问 URL」，而不是 redirect_uri。[已验证] [Lark：应用免登概述](https://open.larksuite.com/document/uYjL24iN/ukTO4UjL5kDO14SO5gTN)
  - 端内的 code 有效期 3 分钟，只能用一次。[未验证：搜索摘要] [飞书：客户端内网页应用接入指南](https://open.feishu.cn/document/sso/web-application-end-user-consent/webapp-incremental-authorization-access-guide?lang=zh-CN)
  - 旧方案就是在端内走重定向到授权页。授权页在客户端内打开时会免确认直接回跳。[已验证] 同上，以及 [Lark：获取授权码](https://open.larksuite.com/document/common-capabilities/sso/api/obtain-oauth-code)
  - **结论** [推断]：在飞书客户端里打开 Polaris 的托管登录页，点「飞书登录」走同一个重定向流程照样能用，而且免确认，体验接近免登。真正的「打开即登录」要 Polaris 的页面调 `tt.requestAccess`，还要引入飞书 JSSDK，一期不需要。
- **原生 App（iOS / Android / Harmony）登录 SDK** [未验证：搜索摘要] [飞书：移动应用登录概述](https://open.feishu.cn/document/common-capabilities/sso/mobile-app/mobile-app-overview?lang=zh-CN)、[飞书：SDK 开发文档](https://open.feishu.cn/document/common-capabilities/sso/mobile-app/sdk?lang=zh-CN)：
  - SDK 拉起飞书客户端授权，回跳 App 后拿到 `code`。挑战码模式（iOS 回调、Android `setChallengeMode`）会同时给出 `code_verifier`。
  - 服务端用 code（以及 verifier）调同一个 v2 token 端点。
  - SDK 文档里有一段提示：SDK 封装的能力有限，不再推荐依赖它。原文没读到，需复核。
  - 对 Polaris 的含义 [推断]：服务端要做的就是「拿 App 提交的 code（加 code_verifier）换 token，再查 user_info」。现在的 `ClientToken(value string)` 只收一个字符串，要么把 code 和 verifier 编码进一个值，要么扩展接口。原生 SDK 登录一期不建议做。

## 6. 重新认证、撤销与解绑

- **强制重新登录**：没找到 `prompt=login` 或 `max_age`。飞书文档有 `prompt=consent`，只是强制展示授权确认页，不要求重新输密码。[未验证：搜索摘要] [飞书：获取授权码](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
  - Lark 版页面连 `prompt` 都没列。[已验证] [Lark：获取授权码](https://open.larksuite.com/document/common-capabilities/sso/api/obtain-oauth-code)
  - 响应里也没有 `auth_time`。[已验证，见 1.3、1.4]
  - 所以要实现 `NoReauthPrompt`，与 ADR 0013 对 OAuth2 的处理一致。
- **撤销 token / 解绑**：没找到主动撤销 user_access_token 或取消授权的 HTTP 接口。权限列表里有一个 `auth:user_access_token:read`，能收到「撤销用户授权事件」，说明撤销是用户侧发起、平台推事件。[未验证：搜索摘要] [飞书：API 权限列表](https://open.feishu.cn/document/ukTMukTMukTM/uYTM5UjL2ETO14iNxkTN/scope-list?lang=zh-CN)
  - Polaris 不保存飞书 token，不需要 `Unlinker`。[推断]
- refresh_token 只能用一次，刷新后旧的那对作废。[已验证] [Lark：获取 user_access_token](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/get-user-access-token) 与 Polaris 无关：我们不要 `offline_access`。

## 7. 飞书与 Lark 的差异

| | 飞书 | Lark |
|---|---|---|
| 开发者后台 / 文档 | open.feishu.cn | open.larksuite.com |
| 授权端点主机 | accounts.feishu.cn [推断] | accounts.larksuite.com [已验证] |
| API 主机（token、user_info） | open.feishu.cn [token 未验证：搜索摘要；user_info 推断] | open.larksuite.com [已验证] |
| 路径与参数 | 相同 | 相同 |

- 两者是不同主体运营的独立产品，账号**不互通**：Lark 账号只能登录 Lark 客户端，飞书账号只能登录飞书客户端。[未验证：搜索摘要] [Lark 帮助中心](https://www.larksuite.com/hc/en-US/articles/499556070769-lark-accounts-cannot-log-in-to-the-current-app)、[飞书帮助中心](https://www.feishu.cn/hc/zh-CN/articles/677730326802)
- 应用也分别在两个后台创建，App ID 和 secret 不能混用。[推断]
- 同一套代码，只换主机就能支持两边。[推断：路径、参数和响应结构在两边文档一致]

## 8. 开发者自测清单（企业自建应用）

1. 准备一个飞书（或 Lark）企业租户，自己是管理员。个人版不能用自建应用；可以免费创建团队租户。[推断]
2. 打开 [open.feishu.cn/app](https://open.feishu.cn/app)（Lark 是 open.larksuite.com/app），创建**企业自建应用**。
3. 在「凭证与基础信息」里记下 App ID（`cli_` 开头）和 App Secret，分别对应 Polaris 的 client_id 和 client_secret。[已验证]
4. 「开发配置 > 安全设置 > 重定向 URL」里加上 `https://<issuer>/login/providers/<id>/callback`（见 `provider.CallbackURL`）。本地测试也要加上本地的回调地址。[已验证：配置位置]
5. 权限：只取 open_id / union_id 的话**不需要开通任何权限**，scope 留空即可。[已验证：user_info 页「无」权限、授权端点 scope 可选] 不要开 `offline_access`、`contact:user.email:readonly` 之类，Polaris 用不上。
6. 是否要先在「添加应用能力」里启用「网页应用」能力，文档没写明。[未验证，实测时确认]
7. 创建版本，可用范围选自己或测试部门，发布并由管理员审核通过。不发布的话，权限和配置不生效。[已验证：「发布应用使配置生效」，见 [Lark：浏览器网页接入指南](https://open.larksuite.com/document/common-capabilities/sso/web-application-end-user-consent/guide)]
8. 实测要点：
   - token 端点是否接受 form 体，还是只认 JSON；
   - authorize 带 `response_type=code` 会不会报错；
   - `code_challenge_method=S256` 是否生效：给一个错误的 verifier，应当报 20049；
   - 范围外的成员登录应报 20010；
   - 飞书客户端内打开登录页是否免确认；
   - 同一用户的 union_id 在两个应用之间是否一致（再建一个自建应用对照）。

## 对 Polaris 的建议

- **实现成独立类型包 `internal/provider/feishu`**，同一个包注册两个类型：`feishu`（飞书）和 `lark`（Lark），只有主机不同。不建议给通用 OAuth2 加「JSON 请求体」和「嵌套 ID 路径」两个开关：那会推翻 ADR 0013 的两条固定决定，而且只为一家服务。独立包的代码量小：授权 URL 与通用类型一样（可以照抄或导出复用），token 用 JSON 请求，user_info 读 `code` 和 `data.union_id`。[推断]
- **主机放进类型，不做配置**：飞书和 Lark 的账号与 ID 完全不相通，把它做成类型 key（加 Provider 时就定了，永远不变），比加一个必须 Immutable 的 `region` 字段简单。`channel.Field` 也没有下拉类型。
- **锚点用 `union_id`**：
  - 官方推荐优先用它；不需要权限，自建和商店应用都能拿到；由平台生成、只读。
  - 管理员换成同一企业下的另一个应用，身份不断。
  - 不用 `user_id`：管理员可以指定，商店应用也拿不到。
  - 也不用 `open_id`：它绑死 App ID，换应用就全员变成新人。
- **配置字段**：
  - `client_id`（App ID，text）、`client_secret`（App Secret，Secret）。
  - 以 union_id 为锚点时两者都**不必 Immutable**。如果锚点改用 open_id，`client_id` 必须 Immutable。
  - 如果换成另一个开发商的应用，union_id 全部变化，结果是「全员变成新人」而不是「认错人」。所以 `client_id` 可以不锁，但 Help 里要写明「只能换成同一企业下的应用」。
  - 不要 scope 字段（留空即可）。
  - 可选：`tenant_key` 限制只接受某个租户。自建应用本来就只有本租户成员能登录，一期不需要。
- **行为**：
  - 实现 `NoReauthPrompt`，因为没有 prompt=login 和 max_age；`AuthTime` 留零值。
  - 不实现 `Unlinker`：没有撤销接口，也不保存 token。
  - 不实现 `ClientToken`：原生 SDK 一期不做。
  - user_info 返回的 `code` 不是 0 时，要按错误处理，把 20021（离职）、20022（冻结）的意思带进错误信息。

## 9. 浏览器复核（2026-11-04）

用浏览器直接打开 open.feishu.cn 原页核对，修正与补充前文：

- **授权端点** `https://accounts.feishu.cn/open-apis/authen/v1/authorize` [已验证]。`response_type=code` 是**必填**（不是可选），`code_challenge` / `code_challenge_method`（S256 推荐，默认 plain）支持，`prompt` 只有 `consent` 一个值，没有 `prompt=login`。code 有效 5 分钟、一次性。用户拒绝时回调带 `error=access_denied`。在飞书客户端内打开可免确认直接跳转。[飞书：获取授权码](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
- **令牌端点已升级到 v3**：v2（`open.feishu.cn/open-apis/authen/v2/oauth/token`）已标为「历史版本，不推荐使用」，新端点是 `https://accounts.feishu.cn/oauth/v3/token`。v3 的请求体**推荐 `application/x-www-form-urlencoded`，也兼容 JSON**；参数与 v2 相同（grant_type、client_id、client_secret、code、redirect_uri、code_verifier），client_secret 放请求体（同时用 Basic 认证会报 20070）。v3 修正了 v2 的 PKCE 漏洞：授权时没传 code_challenge、换 token 时却传了 code_verifier，v2 不拒绝，v3 拒绝。响应顶层带 `code`（0 成功），`access_token` 在顶层。[已验证] [飞书：获取 user_access_token（v3）](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/get-user-access-token-v3)、[v2 历史页](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token)
- **Lark 没有 v3 页面**：`open.larksuite.com` 同路径返回「文档不存在」，Lark 仍按 v2（`open.larksuite.com/open-apis/authen/v2/oauth/token`，JSON 请求体）。[已验证：页面不存在] → 两边都发 JSON 请求体即可共用一份实现（v3 兼容 JSON）。Lark 是否也有 `accounts.larksuite.com/oauth/v3/token` 端点 [未验证，实测时确认]。
- **用户信息** `GET https://open.feishu.cn/open-apis/authen/v1/user_info`，`Authorization: Bearer <user_access_token>`，**无需权限**，响应 `{code, msg, data:{open_id, union_id, tenant_key, name, ...}}`；`user_id`、手机号、邮箱要额外权限且仅自建应用；文档明说手机号、邮箱是管理员导入的、未经本人验证，不建议当登录凭证。用户离职/冻结时返回 20021/20022（HTTP 200）。[已验证] [飞书：获取用户信息](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get)
- **对建议的修正**：token 端点在飞书侧已是标准形状（form + client_secret_post），与通用 OAuth2 的差异只剩 ① userinfo 的 ID 嵌在 `data.union_id`、成败看 `code`；② Lark 只能 JSON。仍建议独立包，但 token 请求统一用 JSON。
