# 集成方接入指南

Application 接入 Polaris 有两种集成模式:

- **API 集成模式**:运营方在自己的后台里管理 User,背后以 **M2M Application** 的身份调用 Management API:管理 User、Application、API 资源、Role 与配置。本指南的大部分内容讲这种模式:怎么创建这样一个 Application、换令牌、需要哪些 Permission、常见需求怎么做。
- **托管集成模式**:Application 自己不做用户相关界面,登录和自助管理交给托管页与账号中心,管理员直接用 Polaris 管理端,见[托管集成模式](#托管集成模式)。

两种模式下 User 登录都由 Polaris 完成。端点、请求体与响应字段的权威定义在 `{issuer}/v1/management/openapi.json`。

概念见 [rbac.md](spec/rbac.md) 与 [GLOSSARY.md](../GLOSSARY.md);管理端界面是同一套接口的另一个调用方,见 [consoles.md](spec/consoles.md)。

## 信任边界

**Management API 上的 Role 是实例级的**(ADR 0031):持有它的 M2M Application 看到、操作的是**整个用户池**,不只是"自己那个 Application 的 User"。Polaris 没有"User 属于某个 Application"的关系,也就没有按 Application 收窄的授权或 `?application=` 筛选。给集成方的 M2M Application 授予 Management API Role,就等于把整个用户池托付给它。

- **只授最小 Permission**。只要查人就只给 `users:read`;别默认给「管理员」。
- `users:write` 是一个整体:它包含替换 Identifier(`PUT /users/{sub}/identifiers/{kind}`),也就等于能接管任意非管理员账号(对管理员动手还需 `admin-roles:assign`)。
- `roles:assign` 能分配任何业务 API 上的 Role,包括别的集成方的 API。
- 全局禁用、删除会影响该 User 在**所有** Application 的使用;其他 Application 通过 Webhook 的 `user.disabled` / `user.deleted` 得知。只想在一个 Application 里挡住某人,见[常见做法](#常见做法)。
- 需要不同集成方之间真正隔离,就另起一个 Polaris 实例。

## 创建 M2M Application

M2M Application 只以自己的身份调一个 API,没有登录界面。要调 Management API,就把它的默认 API 设为 Management API:

```bash
curl -X POST "$ISSUER/v1/management/applications" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "m2m",
    "settings": {
      "name": "部署脚本",
      "defaultApi": "urn:polaris:management-api"
    }
  }'
```

- 需要 `applications:write`。管理员在管理端登录后拿到的 access token 也能调这个接口。
- 响应里的 `secret` 是它的 client secret,**只回显这一次**,记下来。丢了用 `POST /applications/{clientId}/secret` 换一把新的。
- `urn:polaris:management-api` 是内置 Management API 的标识符,也是它签发的 access token 的 `aud`。
- 也可以在管理端「应用」列表里用「后端服务(M2M)」卡片创建,再回来分配角色。

再给它分配 Role。它必须在 Management API 上持有至少一个 Role,否则任何接口(包括 `GET /me`)都返回 `403`:

```bash
curl -X PUT "$ISSUER/v1/management/applications/$CLIENT_ID/roles" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"roles": ["readonly"]}'
```

- 需要 `roles:assign`;目标是 Management API,所以还需 `admin-roles:assign`。
- 可分配内置的「管理员」「只读」或自定义 Role。「所有者」代表自然人,不能分配给 Application。
- 整体替换:请求里没列出的 Role 会被撤销。
- **实时鉴权**:改 Role、撤销 Role 或删除 Application,下一次请求就按新状态判断,不用等令牌过期。

## 换令牌

`client_credentials`,用 HTTP Basic 认证(secret 放 body 会被拒):

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  "$ISSUER/token"
```

- 只有 M2M Application 能用这个 grant。
- 请求里的 `scope` 被忽略:令牌的 `aud` 就是它的默认 API,`roles` / `entitlements` 只含那个 API 下的。
- **没有 refresh token**。access token 寿命 10 分钟,过期就再换一张。
- M2M Application 不需要两步验证或 Passkey,也不受「管理员必须启用两步验证或 Passkey」约束。

## 调用接口

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$ISSUER/v1/management/users?limit=50"
```

## 创建 User

给一个标识符,再**二选一**:一个初始密码,或一封**注册邀请**(`"invite": true`,此时标识符必须是邮箱)。两种情况账号都进入**待激活**:本人用初始密码登录时被要求先设置自己的密码,或点邮件里的链接自己设一个,设完才拿得到令牌。管理员代填的手机号或邮箱**直接算已验证**,不发验证邮件、不消耗验证码条数——与 GitLab 建号时替用户确认邮箱、Keycloak 的 Email Verified 勾选同形,填错由管理员线下核对承担。密码登录关闭时返回 `422`(两条路都要走密码,所以一起被挡)。

```bash
curl -X POST "$ISSUER/v1/management/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "13800001234", "password": "initial-password"}'
```

```bash
# 发注册邀请: 管理员看不到也设不了本人的密码
curl -X POST "$ISSUER/v1/management/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com", "invite": true}'
```

- `identifier` 是手机号、邮箱或用户名任一,按既有口径归一化。
- 两个字段都给、或都不给,返回 `422`;选邀请时标识符必须是邮箱,否则返回 `422` 并说明是这个原因。
- 标识符已被别的 User 占用时返回 `409`;建出的 User 照常获得业务 API 的默认 Role。
- 响应里的 `pending: true` 表示待激活;`GET /users?status=pending` 按状态筛选,详情与列表都带这个字段。
- 选邀请但信发不出去时同样返回 `422`,**账号却已经建好**了(它和它的审计都落了库),所以这条 `422` 的正文会说明这一点并指出重发的位置:照原样重试撞的是 `409`。

## 发出与撤销注册邀请

对**已有** User 也能发,已经激活的也一样——那是忘了密码的人回得来的那条路。链接 7 天有效、一次性,重发就是拿新的换掉旧的,旧链接**立刻**不可用。

```bash
curl -X POST "$ISSUER/v1/management/users/$SUB/invite" -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN"
curl -X DELETE "$ISSUER/v1/management/users/$SUB/invite" -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN"
```

- 两个都是 `204`;撤销一条本来就没有的邀请也返回 `204`,但不算一次撤销、不留审计。
- 账号没有邮箱、实例没配邮箱 Channel、或密码登录已关闭时,`POST` 返回 `422` 并说明原因;邮件发不出去时返回 `422`,并且**不会留下可用链接**(账号本身还在,重发即可)。
- 对已有 User 只有这一条路:Management API 不提供替本人设密码的接口。
- 邀请现在是什么状态,`GET /users/{sub}` 的 `invite` 字段说得出:`{"state": "none" | "sent" | "accepted"}`,`sent` 时带 `expiresAt`(链接失效的时刻,发出后 7 天)。`accepted` 是上一条已经被本人用掉;撤销过、过期、从来没发过,一律是 `none`——过期的不用等清理任务扫掉那行,对调用方来说都是"没有能用的链接"。`accepted` 靠审计日志里的 `invite.accepted` 认出来,日志过了保留期(默认 180 天)这条就回落到 `none`:同样按"没有能用的链接"处理即可。

## 指定 Application 的登录方式

`ApplicationSettings` 的 `loginMethods` 不填就是**跟随实例**(默认):实例开着的登录方式、启用的 Provider 都能用,以后新加的也算。填了就只用这几种,且实例也得开着(ADR 0027):

```json
"loginMethods": {"methods": ["sms", "password"], "providers": ["corp-sso"]}
```

- `methods` 取 `sms`、`email`、`password`、`passkey`;`providers` 是 Provider ID,必须已存在,删除 Provider 时自动从各 Application 里去掉。
- 两个都空、M2M Application 带这一项、或者内置的管理端与账号中心带这一项,返回 `422`。
- `PUT /applications/{clientId}` 整体替换设置:改别的字段时要把 `loginMethods` 原样带回,漏掉就回到跟随实例。
- 读出来的 Application 多一个只读的 `noLoginMethod`:为 `true` 时它指定的方式在实例里一个都没开,现在没人能登录它。
- 改设置不吊销已有的 Session 和 refresh token,只影响之后的登录与单点登录判断。

## 英文协议链接

`PUT /settings` 的 `termsUrlEn`、`privacyUrlEn` 可选,须为 https。英文托管页优先链到它们,没填就用 `termsUrl`、`privacyUrl`。`termsVersion` 只有一个,中英文协议算同一版,换语言不会要求重新同意。`PUT /settings` 整体替换:改别的字段时要把它们原样带回。

## 品牌

托管页的品牌(ADR 0028)有三项:品牌名、Logo、主色。实例在 `PUT /settings` 的 `brand` 里设默认,Application 在 `ApplicationSettings` 的 `brand` 里逐项覆盖,没填的项跟随实例:

```json
"brand": {"name": "Acme", "logo": "<上传返回的引用>", "color": "#0a66c2"}
```

- `color` 只收 `#rrggbb`,白字在它上面(也就是它在白底上)的对比度要达到 4.5:1(WCAG AA),否则 `422`。悬停色、浅底和浅底上的文字色由服务端推导。
- Logo 先上传:`PUT /settings/brand/logo` 或 `PUT /applications/{clientId}/brand/logo`,请求体就是图片本身。只收 PNG、WebP、SVG(按内容判断,不看 Content-Type),不超过 1 MB,不重新编码;不合格返回 `422`(超过 2 MB 的请求体是 `413`)。上传当场生效,返回 `{"logo": "<引用>"}`,旧 Logo 同一事务里删掉。Logo 公开在 `/brand-logos/{logo}`,响应带 `Content-Security-Policy: sandbox` 和 `X-Content-Type-Options: nosniff`。`DELETE` 同一路径去掉 Logo。
- `PUT` 时 `brand.logo` 只能原样带回当前的引用,或留空去掉 Logo;别的值返回 `422`。
- `PUT /settings` 和 `PUT /applications/{clientId}` 都是整体替换:漏带 `brand` 就清空实例品牌,或让 Application 回到全部跟随实例(它自己的 Logo 一并删掉)。
- 内置 Application 和 M2M Application 不能带品牌,带了返回 `422`。
- 改动记入审计:实例的记 `settings.updated`,Application 的记 `application.updated`。

## 各接口所需 Permission

| Permission | 接口 |
|---|---|
| 任一 Role | `GET /me` |
| `users:read` | `GET /users`、`GET /users/{sub}`、`GET /users/{sub}/sessions`、`GET /users/{sub}/passkeys`、`GET /users/{sub}/external-identities`、`GET /overview`、`GET /roles` |
| `users:write` | `POST /users`、`POST` / `DELETE /users/{sub}/invite`、`POST /users/{sub}/disable`、`POST /users/{sub}/enable`、`DELETE /users/{sub}`、`DELETE /users/{sub}/2fa`、`PUT /users/{sub}/identifiers/{kind}`、`DELETE /users/{sub}/sessions/{id}`、`DELETE /users/{sub}/passkeys/{id}`、`DELETE /users/{sub}/external-identities/{provider}` |
| `audit:read` | `GET /audit` |
| `applications:read` | `GET /apis`、`GET /applications`、`GET /applications/{clientId}`、`GET /applications/{clientId}/roles` |
| `applications:write` | `PUT` / `DELETE /apis/{api}`、`PUT` / `DELETE /apis/{api}/permissions/{key}`、`PUT` / `DELETE /apis/{api}/roles/{key}`、`POST /applications`、`PUT` / `DELETE /applications/{clientId}`、`POST /applications/{clientId}/secret`、`PUT` / `DELETE /applications/{clientId}/brand/logo` |
| `roles:assign` | `PUT /users/{sub}/roles`、`PUT /applications/{clientId}/roles` |
| `config:read` | `GET /channels`、`GET /providers`、`GET /settings`、`GET /signing-keys` |
| `config:write` | `PUT` / `DELETE /channels/{kind}`、`POST /channels/{kind}/test`、`POST /providers`、`PUT` / `DELETE /providers/{id}`、`POST /providers/{id}/enable`、`POST /providers/{id}/disable`、`PUT /settings`、`PUT` / `DELETE /settings/brand/logo` |
| `keys:rotate` | `POST /signing-keys/rotate` |

除表里的 Permission,还有这几条附加规则:

- **给 User 管理员权限**:`PUT /users/{sub}/roles` 设置 Management API 上的 Role 时,除 `roles:assign` 还需 `admin-roles:assign`。
- **对管理员动手**:目标 User 在 Management API 上持有 Role 时,`users:write` 里的写操作(禁用、删除、重置两步验证、替换登录标识、删除 Passkey、解绑外部账号、发出或撤销邀请)还需 `admin-roles:assign`。
- **改 Management API 自己的定义**:定义、修改或删除 Management API 上的自定义 Role 还需 `admin-roles:assign`;它内置的 API、Permission 与 Role 一律不可改(`409`)。
- **最后一个所有者**:不能被删除、禁用或降级(`409`)。

「业务 API 的默认 Role」只在 User 创建时授予,不作用于 Application;M2M Application 拿到的 Role 全靠显式分配。

## 常见做法

### 用 Role 表达会员等级等业务分级

Polaris 不存 Application 的业务数据(ADR 0032):没有 `app_metadata` 式的自定义字段,也没有往 token 里塞任意 claim 的模板。工号这类自由文本,集成方以 `sub` 为键存在自己库里。

**分级或资格类**字段(会员等级、是否内测用户)则建成集成方自建 API 上的 Role:它会出现在发给该 API 的 access token 的 `roles` 里,能按它查人,变更也会触发 Webhook(`user.updated`,`changed` 含 `roles`)。

```bash
# 注册自己的 API 和一个 Role(需要 applications:write)
curl -X PUT "$ISSUER/v1/management/apis/urn:acme:shop" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "商城"}'
curl -X PUT "$ISSUER/v1/management/apis/urn:acme:shop/roles/gold" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "金卡会员", "permissions": []}'

# 给 User 定级(需要 roles:assign);整体替换,该 API 上没列出的 Role 会被收回
curl -X PUT "$ISSUER/v1/management/users/$SUB/roles" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"api": "urn:acme:shop", "roles": ["gold"]}'

# 查所有金卡会员(需要 users:read)
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$ISSUER/v1/management/users?api=urn:acme:shop&role=gold"
```

API 标识符放进路径时要 URL 转义(`https://api.acme.com` 写成 `https%3A%2F%2Fapi.acme.com`)。

### 只在一个 Application 里禁用 User

全局禁用(`POST /users/{sub}/disable`)会挡住这个人的所有 Application。只想挡在一个 Application 外面:

1. 给该 Application 设默认 API,并开启「要求持 Role」(`ApplicationSettings` 的 `requireRole: true`)。
2. 用 `PUT /users/{sub}/roles` 收回这个 User 在该 API 上的全部 Role(`"roles": []`)。

收回后他拿不到授权码,refresh token 下次刷新时被拒;已签发的 access token 到期前仍有效。重新授予 Role 即恢复。不另设"按 Application 禁用"的接口。

### 「用户管理员」式的自定义 Role

托管集成模式下,集成方的运营人员要登录 Polaris 管理端管人、但不该碰实例配置时,在 Management API 上建一个自定义 Role:

```bash
# 需要 applications:write 和 admin-roles:assign
curl -X PUT "$ISSUER/v1/management/apis/urn:polaris:management-api/roles/user-admin" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "用户管理员", "permissions": ["users:read", "users:write", "roles:assign"]}'
```

再用 `PUT /users/{sub}/roles`(`"api": "urn:polaris:management-api"`)分给运营人员,同样需要 `admin-roles:assign`。管理端按 Permission 显示导航,持这个 Role 的人只看得到概览和用户页。

要清楚它的边界:它**看得到、改得了整个用户池**,不只是某个 Application 的 User;`roles:assign` 能分配任何业务 API 上的 Role。它没有 `admin-roles:assign`,所以动不了其他管理员(在 Management API 上持有 Role 的 User),也给不了别人 Management API 上的 Role。Polaris 不按 Application 委派管理员,需要隔离就另起实例。

## 导入已有用户

> 本节描述的全部行为(只带 Identifier 或附带密码哈希建号、`409` 的 body 带 `sub`)随 [#151](https://github.com/zibyn/polaris/issues/151) 上线;在那之前 `POST /users` 只能按上文建待激活 User,`409` 也不带 `sub`。

把原系统的用户搬进 Polaris,就是对每个人调一次 `POST /users`(ADR 0033),不设批量接口:几万用户逐个调也只要几分钟。

- 只带 `identifier`:建出的是**正常** User,不进待激活,他用验证码登录即可。
- 再附带原密码哈希:他还能用原密码登录。只收 argon2id(PHC 字符串)和 bcrypt(`$2a$`/`$2b$`/`$2y$`),别的格式整个请求 `422`;首次凭它登录成功后 Polaris 转存为 argon2id。
- 代填的手机号、邮箱直接算已验证,由调用方担保。
- 只有用户名的 User 必须带哈希,否则他没有任何可登录途径。
- 密码登录关闭时,带哈希的请求 `422`;只带 Identifier 的照常建。

Identifier 已被占用时返回 `409`,body 里带已有 User 的 `sub`,整个请求不写入任何东西。这通常是那个人已经自己在 Polaris 登录过:直接用这个 `sub` 完成关联即可。

**`sub` 由集成方自己保存**。Polaris 不记集成方原系统的用户 ID(没有 `external_id`),把"旧 ID → `sub`"的对应关系存在你的库里。

## 把 User 同步到你的系统

Webhook 是薄事件(ADR 0022):只告诉你"哪个 `sub` 变了",不带新值。推荐做法:

1. **首次全量**:用 `GET /users?limit=200&offset=…` 翻页,直到 `hasMore` 为 `false`。
2. **收到事件就按 `sub` 回拉**:`GET /users/{sub}` 取当前状态;`404` 说明已删除。`user.updated` 的 `changed` 告诉你哪几项变了,可以只更新这几项。
3. **丢弃过时事件**:投递不保证顺序,重试也可能迟到。为每个 `sub` 记下处理过的最新 `timestamp`,更早的事件直接丢掉。`timestamp` 精确到秒,同一秒的事件照常处理(反正是回拉当前状态)。
4. **定期对账**:投递失败约一天后放弃,所以隔一段时间重跑一遍全量,兜住漏掉的事件。

接收方必须忽略不认识的事件 `type`。Session 终止不走 Webhook,走 Back-Channel Logout,见下一节。

Polaris 不提供 SCIM:入站 SCIM 在各家都是挂在 organization 上的 B2B 功能,而 Polaris 只有一个用户池;Management API 加 Webhook 已能完成同样的同步。

## 托管集成模式

Application 只负责把 User 送到 Polaris 的页面,再接回来。

- **登录**:标准 OIDC authorization code flow,托管页套用 Application 的品牌(见上文[品牌](#品牌))。
- **账号中心**:放一个普通链接 `{issuer}/account?client_id=<client_id>`(ADR 0034)。User 本就经 Polaris 登录,Session 还在就直接进入,过期了照常再登录一次。带 `client_id` 时账号中心用该 Application 的品牌;`client_id` 不存在就按没带处理,不报错。Polaris 不提供可嵌入组件,托管页也不允许被 iframe 嵌入。
- **首页地址**:在 `ApplicationSettings` 的 `homeUrl` 填上(须 https,本机可用 http),账号中心就显示「返回 <Application 名>」链到这里;不填就没有返回入口。账号中心不接受任意的返回地址参数。
- **退出**:把 User 送到 `{issuer}/logout?id_token_hint=<ID token>&post_logout_redirect_uri=<地址>`(RP-Initiated Logout)。`post_logout_redirect_uri` 必须登记在 `postLogoutRedirectUris` 里。
- **Back-Channel Logout**:Session 被主动终止时(User 退出、管理员终止 Session 或禁用、删除 User 等),Polaris 向 Application 的后端 `POST` 一个 `logout_token`,让它同时清掉自己的会话。只有 Web(confidential)Application 能配:在 `ApplicationSettings` 的 `backchannelLogoutUri` 填一个 http(s) 地址,管理端的 Application 编辑页也能设。收到后按 OIDC Back-Channel Logout 1.0 验证 JWT(用 JWKS 验签,核对 `iss`、`aud`、`events`,`exp` 未过期),再结束本地与 `sid` 对应的会话;`sid` 总会带上,与这个 Session 签发的 ID token 里的一致。返回 2xx 视为收到,否则会退避重试。细节见 [protocol.md](spec/protocol.md#back-channel-logout)。

## 生成 client

Polaris 不发布服务端 SDK。spec 由服务端从代码生成,跟实现同步;用工具生成 client 即可:

```bash
# TypeScript 类型
npx openapi-typescript "$ISSUER/v1/management/openapi.json" -o polaris.d.ts

# Go:oapi-codegen 对 OpenAPI 3.1 支持不全,用同一份 spec 的 3.0 版本
curl -o polaris-openapi.json "$ISSUER/v1/management/openapi-3.0.json"
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest \
  -generate types,client -package polaris -o polaris.gen.go polaris-openapi.json
```

## 版本与兼容

- **`/v1` 内只做加法**:新增端点、新增可选字段、新增枚举值。删字段、改语义这类破坏性变更只会出在 `/v2`。
- 集成方要**容忍未知的枚举值和响应里新增的字段**:别用拒收未知字段的严格反序列化,遇到不认识的枚举值按"其他"处理。
- **Account API(`/v1/account`)是内部接口**,只供 Polaris 自己的账号中心调用,随时可能变,不在承诺范围内。
- 升级前看 [Releases](https://github.com/zibyn/polaris/releases) 的 changelog。
