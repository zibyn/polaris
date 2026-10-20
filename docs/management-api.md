# Management API 接入指南

业务后端以 **M2M Application** 的身份调用 Management API:管理 User、Application、API 资源、Role 与配置。本指南讲怎么创建这样一个 Application、换令牌、需要哪些 Permission;端点、请求体与响应字段的权威定义在 `{issuer}/v1/management/openapi.json`。

概念见 [rbac.md](spec/rbac.md) 与 [GLOSSARY.md](../GLOSSARY.md);管理端界面是同一套接口的另一个调用方,见 [consoles.md](spec/consoles.md)。

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

## 各接口所需 Permission

| Permission | 接口 |
|---|---|
| 任一 Role | `GET /me` |
| `users:read` | `GET /users`、`GET /users/{sub}`、`GET /users/{sub}/sessions`、`GET /users/{sub}/passkeys`、`GET /users/{sub}/external-identities`、`GET /overview`、`GET /roles` |
| `users:write` | `POST /users`、`POST` / `DELETE /users/{sub}/invite`、`POST /users/{sub}/disable`、`POST /users/{sub}/enable`、`DELETE /users/{sub}`、`DELETE /users/{sub}/2fa`、`PUT /users/{sub}/identifiers/{kind}`、`DELETE /users/{sub}/sessions/{id}`、`DELETE /users/{sub}/passkeys/{id}`、`DELETE /users/{sub}/external-identities/{provider}` |
| `audit:read` | `GET /audit` |
| `applications:read` | `GET /apis`、`GET /applications`、`GET /applications/{clientId}`、`GET /applications/{clientId}/roles` |
| `applications:write` | `PUT` / `DELETE /apis/{api}`、`PUT` / `DELETE /apis/{api}/permissions/{key}`、`PUT` / `DELETE /apis/{api}/roles/{key}`、`POST /applications`、`PUT` / `DELETE /applications/{clientId}`、`POST /applications/{clientId}/secret` |
| `roles:assign` | `PUT /users/{sub}/roles`、`PUT /applications/{clientId}/roles` |
| `config:read` | `GET /channels`、`GET /providers`、`GET /settings`、`GET /signing-keys` |
| `config:write` | `PUT` / `DELETE /channels/{kind}`、`POST /channels/{kind}/test`、`POST /providers`、`PUT` / `DELETE /providers/{id}`、`POST /providers/{id}/enable`、`POST /providers/{id}/disable`、`PUT /settings` |
| `keys:rotate` | `POST /signing-keys/rotate` |

除表里的 Permission,还有这几条附加规则:

- **给 User 管理员权限**:`PUT /users/{sub}/roles` 设置 Management API 上的 Role 时,除 `roles:assign` 还需 `admin-roles:assign`。
- **对管理员动手**:目标 User 在 Management API 上持有 Role 时,`users:write` 里的写操作(禁用、删除、重置两步验证、替换登录标识、删除 Passkey、解绑外部账号、发出或撤销邀请)还需 `admin-roles:assign`。
- **改 Management API 自己的定义**:定义、修改或删除 Management API 上的自定义 Role 还需 `admin-roles:assign`;它内置的 API、Permission 与 Role 一律不可改(`409`)。
- **最后一个所有者**:不能被删除、禁用或降级(`409`)。

「业务 API 的默认 Role」只在 User 创建时授予,不作用于 Application;M2M Application 拿到的 Role 全靠显式分配。

## 版本与兼容

**0.x 期间不承诺兼容**:接口、请求体、Permission 都可能在任何小版本里变。升级前先看 [Releases](https://github.com/zibyn/polaris/releases) 的 changelog。1.0 起接口冻结。
