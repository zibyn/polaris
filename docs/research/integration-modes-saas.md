# SaaS 认证服务商的两种集成模式

- 调研日期：2026-11-05
- 问题（[#172](https://github.com/zibyn/polaris/issues/172)，属于 [#171](https://github.com/zibyn/polaris/issues/171)）：Auth0、Clerk、WorkOS、Stytch、Descope、Kinde、Firebase / Identity Platform、AWS Cognito、Entra External ID、Authing、Logto Cloud 各自怎样支持 **API 集成模式**和**托管集成模式**（术语见 `GLOSSARY.md`）。
- 范围：只看集成。协议和登录能力已在 [auth-market-survey.md](auth-market-survey.md) 里讲过，本文不再重复。
- 用途：给以下 grilling ticket 提供对照材料：[#174](https://github.com/zibyn/polaris/issues/174) 可见范围、[#175](https://github.com/zibyn/polaris/issues/175) 写操作、[#176](https://github.com/zibyn/polaris/issues/176) 应用自定义数据、[#177](https://github.com/zibyn/polaris/issues/177) 委派管理员、[#178](https://github.com/zibyn/polaris/issues/178) 导入与关联、[#179](https://github.com/zibyn/polaris/issues/179) SDK / 文档形态。

## 0. 怎么读这份文档

- **第 1 节是结论速览，第 2 节按维度给出对比表，第 3 节写对 Polaris 的启示，附录是逐家的取证记录。** 每条非显然结论都在附录里附了一手来源：官方文档、API reference、官方 OpenAPI / 源码、定价页。
- 我自己的判断标 **【推断】**。拿不到一手来源的标 **未验证**，没有凭记忆补。
- 取证方式：四路并行调查，按厂商分组：
  - Auth0 / Clerk / Kinde
  - WorkOS / Stytch / Descope
  - Firebase / Cognito / Entra
  - Authing / Logto
  - Clerk、Kinde、Logto、Authing 的部分结论直接取自它们公开的 OpenAPI 文件或 SDK / 服务端源码，比文档页可靠。
- **取证局限**，读的时候请留意：
  - **AWS 文档站和 docs.authing.cn 在调研环境里连不上**（TLS 被断开）。Cognito 的事实和 Authing 的大部分文档类事实来自 WebSearch 返回的官方页面摘要，标为「（搜索摘要）」，可信度比直接读页面低一级。Authing 的 API 事实另外来自官方 SDK 源码。
  - 部分 WebFetch 结论是摘要模型转述，不是逐字引用，主要是 WorkOS widget 的权限名和 Stytch 的 RBAC 请求头。写进设计文档前，建议回到原链接核对一次。
  - 以上全部是只读调研，没有在真实租户里实测。

## 1. 结论速览

**已验证的事实**

1. **没有一家能把 Management API 凭据限定到「某个 Application 的用户」。** 用户池是 tenant、project 或 user pool 级的，所有应用共享。能做到的最细隔离单位，各家不同：
   - **tenant**：Identity Platform 在 tenant 上授 IAM。
   - **user pool**：Cognito 的 IAM 可限定到 pool ARN。
   - **organization**：Kinde 的 org-scoped M2M（Plus / Scale）；Auth0 的 My Organization API（用户级 token）；Stytch B2B 以成员 session 代理调用。
   - **project 或 tag**：Descope 的 Management Key。

   WorkOS、Clerk、Stytch 的 `organization_id` 只是查询参数，不是权限边界。
2. **Management API 授权粒度分三档：**
   - **全权 secret**：Clerk、WorkOS、Stytch、Logto Cloud（只有一个 `all` scope）。
   - **按资源 × 动作的 scope**：Auth0（`read:users` 等）、Kinde（`read/create/update/delete:users`）。
   - **云 IAM 或目录权限，粒度最细**：Firebase / Identity Platform、Cognito、Entra Graph。Entra 甚至把「改启用状态」「改密码」「改手机号」拆成了各自独立的权限。

   Descope 处在中间：按 project 授角色，读、读写、审计分开。
3. **禁用、删除、全量下线一律作用于整个用户池，即所有应用。** 只有 Authing 的 `kickUsers` 要求传入 `appIds`，可以只让用户在指定应用下线。禁用状态本身也不是人人都有：
   - **WorkOS 和 Stytch Consumer 没有 disable 状态**。Stytch 只有 `pending/active/deleted`。
   - Stytch B2B 有 Reactivate Member，可以恢复已删除的成员。
4. **自定义用户数据普遍是全局一份，没有「每个应用一份」。** 各家都分了「用户可写」和「仅后端可写」两类：
   - Auth0：`user_metadata` 和 `app_metadata`。
   - Clerk：`public`、`private`、`unsafe` 三类。
   - Stytch：`trusted` 和 `untrusted`。

   进 token 的方式有两种：
   - **配置模板**：Clerk、WorkOS、Stytch、Descope、Kinde。
   - **脚本或钩子**：Auth0 Actions、Logto、Authing Pipeline、Firebase blocking functions、Cognito pre-token Lambda、Entra custom claims provider。

   能「按应用决定放哪些 claim」的有：
   - Kinde：在每个 application 上勾选要放进 token 的 property。
   - Entra：custom claims provider 可以分配给一个或多个应用。
   - Authing：每个应用可以自定义 OIDC scope 和 claim（搜索摘要）。
   - Cognito：按 app client 设置属性读写权限。
5. **委派管理员：「只管一个应用」的管理端角色几乎没有。**
   - **只有 Authing** 明确支持「一个应用一个管理员」（应用管理员，搜索摘要）。
   - Entra 可以把角色限定到单个 app registration，但外部租户里只开放 Cloud Application Administrator，管不到用户。
   - 其他家的 dashboard 角色都作用于整个 tenant，例如 Auth0 的 Admin / Viewer / Editor、Clerk 的 Owner / Admin / Developer / Support / Viewer、Kinde、Logto 的 Admin / Collaborator / Viewer。

   主流的委派单位是 **organization**，而且形态是**嵌进集成方自己产品里的组件**：
   - WorkOS Users Management widget。
   - Stytch B2B Admin Portal 组件。
   - Descope Admin Widgets，以及按 tenant 隔离的托管 Admin Portal。
   - Auth0 Universal Components 加 My Organization API。
   - Clerk `<OrganizationProfile/>`。
6. **账号中心：**
   - **有托管页**的是 Clerk（Account Portal）、Kinde（self-serve portal，由一次性链接进入）、Logto（`/account/*`）、Authing（`/u`，搜索摘要）、Descope（托管 Admin Portal 和 User Profile widget）。
   - **只有可嵌入组件**的是 Clerk `<UserProfile/>`、WorkOS Widgets、Descope widgets、Auth0（Web 端只有 org 组件，个人资料组件只在 iOS / Android）。
   - **两样都没有**的是 Cognito（原文："doesn't support user self-service profile management"）、Firebase（FirebaseUI 只做登录）、Stytch。Entra 证据矛盾。
7. **变更通知：**
   - **Webhook 普遍不保证顺序**，官方建议当作信号、再回拉数据。Clerk 和 Stytch 用 Svix 投递，WorkOS 的 webhook 也不保证顺序。
   - **保证顺序的只有 WorkOS Events API**，它可以回放。Auth0 Event Streams 另有 SSE 拉取接口。
   - **最差的是 Entra 外部租户**：Graph change notifications 和 delta query **都不支持**。Firebase 只有 created / deleted 两个触发器，**没有 update**。
   - **入站 SCIM** 属于 B2B 功能：WorkOS、Stytch B2B、Descope、Clerk、Auth0、Kinde 都有，挂在 enterprise connection 或 organization 上，通常单独计费。面向 C 端的 Firebase、Cognito、Logto 没有。
8. **导入：密码哈希支持面差异很大**（详见 2.8）。
   - 最宽：Clerk（17 种）、Descope、Stytch、Auth0、Firebase。
   - 最窄：Entra，**完全不支持导入哈希**，只能用 JIT 迁移。
   - **懒迁移（首次登录时回源校验）几乎是标配**，只有 Clerk 和 WorkOS 没有内置钩子。
   - 关联本地 ID 普遍靠 `external_id` 一类字段，各家支持情况：
     - 有专门字段：WorkOS、Clerk、Stytch、Descope `externalIds`、Kinde `provided_id`、Authing `externalId`。
     - 能保留原 ID：Firebase（指定 `uid`）、Auth0（指定 `user_id`，但没有 external_id 字段）。
     - 两样都没有：Logto Cloud，不能自定义 `id`，也没有 externalId 列。
9. **SDK 与文档：公开 OpenAPI 已是主流。**
   - 发布 OpenAPI 的：Clerk（按日期版本化，SDK 由 Speakeasy 生成）、WorkOS（2026-03 起，MIT）、Kinde、Descope、Logto（每个实例都有 `/api/swagger.json`）、Entra Graph（msgraph-metadata）。
   - 用其他模型格式的：Firebase（Google Discovery）、Cognito（Smithy）。
   - 不公开的：Authing（SDK 由内部 spec 生成）、Stytch（只在每个端点页内嵌片段，没找到完整下载）、Auth0（有 OpenAPI，但状态和下载地址未验证）。
   - **后端 SDK 普遍由 spec 生成**：Clerk、Kinde、Authing、Graph、AWS 都是。Authing 的 Python 和 PHP SDK 已经停更两三年。

**【推断】我的判断**

- 「按 Application 限定可见范围」在市场上是**空白**，各家的答案都是「改用 organization」，或者「集成方在自己后端包一层」（Logto 官方就这么推荐）。Polaris 如果做 per-Application 的可见范围，是在发明新东西，代价和语义都要自己定。
- 主流把「API 集成」和「托管集成」之间的中间地带，交给**可嵌入组件 + 短期 token** 解决（WorkOS widget token 1 小时、Kinde portal 一次性链接、Descope widgets）。这正好避开了把 Management API 凭据交给前端或交给集成方的问题。

## 2. 对比表

表格是对附录的压缩。「—」表示没有，「?」表示未验证。

### 2.1 Management API 授权模型

| 厂商 | 凭据 | scope 粒度 | 套餐门槛 |
|---|---|---|---|
| Auth0 | M2M client_credentials，token 默认 24h、不可撤销 | 资源 × 动作（`read:users`、`delete:sessions`…） | — |
| Clerk | `sk_` secret key（可设 IP allowlist） | 无 scope，全权 | — |
| WorkOS | 环境级 `sk_` key（"can perform any API request"） | 无 | — |
| Stytch | `project_id:secret` Basic | 无；Workspace Management Key 只管配置 | — |
| Descope | Management Key（过期时间、IP 限制、绑定 project） | project / tag 级角色，读、读写、审计分开 | — |
| Kinde | M2M client_credentials，1h | 资源 × 动作（`read:users`、`delete:user_sessions`…） | — |
| Firebase / IdP | service account + IAM | IAM 预定义角色，权限到 `firebaseauth.users.update` | — |
| Cognito | IAM SigV4 | IAM action × user pool ARN / tag | — |
| Entra External ID | Graph 应用权限 | 极细：`User.EnableDisableAccount.All`、`User-PasswordProfile.ReadWrite.All`… | — |
| Authing | 用户池 AK/SK 签名；另有协作管理员 AK/SK | 协作管理员 AK 继承该管理员的权限（API 层是否严格执行：?） | ? |
| Logto Cloud | M2M + Management API 角色 | **只有 `all`** | Free 1 个 M2M |

### 2.2 能否按应用 / 组织限定可见用户

| 厂商 | 按 Application | 按 organization / tenant |
|---|---|---|
| Auth0 | — | My Organization API（用户 token，取 app 策略 ∩ 用户 RBAC ∩ consent 的交集）；Management API 本身不能 |
| Clerk | 每个 Clerk application 有独立用户池；同一 application 内不能按 app 限定 | `organization_id` 仅是查询参数 |
| WorkOS | — | `organization_id` 仅是查询参数 |
| Stytch | — | B2B：带成员 session 头调用时按 RBAC 校验 org；不带头就不校验 |
| Descope | — | key 只能限到 project / tag；按 tenant 收窄要靠 Tenant Admin 身份走 widget |
| Kinde | — | **org-scoped M2M app**（token 带 `org_code`，Plus / Scale；哪些端点遵守：?） |
| Firebase / IdP | — | IAM 授在 tenant 资源上（multi-tenancy 是 Identity Platform 功能） |
| Cognito | —（IAM 没有 app client 维度） | 一个租户一个 user pool + IAM 限定 ARN |
| Entra | — | Administrative Unit 在外部租户是否可用：? |
| Authing | 应用访问授权只管登录准入 | tenant AK / 租户协作管理员是否只看到本租户：? |
| Logto Cloud | 应用访问控制只管登录准入 | M2M 的 organization token 不能调 Management API |

### 2.3 写操作与跨应用影响

| 厂商 | 禁用 | 删除 | 下线 | 作用范围 |
|---|---|---|---|---|
| Auth0 | block（登录返回 `user is blocked`；是否撤销已有 session：?） | 有 | sessions / revoke-access / refresh-tokens（后者限 Enterprise） | 整个 tenant【推断】 |
| Clerk | ban（撤销全部 session 和 OAuth grant）、lock | 有 | 单个 session revoke | 整个 instance |
| WorkOS | **没找到** | 永久删除 | sessions revoke | 整个环境【推断】 |
| Stytch | Consumer **没有**；B2B 也没有（但有 Reactivate） | 有 | revoke（JWT 最多再有效 5 分钟） | 整个 project |
| Descope | Disabled，可重新激活 | 有 | force logout 所有设备，支持批量 | 整个 project【推断】 |
| Kinde | `is_suspended`（立即结束 session、作废 refresh token） | 有 | `DELETE /users/{id}/sessions` | 整个 business【推断】 |
| Firebase | `disabled` | 有（批量删除不触发事件） | `revokeRefreshTokens` | 整个项目 |
| Cognito | 有（Admin API；条文：?） | 有 | `AdminUserGlobalSignOut` 撤销全部；`RevokeToken` 需传 client ID | 整个 pool |
| Entra | `accountEnabled` | 有（30 天内可恢复） | `revokeSignInSessions`（所有应用） | 整个租户 |
| Authing | status：Suspended / Deactivated / Archived | 批量删除、离职 | **`kickUsers` 需传 `appIds`，可只下线部分应用** | 禁用：整个池【推断】；下线：按应用 |
| Logto Cloud | `is-suspended`（同时 signOutUser） | 有 | 单个 session / grant | 整个租户 |

### 2.4 自定义用户数据与进 token

| 厂商 | 字段 | 是否按应用 | 进 token |
|---|---|---|---|
| Auth0 | `user_metadata`（用户偏好）/ `app_metadata`（用户不可改） | 否【推断】 | Actions `setCustomClaim`，需要 namespace |
| Clerk | public / private / unsafe，共 8KB | 否【推断】 | session claims 模板（建议 ≤1.2KB）、JWT templates |
| WorkOS | `metadata`（10 对键值）+ `external_id` | 否 | JWT Templates |
| Stytch | trusted / untrusted，各 4KB | 否；B2B member 天然按 org | custom claim templates |
| Descope | custom attributes（project 级，有类型）+ tenant attributes | 否 | JWT Templates（可引用当前 tenant 的属性） |
| Kinde | user / org / application properties | 数据全局；**每个 app 勾选哪些进 token** | Tokens 设置 + token generation workflow |
| Firebase | custom claims ≤1000 字节 | 否【推断】 | 自动进 ID token；blocking functions 可加 sessionClaims |
| Cognito | `custom:` 属性 | **按 app client 设读写权限** | pre-token Lambda（V2 需 Essentials / Plus；事件是否带 clientId：?） |
| Entra | 自定义属性 `extension_{appId}_x` | 定义挂在 app 上，数据在用户上 | 进 ID token；custom claims provider **可按应用分配** |
| Authing | 自定义字段（带 `appIds` 参数，是否按应用隔离：?） | ? | Pipeline `addToken`；每个应用自定义 OIDC claim |
| Logto Cloud | `customData` / `profile` jsonb | 否 | `getCustomJwtClaims` 脚本，按 token 类型配置（Pro） |

### 2.5 委派管理员

| 厂商 | 管理端只管一个应用 | 只管一个 organization |
|---|---|---|
| Auth0 | — | DAE v3（社区反映可以看到其他 org 的用户，官方没有回应）；推荐用 Universal Components + My Organization API 嵌进自己的产品 |
| Clerk | —（Business 套餐才有全部 workspace 角色） | org admin + `<OrganizationProfile/>` |
| WorkOS | — | Users Management widget（`widgets:users-table:manage`）；Admin Portal 只配 SSO / 目录同步，不管用户 |
| Stytch | — | B2B Admin Portal 组件（需嵌入） |
| Descope | — | Tenant Admin + Admin Widgets；**托管的 Admin Portal 按 tenant 隔离** |
| Kinde | —（团队角色可读整个 business） | org 自管角色（Scale） |
| Firebase / IdP | — | IAM 授在 tenant 上 |
| Cognito | — | IAM 限定 pool |
| Entra | 可限定到 app registration，但只开放 Cloud Application Administrator，**不管用户** | AU：? |
| Authing | **应用管理员：一个应用一个管理员**（搜索摘要） | 组织机构管理员 |
| Logto Cloud | —（Admin / Collaborator / Viewer 都作用于整个租户） | 只能自建后端代理 |

### 2.6 嵌入组件与账号中心

| 厂商 | 托管账号中心 | 可嵌入组件 |
|---|---|---|
| Auth0 | —（My Account API 只管认证方式） | Web：只有 My Organization 组件；iOS / Android：My Account 组件 |
| Clerk | Account Portal（登录、user profile、org profile） | `<UserProfile/>`、`<OrganizationProfile/>`、`<UserButton/>` |
| WorkOS | AuthKit 托管登录（账号中心：?） | User Profile / Security / Sessions / Users Management 等 Widgets |
| Stytch | — | 只有登录组件 |
| Descope | Auth Hosting 登录页 + 托管 Admin Portal | User Profile、Tenant Switcher 等 widgets |
| Kinde | self-serve portal（一次性链接进入；MFA 是 "coming soon"；外观不能定制） | — |
| Firebase | — | FirebaseUI（只做登录） |
| Cognito | —（官方原话：不支持资料自助） | Amplify UI（AccountSettings：?） |
| Entra | 证据矛盾：? | Native auth（应用自己绘制 UI） |
| Authing | `/u` 个人中心（搜索摘要） | Guard（托管 / 嵌入 / 弹窗；GitHub 最后正式 release 是 2023） |
| Logto Cloud | `/account/*` 账号中心（可用 CSS 定制） | —；有 Account API，可按字段设 Off / ReadOnly / Edit |

### 2.7 变更通知与同步

| 厂商 | 推送 | 有序 / 可回放 | 入站 SCIM |
|---|---|---|---|
| Auth0 | Event Streams（`user.created/updated/deleted`，webhook 或 EventBridge）+ Log Streams（不要放在关键路径上） | Events API 用 SSE 拉取 | 挂在 enterprise connection 上 |
| Clerk | Webhook（Svix，有 user / session / org / role 等事件） | 不保证顺序，Dashboard 可重放 | Directory Sync（Pro 起） |
| WorkOS | Webhook + Events API | **Events API 保证顺序**，可回放 | Directory Sync（每个连接 $125） |
| Stytch | Webhook（Svix，带完整对象） | 不保证顺序 | B2B |
| Descope | Audit Webhook（不实时、有节流）；Search Users `fromModifiedTime` 增量拉取 | 增量拉取 | 每个 tenant |
| Kinde | Webhook（body 是签名 JWT，27 个事件；**导入不触发 `user.created`**） | ? | 定价页说 Scale，公告说全部套餐，互相矛盾 |
| Firebase | 只有 `onUserCreated` / `onUserDeleted`，**没有 update** | — | — |
| Cognito | Lambda 触发器 + CloudTrail → EventBridge | — | — |
| Entra | **change notifications 和 delta query 在外部租户都不支持** | — | 只有出站 |
| Authing | Webhook（`user:created/updated/deleted/blocked`…）、事件中心、同步中心 | ? | ? |
| Logto Cloud | Webhook（User.Created / Deleted / Data.Updated / SuspensionStatus.Updated、Organization.*…；Free 1 个） | ? | — |

### 2.8 导入与本地关联

| 厂商 | 批量 | 密码哈希 | 懒迁移 | 本地 ID |
|---|---|---|---|---|
| Auth0 | bulk import job | argon2、bcrypt、hmac、ldap、md4、md5、sha1、sha256、sha512、pbkdf2、scrypt | Custom DB（Professional 起） | 可指定 `user_id`，没有 external_id 字段 |
| Clerk | 逐个 CreateUser + 官方工具 | 17 种：bcrypt、argon2i / id、pbkdf2 各变体、scrypt_firebase、md5、sha256、phpass… 还可导入 TOTP 和备用码 | 没有内置钩子 | `external_id` |
| WorkOS | Create User / CLI；超过 20 万找支持 | bcrypt、scrypt、firebase-scrypt、ssha、ssha256、pbkdf2、argon2；**不支持 md5 / sha** | 没有 | `external_id`（环境内唯一） |
| Stytch | 逐条，65 r/s | bcrypt、md5、argon2i / id、sha1、sha512、scrypt、phpass、pbkdf2；不兼容 Firebase | 无密码用户可以 | `external_id`，可代替 user_id 使用 |
| Descope | Batch Create | bcrypt、argon2、django、firebase、pbkdf2、phpass、md5、SHA1/2/3… | 有（Flow + HTTP connector） | `externalIds` |
| Kinde | CSV / NDJSON | bcrypt、crypt、md5、sha256、wordpress、pbkdf2、firebase-scrypt、aspnet-identity-v2 | 有（drip-feed workflow） | `provided_id` |
| Firebase | `importUsers` ≤1000 / 次 | scrypt（含标准版）、HMAC_*、MD5、SHA*、PBKDF*、BCRYPT、Argon2（仅 Java） | 没有 | 指定 `uid`（同 uid 直接覆盖） |
| Cognito | CSV（2026-07 起可带哈希：BCRYPT、SCRYPT、ARGON2ID、PBKDF2_SHA256） | 同左 | migrate user Lambda | ? |
| Entra | Graph 逐个创建 | **不支持导入哈希** | OnPasswordSubmit JIT | extension 属性 |
| Authing | `createUsersBatch` + `keepPassword` | 没有枚举，要自己写自定义密码函数（作用于整个池） | 自定义数据库（Enterprise） | `externalId` |
| Logto Cloud | 逐个 `POST /users` | Argon2i / id / d、SHA1、SHA256、MD5、Bcrypt、Legacy（JSON 描述任意算法） | Post first-factor Action | **Cloud 不能自定义 id，也没有 externalId** |

### 2.9 SDK 与文档

| 厂商 | 公开 spec | 后端 SDK |
|---|---|---|
| Auth0 | 有 OpenAPI，状态和下载地址：? | Node、Go、Python、Java、.NET、PHP、Ruby |
| Clerk | **OpenAPI，按日期版本化**（bapi / fapi / webhooks） | Speakeasy 生成：JS、Go、Python、Java、Ruby、PHP |
| WorkOS | OpenAPI 3.1（2026-03，MIT） | 10 种语言 |
| Stytch | 只在端点页内嵌片段 | Python、Go、Node、Ruby、Java |
| Descope | OpenAPI 3.0 | 7 种语言 + Terraform |
| Kinde | OpenAPI 3.0 | 由 spec 生成，6 种以上 |
| Firebase | Google Discovery | Node、Java、Python、Go、C# |
| Cognito | Smithy 模型 | AWS SDK 全家 |
| Entra | OpenAPI + CSDL | Graph SDK 8 种 + Kiota |
| Authing | 不公开（SDK 由内部 spec 生成） | Node、Java 仍在维护；Python、PHP 已停更 |
| Logto Cloud | 每个实例都有 `/api/swagger.json` + openapi.logto.io | 只有 TS：`@logto/api` |

## 3. 对 Polaris 的启示

先说现状（来源：仓库）：
- Management API 已按资源 × 动作划分 Permission：`users:read`、`users:write`、`roles:assign`…，见 `docs/spec/rbac.md`。这在粒度上和 Auth0、Kinde 同档，比 Logto 的 `all` 细。
- Webhook 是薄事件，不保证顺序，见 ADR 0022。
- `docs/management-api.md` 写明，每个实例已在 `{issuer}/v1/management/openapi.json` 暴露 OpenAPI。但 #179 的题干写的是「没有 OpenAPI 文档」，**grilling 时需先澄清题干**。

### #174 集成方能看到哪些 User（维度 1、2）

- **主流做法**：Management API 凭据看到整个用户池。需要隔离时，隔离单位是 tenant、pool 或 organization，没有一家按 Application 隔离。
- **最接近 per-Application 的两种参考**：
  - Kinde org-scoped M2M：token 带上下文，服务端据此过滤。
  - Auth0 My Organization API：另开一套「我的 org」API，权限取交集。
- **分歧点**：
  - 隔离靠**凭据绑定上下文**（Kinde、Descope、IAM 方案），还是靠**以最终用户身份代理调用**（Stytch B2B、Auth0 My Org）？
  - 还是像 Logto 一样不做，让集成方自己包一层？
- 【推断】Polaris 只有一个用户池、没有 organization。如果要做，「相关」的界定（登录过 / 持有 Role / 由它创建）完全没有先例可抄。最小方案是保持全池可见，靠 Permission 粒度和审计约束。

### #175 写操作（维度 3）

- **主流做法**：禁用、删除、全量下线都作用于整个用户池，没有一家对「跨应用影响」做特殊处理。
- **唯一的按应用写操作**：Authing `kickUsers(appIds)` 只让用户在指定应用下线。
- **分歧点**：
  - 有没有「禁用」：WorkOS 和 Stytch 没有，只能删除。
  - 删除可不可逆：Entra 30 天内可恢复，Stytch B2B 可以 Reactivate，WorkOS 永久删除。
  - 写权限拆多细：Entra 把启用状态、密码、手机号各拆成一个权限。
- 【推断】Polaris 的 `users:write` 目前把创建、禁用、删除、改 Identifier、下线捆在一起。如果要把「改资料」交给集成方、同时不让它禁用或删除全池用户，最直接的做法是**拆分 Permission**，这比引入作用域简单。

### #176 应用自定义数据（维度 4）

- **主流做法**：
  - 一份全局自定义数据，分「用户可写」和「仅后端可写」两类，大小几 KB。
  - 用模板或脚本放进 token。
- **按应用的变体**：
  - Kinde 数据全局，但每个 app 自己选择哪些放进 token。
  - Cognito 按 app client 设属性读写权限。
  - Entra 的扩展属性定义挂在 app 上。
- **没有一家真正「每个应用存一份」**。
- 【推断】Polaris 的 Webhook 薄事件设计（ADR 0022）本来就是为了避免把全池数据推给每个 Application。如果加入全局自定义数据，同样会出现「所有集成方互相可见」的问题。这时「业务数据由集成方以 `sub` 为键自存」与主流并不冲突：Logto 和 WorkOS 的 metadata 都很小，官方定位就是放少量标识。

### #177 委派管理员（维度 5）

- **主流做法**：管理端角色作用于整个 tenant。委派给集成方的形态是 **organization 级 + 嵌进集成方产品的组件**（WorkOS、Descope、Stytch、Auth0、Clerk），不是登录 IdP 自己的管理端。
- **反例**：Authing 的「应用管理员」，管理端里一个应用一个管理员。Descope 的托管 Admin Portal 也按 tenant 隔离。
- 【推断】在 Polaris 的 Role 模型里，「只管一个 Application」需要给 Role 加上作用对象（类似 Entra 把角色限定到 app registration）。现有的「所有者 / 管理员 / 只读」都是实例级的。这和 #174 是同一个问题：没有「应用范围的 User 集合」，就谈不上「只管这个应用的 User」。

### #178 导入与关联（维度 8）

- **主流做法**：
  - 至少支持 bcrypt、argon2、pbkdf2、scrypt；多数还支持 md5、sha 系列。
  - 首次登录后重新哈希成自家算法（Logto、Kinde 都这么做）。
  - 提供懒迁移钩子。
  - 用 `external_id` 关联本地 ID，并能在 token 里输出（Clerk 推荐 `{{user.external_id || user.id}}`）。
- **分歧点**：
  - 支持面宽窄：Entra 一种哈希都不接，Clerk 支持 17 种。
  - 批量接口还是逐条加限流：Logto、Stytch、Clerk 是逐条。
  - 能否保留原 ID：Firebase、Auth0 能；Logto Cloud 不能。
  - Identifier 冲突怎么处理：各家文档都没讲清楚，未验证。
- 【推断】`external_id` 几乎是标配，成本很低。懒迁移要在登录链路上回调外部系统，对 Polaris 是一条新的信任边界，可以后置。

### #179 SDK 与文档形态（维度 9）

- **主流做法**：公开 OpenAPI，后端 SDK 由 spec 生成。
  - 生成工具：Clerk 用 Speakeasy，Kinde 和 Authing 用 codegen，Entra 用 Kiota，AWS 用 Smithy。
  - Clerk 按日期给 spec 做版本化。
- **反例**：Authing 的 spec 不公开、SDK 半停更，可以看作「手写或内部生成，没有持续维护」的结局。
- Logto 只提供 TS SDK，但每个实例都暴露 swagger.json，和 Polaris 现状最接近。
- 【推断】Polaris 已经有 openapi.json，「只出 OpenAPI」是最低成本、也符合主流的形态。要不要生成 Go / TS client，取决于是否愿意把 spec 当作契约做版本化。

### 维度 6、7（没有单独的 ticket，但会影响上面几项）

- **账号中心**：托管页（Clerk、Kinde、Logto、Authing）和可嵌入组件是两条路线。Kinde 用「后端生成一次性链接 → 托管 portal」，可以让 API 集成方把用户送进账号中心，又不必自建 UI，值得在托管集成模式里参考。
- **通知**：Polaris 的「薄事件 + 不保证顺序 + 回拉」与 Stytch、Clerk 的官方建议一致。如果以后要做可靠同步，WorkOS 的「有序 Events API + Webhook」和 Descope 的「按修改时间增量拉取」是两种成本较低的补充。入站 SCIM 是 B2B 功能，和 Polaris 当前场景无关。

## 4. 主要未验证事项

- **Cognito 全部**：只有搜索摘要。包括 Admin API 是否受 app client 属性权限约束、pre-token 事件是否带 clientId、导入能否保留 `sub`。
- **Authing 文档类结论**：应用管理员、个人中心、Webhook 事件、定价，均为搜索摘要。另外：协作管理员 / 租户 AK 在 API 层是否真的按权限过滤；自定义字段 `appIds` 是否等于按应用隔离；是否有 SCIM。
- **Auth0**：block 是否撤销已有 session；Event Streams 的完整事件列表和套餐门槛；OpenAPI 的状态；My Account API 和 Universal Components 是否 GA。
- **WorkOS**：是否真的没有禁用接口；widget token 是否严格限定在 `organizationId`。
- **Stytch**：是否有完整的 OpenAPI 下载；B2B 支持的哈希列表。
- **Descope**：Management Key 能否限定到 tenant；SCIM 的套餐门槛（定价页前后矛盾）。
- **Kinde**：org-scoped M2M 对哪些 Management API 端点生效；SCIM 的套餐门槛（定价页与公告矛盾）。
- **Entra**：外部租户是否支持 AU 和自定义角色；是否有托管的资料编辑页。
- **Logto**：自定义 JWT 能否按应用配置；账号中心 UI 是否有套餐门槛。
- **通用**：导入时 Identifier 冲突怎么处理，各家都没查到明确规则。

---

## 附录：逐家取证记录

### Auth0

1. **鉴权**：M2M client_credentials，audience 为 `https://{domain}/api/v2/`，按端点要求 scope。token 默认 24h，签发后不可撤销。[management-api-access-tokens](https://auth0.com/docs/secure/tokens/access-tokens/management-api-access-tokens)、[session scopes](https://auth0.com/docs/manage-users/sessions/manage-user-sessions-with-auth0-management-api)
2. **范围**：用户是 tenant 级的，一个用户可属于多个 Organization（[organizations-overview](https://auth0.com/docs/manage-users/organizations/organizations-overview)）；没有限定 Management API token 范围的机制【推断】。[My Organization API](https://auth0.com/docs/manage-users/my-organization-api) 用用户级 token，权限取「app 策略 ∩ 用户 RBAC ∩ consent」，scope 如 `update:my_org:details`。另见 [build-delegated-admin](https://auth0.com/docs/get-started/universal-components/web/components/build-delegated-admin)。
3. **写操作**：block 后登录返回 `user is blocked`；通过 Management API 重置密码会解除 admin block（[block-and-unblock-users](https://auth0.com/docs/manage-users/user-accounts/block-and-unblock-users)）。`revoke-access` 可以保留 refresh token；refresh-tokens 端点限 Enterprise（[user-revoke-access](https://auth0.com/docs/api/management/v2/users/user-revoke-access)、[delete-refresh-tokens](https://auth0.com/docs/api/management/v2/users/delete-refresh-tokens-for-user)）。删除、改 email 的细节：未验证。
4. **数据**：`user_metadata` 和 `app_metadata`，另有应用自己的 `client_metadata`（[metadata](https://auth0.com/docs/manage-users/user-accounts/metadata)）。Actions 用 `setCustomClaim` 写 claim，payload ≤100KB，claim 冲突时被静默丢弃（[create-custom-claims](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims)）。
5. **委派**：[DAE v3](https://auth0.com/docs/customize/extensions/delegated-administration-extension) 只开放 Users 部分。社区反映 org 隔离不严（[community](https://community.auth0.com/t/delegated-admin-for-organizations/97108)，非一手来源）。[Universal Components](https://auth0.com/docs/get-started/universal-components/universal-components-overview)。Dashboard 角色按套餐：Free 只有 Admin（≤3 人），Essentials 加 Viewer，Professional 起加 Editor（[pricing](https://auth0.com/pricing)）。
6. **账号中心**：[My Account API](https://auth0.com/docs/manage-users/my-account-api) 管理认证方式，scope 为 `*:me:authentication_methods`。Lock：未验证。
7. **通知**：[Log Streams](https://auth0.com/docs/customize/log-streams)（Free 没有，Essentials 1 条）。[Event Streams](https://auth0.com/docs/customize/events/event-types)、[create](https://auth0.com/docs/customize/events/create-an-event-stream)、[Events API](https://auth0.com/docs/customize/events/consume-events-with-events-api)。[Inbound SCIM](https://auth0.com/docs/authenticate/protocols/scim/configure-inbound-scim)。
8. **导入**：[bulk import schema](https://auth0.com/docs/manage-users/user-migration/bulk-user-import-database-schema-and-examples) 列出哈希算法，`additionalProperties:false`，没有 external_id 字段。[automatic migration](https://auth0.com/docs/manage-users/user-migration/configure-automatic-migration-from-your-database)：Custom DB 要 Professional 起。
9. **SDK**：官方 GitHub 上有 7 种语言。OpenAPI 见 [support 文章](https://support.auth0.com/center/s/article/OpenAPI-Spec-Swagger-representation-of-management-API)；[社区帖](https://community.auth0.com/t/auth0-management-api-oas-schema-beta/185026)称处于 Beta。状态：未验证。

### Clerk

1. **鉴权**：OpenAPI 里只有 bearer `sk_` 一种 securityScheme（[bapi/2026-08-20.yml](https://github.com/clerk/openapi-specs/blob/main/bapi/2026-08-20.yml)）。可设 IP allowlist（[errors/backend-api](https://clerk.com/docs/errors/backend-api)）；只有 Admin 能管 secret key（[changelog](https://clerk.com/changelog/2026-01-09-secret-key-management-restricted-to-admins)）。
2. **范围**：每个 application 的每个 instance 有独立用户池；目前不支持按客户隔离用户池的 Platforms 场景（[multi-tenant-architecture](https://clerk.com/docs/guides/how-clerk-works/multi-tenant-architecture)、[satellite-domains](https://clerk.com/docs/guides/dashboard/dns-domains/satellite-domains)）。
3. **写操作**：ban、lock、session revoke、`password/set_compromised`（见 spec）。
4. **数据**：[metadata](https://clerk.com/docs/users/metadata)，三类，共 8KB；session claim 建议 ≤1.2KB。
5. **委派**：[manage-team-access](https://clerk.com/docs/guides/dashboard/manage-team-access)，Business 套餐才有全部角色。[org roles](https://clerk.com/docs/guides/organizations/control-access/roles-and-permissions)，自定义角色需要 Enhanced B2B（$100/月，[pricing](https://clerk.com/pricing)）。
6. **账号中心**：[`<UserProfile/>`](https://clerk.com/docs/components/user/user-profile)、[composable profile](https://clerk.com/changelog/2026-07-27-composable-profile-components)、[Account Portal](https://clerk.com/docs/guides/account-portal/overview)。
7. **通知**：[webhooks overview](https://clerk.com/docs/webhooks/overview)，事件列表见 [webhooks spec](https://github.com/clerk/openapi-specs)。[Directory Sync](https://clerk.com/docs/guides/configure/auth-strategies/enterprise-connections/directory-sync)、[自助配置](https://clerk.com/changelog/2026-09-30-self-serve-directory-sync)。
8. **导入**：[migrate-overview](https://clerk.com/docs/deployments/migrate-overview)、[migration-tool](https://github.com/clerk/migration-tool)；`PasswordHasher` 枚举见 spec。
9. **SDK**：[clerk/openapi-specs](https://github.com/clerk/openapi-specs)（bapi / fapi / platform / webhooks）。

### WorkOS

1. **鉴权**：原文 "API keys can perform any API request to WorkOS"，按环境隔离（[api-keys](https://workos.com/docs/reference/api-keys)、[environments](https://workos.com/docs/authkit/environments)）。另一套 [API Keys 功能](https://workos.com/docs/authkit/api-keys)是给集成方发给自己客户用的，不能调 WorkOS。
2. **范围**：`organization_id` 是查询参数（[user reference](https://workos.com/docs/reference/authkit/user)）。
3. **写操作**：update（改 email 后会重置验证状态）、永久 delete、设 password_hash；[sessions revoke](https://workos.com/docs/reference/authkit/session)。没找到 disable。
4. **数据**：[metadata](https://workos.com/docs/authkit/metadata)，10 对键值，可经 JWT Templates 进 token。
5. **委派**：[Admin Portal](https://workos.com/docs/admin-portal)（按 org，链接 5 分钟过期，不管用户）；[widget tokens](https://workos.com/docs/widgets/tokens)、[user-security](https://workos.com/docs/widgets/user-security)。
6. **组件**：[widgets quick-start](https://workos.com/docs/widgets/quick-start)。
7. **通知**：[data-syncing](https://workos.com/docs/events/data-syncing)（Events API 保证顺序；webhook 不保证，重试 3 天）、[events](https://workos.com/docs/events)。Directory Sync 计费见 [pricing](https://workos.com/pricing)。
8. **导入**：[migrate/other-services](https://workos.com/docs/migrate/other-services)；pbkdf2-sha1 或低迭代次数的哈希导入时转成 bcrypt。
9. **SDK**：[OpenAPI spec 发布](https://workos.com/changelog/openapi-spec)、[SDKs](https://workos.com/docs/sdks)。

### Stytch

1. **鉴权**：`project_id:secret` Basic（[api-keys](https://stytch.com/docs/resources/workspace-management/api-keys.md)）；Workspace Management Key 不能调认证 API（[pwa-api](https://stytch.com/docs/resources/workspace-management/pwa-api.md)）；M2M 是给集成方自己的 API 用的（[m2m](https://stytch.com/docs/api-reference/b2b/api/m2m/overview)）。
2. **范围**：带成员 session 头调用时按 RBAC 校验 org；不带头就 "no authorization check will be performed"（[enforcing-permissions](https://stytch.com/docs/multi-tenant-auth/enterprise-ready/rbac/enforcing-permissions)、[rbac overview](https://stytch.com/docs/b2b/guides/rbac/overview)）。Consumer 的 Search Users 搜整个 project（[search-users](https://stytch.com/docs/api-reference/consumer/api/users/search-users.md)）。
3. **写操作**：用户状态只有 pending / active / deleted（[user-states](https://stytch.com/docs/api-reference/consumer/api/resources/user-states.md)）；端点列表见 [consumer-api.txt](https://stytch.com/docs/_llms/api-and-sdk-reference/consumer-api/consumer-api.txt)、[b2b-api.txt](https://stytch.com/docs/_llms/api-and-sdk-reference/b2-b-api/b2-b-api.txt)；锁定只能由失败次数自动触发（[user-locks](https://stytch.com/docs/resources/policies/platform/user-locks.md)）；JWT 撤销后最多再有效 5 分钟（[revoke-session](https://stytch.com/docs/consumer-auth/manage-sessions/lifecycle/revoke-session.md)）。
4. **数据**：[metadata](https://stytch.com/docs/api-reference/consumer/api/resources/metadata.md)、[custom-claims](https://stytch.com/docs/consumer-auth/manage-sessions/custom-claims.md)。
5. **委派**：[B2B Admin Portal](https://stytch.com/docs/multi-tenant-auth/enterprise-ready/admin-portal.md)，是需要嵌入的组件。
6. **组件**：[build-auth overview](https://stytch.com/docs/multi-tenant-auth/build-auth/overview.md)。托管登录页、账号中心：未验证。
7. **通知**：[webhooks](https://stytch.com/docs/resources/workspace-management/webhooks.md)、[event-log-streaming](https://stytch.com/docs/resources/workspace-management/event-log-streaming.md)、[SCIM](https://stytch.com/docs/multi-tenant-auth/enterprise-ready/scim/overview.md)。
8. **导入**：[passwords/migrate](https://stytch.com/docs/api-reference/consumer/api/passwords/migrate.md)、[migrating-user-data](https://stytch.com/docs/resources/migrations/migrating-user-data.md)、[external-ids](https://stytch.com/docs/resources/migrations/external-ids.md)。
9. **SDK**：[sdks](https://stytch.com/docs/api-reference/consumer/api/sdks.md)。

### Descope

1. **鉴权**：Management Key 可设过期、绑定 project、限制 IP；角色有 `project-full-access`、`project-asset-mgmt-read(-write)`、`project-audit` 等（[management](https://docs.descope.com/management)）。Access Keys 是给集成方自己 API 用的 M2M 凭据（[m2m-access-keys](https://docs.descope.com/management/m2m-access-keys)）。
2. **范围**：Search Users 的 `tenantIds` 是查询过滤（[user-tracking](https://docs.descope.com/management/user-management/user-tracking)）。
3. **写操作**：Active / Disabled / Invited 三种状态，force logout，批量登出（[user-management](https://docs.descope.com/management/user-management)）。
4. **数据**：custom attributes 和 tenant attributes 可进 [JWT Templates](https://docs.descope.com/management/token/jwt-templates)。
5. **委派**：[Admin Widgets](https://docs.descope.com/widgets/admins)（Tenant Admin）、[托管 Admin Portal](https://docs.descope.com/widgets/admin-portal)，原文 "everything in the portal is scoped to that tenant"。所有套餐都含（[pricing](https://www.descope.com/pricing)）。
6. **组件**：[User Widgets](https://docs.descope.com/widgets/users)、[Auth Hosting](https://docs.descope.com/identity-federation/auth-hosting)。
7. **通知**：Audit Webhook 不实时；审计流推送需要 Growth 起（[connectors](https://docs.descope.com/connectors)）；[tenant SCIM](https://docs.descope.com/management/tenant-management/scim)。
8. **导入**：[migrate/custom](https://docs.descope.com/migrate/custom)（Batch Create、哈希列表、`externalIds`）、[JIT](https://docs.descope.com/migrate)。
9. **SDK**：[OpenAPI](https://docs.descope.com/api/openapi-spec)、[backend-sdk](https://docs.descope.com/backend-sdk)。

### Kinde

1. **鉴权**：[M2M scopes](https://docs.kinde.com/developer-tools/kinde-api/about-m2m-scopes/)、[authenticate](https://docs.kinde.com/machine-to-machine-applications/about-m2m/authenticate-with-m2m/)；请求不带 scope 时拿到该 app 已启用的全部 scope。
2. **范围**：[org-scoped M2M](https://docs.kinde.com/machine-to-machine-applications/organization-scoped-m2m-apps/m2m-applications-for-organizations/)（Plus / Scale）；按 app 拒绝登录靠 workflow `denyAccess`（[auth-binding](https://docs.kinde.com/workflows/bindings/auth-binding/)）。
3. **写操作**：[delete-or-suspend](https://docs.kinde.com/manage-users/access-control/delete-or-suspend-users/)，挂起立即结束 session，但已签发的 access token 在过期前仍有效。PATCH 字段见 [spec](https://api-spec.kinde.com/kinde-management-api-spec.yaml)。
4. **数据**：[properties](https://docs.kinde.com/properties/about-properties/)、[properties-in-tokens](https://docs.kinde.com/properties/work-with-properties/properties-in-tokens/)、[token-customization](https://docs.kinde.com/build/tokens/token-customization/)。
5. **委派**：[team-member-roles](https://docs.kinde.com/get-started/team-and-account/team-member-roles/)，作用于整个 business；[pricing](https://kinde.com/pricing/)。
6. **账号中心**：[self-serve portal](https://docs.kinde.com/build/self-service-portal/self-serve-portal-for-users/)（`POST /api/v1/portal/generate_url`）、[about portal](https://docs.kinde.com/build/self-service-portal/about-self-service-portal/)。
7. **通知**：[about-webhooks](https://docs.kinde.com/integrate/webhooks/about-webhooks/)、[事件列表](https://docs.kinde.com/integrate/webhooks/add-manage-webhooks/)；SCIM 见[公告](https://updates.kinde.com/announcements/scim-directory-sync-now-for-every-kinde-business)，与定价页矛盾。
8. **导入**：[import-users-in-bulk](https://docs.kinde.com/manage-users/add-and-edit/import-users-in-bulk/)，`hashing_method` 枚举见 spec；[drip-feed](https://docs.kinde.com/get-started/switch-to-kinde/drip-feed-migration/)。
9. **SDK**：[OpenAPI spec](https://api-spec.kinde.com/kinde-management-api-spec.yaml)。

### Firebase Auth / Identity Platform

1. **鉴权**：[manage-users](https://firebase.google.com/docs/auth/admin/manage-users)；IAM 角色见 [identitytoolkit](https://docs.cloud.google.com/iam/docs/roles-permissions/identitytoolkit)、[identityplatform](https://docs.cloud.google.com/iam/docs/roles-permissions/identityplatform)、[access-control](https://docs.cloud.google.com/identity-platform/docs/access-control)。
2. **范围**：[multi-tenancy](https://docs.cloud.google.com/identity-platform/docs/multi-tenancy)、[tenant IAM](https://docs.cloud.google.com/identity-platform/docs/multi-tenancy-access-control)、[TenantAwareAuth](https://docs.cloud.google.com/identity-platform/docs/multi-tenancy-managing-tenants)；multi-tenancy 只在 Identity Platform 提供（[product-comparison](https://docs.cloud.google.com/identity-platform/docs/product-comparison)）。
3. **写操作**：[manage-sessions](https://firebase.google.com/docs/auth/admin/manage-sessions)，ID token 要用 `checkRevoked` 才能识别已撤销。
4. **数据**：[custom-claims](https://firebase.google.com/docs/auth/admin/custom-claims)；[blocking functions](https://docs.cloud.google.com/identity-platform/docs/blocking-functions)（7 秒超时，仅 Identity Platform，不能只作用于单个 tenant）。
6. **组件**：[FirebaseUI](https://firebase.google.com/docs/auth/web/firebaseui)。
7. **通知**：[auth-events](https://firebase.google.com/docs/functions/auth-events)、[activity-logging](https://docs.cloud.google.com/identity-platform/docs/activity-logging)。
8. **导入**：[import-users](https://firebase.google.com/docs/auth/admin/import-users)。
9. **SDK**：[REST reference / Discovery](https://docs.cloud.google.com/identity-platform/docs/reference/rest)。

### AWS Cognito（全部来自搜索摘要）

1. **鉴权与范围**：[service-authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncognitouserpools.html)、[security_iam](https://docs.aws.amazon.com/cognito/latest/developerguide/security_iam_service-with-iam.html)；多租户最佳实践列了四种方案，强隔离推荐一个租户一个 pool（[multi-tenant best practices](https://docs.aws.amazon.com/cognito/latest/developerguide/multi-tenant-application-best-practices.html)）。
3. **写操作**：[token-revocation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html)。
4. **数据**：[attributes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html)，按 app client 设读写权限；[pre-token generation](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html)。
6. **组件**：[managed login](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managed-login.html)，原文 "doesn't support user self-service profile management"。
7. **通知**：[Lambda triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html)、[EventBridge](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-cognito-idp.html)、[CloudTrail](https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html)。
8. **导入**：[哈希导入公告](https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-cognito-password-hash-import/)、[import tool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-using-import-tool.html)、[migrate user Lambda](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html)。
9. **SDK**：[aws/api-models-aws](https://github.com/aws/api-models-aws)（Smithy）；套餐见 [feature plans](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-sign-in-feature-plans.html)。

### Microsoft Entra External ID（外部租户）

1. **鉴权**：Graph 在外部租户里覆盖全部功能（[supported features](https://learn.microsoft.com/en-us/entra/external-id/customers/concept-supported-features-customers)）；按字段区分权限见 [user-update](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)，改密码还要给应用分配 User Administrator 目录角色。
2. **范围 / 委派**：[role scope](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-overview)、[administrative units](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units)；外部租户里应用相关角色只有 Cloud Application Administrator（见 supported features）。
3. **写操作**：[revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions)，作用于所有应用。
4. **数据**：[custom attributes](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-define-custom-attributes)、[custom claims provider](https://learn.microsoft.com/en-us/entra/identity-platform/custom-claims-provider-overview)（可分配给一个或多个应用）。
6. **组件**：[native authentication](https://learn.microsoft.com/en-us/entra/identity-platform/concept-native-authentication)。
7. **通知**：[change notifications 不支持外部租户](https://learn.microsoft.com/en-us/graph/change-notifications-overview)、[delta query 不支持外部租户](https://learn.microsoft.com/en-us/graph/delta-query-overview)。
8. **导入**：[how-to-migrate-users](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-migrate-users)、[迁移工具](https://github.com/microsoft/b2c-to-meeid-migration-tool)。
9. **SDK**：[Graph SDKs](https://learn.microsoft.com/en-us/graph/sdks/sdks-overview)、[msgraph-metadata](https://github.com/microsoftgraph/msgraph-metadata)。

### Authing（API 事实来自 SDK 源码，文档类事实来自搜索摘要）

1. **鉴权**：[ManagementClientOptions](https://github.com/Authing/authing-node-sdk/blob/master/src/ManagementClientOptions.ts)、[ManagementHttpClient](https://github.com/Authing/authing-node-sdk/blob/master/src/ManagementHttpClient.ts)；SDK 里约 447 个 `/api/v3/*` 端点；`createAccessKey` 用于创建协作管理员的 AK/SK。编程访问账号用于集成方自己的资源授权（[application-access-control](https://docs.authing.cn/v2/guides/app-new/create-app/application-access-control.html)、[m2m-authz](https://docs.authing.cn/v2/guides/authorization/m2m-authz.html)）。
3. **写操作**：[UpdateUserReqDto](https://github.com/Authing/authing-node-sdk/blob/master/src/models/UpdateUserReqDto.ts)、[KickUsersDto](https://github.com/Authing/authing-node-sdk/blob/master/src/models/KickUsersDto.ts)（`appIds`）；另有导出密码密文的接口。
4. **数据**：[SetCustomFieldDto](https://github.com/Authing/authing-node-sdk/blob/master/src/models/SetCustomFieldDto.ts)（`appIds`、`userEditable`、`encrypted`）；[customize-id-token](https://docs.authing.cn/v2/guides/authentication/extensibility/customize-id-token.html)、[oidc-scope](https://docs.authing.cn/v2/guides/app-new/create-app/oidc-scope.html)。
5. **委派**：[协作管理员（新）](https://docs.authing.cn/v2/guides/userpool-config/new-collaboration-adminstrator.html)、[协作管理员](https://docs.authing.cn/v2/guides/userpool-config/collaboration-adminstrator.html)。
6. **组件**：[Guard](https://docs.authing.cn/v2/reference/guard/v2/web.html)、[个人中心](https://docs.authing.cn/v2/guides/user/manage-profile.html)、[Guard 仓库](https://github.com/Authing/Guard)。
7. **通知**：[webhook](https://docs.authing.cn/v2/guides/webhook/)、[同步中心](https://docs.authing.cn/v2/guides/sync-new/)。
8. **导入**：[CreateUserOptionsDto](https://github.com/Authing/authing-node-sdk/blob/master/src/models/CreateUserOptionsDto.ts)（`keepPassword`、`externalId`）；[自定义密码函数](https://docs.authing.cn/v2/guides/migrations/custom-password-script/)、[use-api](https://docs.authing.cn/v2/guides/migrations/use-api.html)、[自定义数据库](https://docs.authing.cn/v2/guides/database-connection/overview.html)。
9. **SDK**：[generate-node-sdk.js](https://github.com/Authing/authing-sdk-factory/blob/master/scripts/generate-node-sdk.js)，输入是 `localhost:3888/openapi-json`。Python 最后发布 5.1.0（2023-10），PHP 最后推送是 2023-03。

### Logto Cloud

1. **鉴权**：[interact-with-management-api](https://docs.logto.io/integrate-logto/interact-with-management-api)；只有 `PredefinedScope.All` 一个 scope（[management-api.ts](https://github.com/logto-io/logto/blob/master/packages/schemas/src/seeds/management-api.ts)）；[pricing](https://logto.io/pricing)。
2. **范围**：官方建议在自己的后端包一层（[organization-management](https://docs.logto.io/end-user-flows/organization-experience/organization-management)，搜索摘要）；organization token 不能访问 Management API（[org-level API resources](https://docs.logto.io/authorization/organization-level-api-resources)）；应用访问控制见 [application-access-control.ts](https://github.com/logto-io/logto/blob/master/packages/core/src/routes/applications/application-access-control.ts)。
3. **写操作**：[admin-user/basics.ts](https://github.com/logto-io/logto/blob/master/packages/core/src/routes/admin-user/basics.ts)；停用和删除时调用 `signOutUser`。
4. **数据**：[users.sql](https://github.com/logto-io/logto/blob/master/packages/schemas/tables/users.sql)、[custom token claims](https://docs.logto.io/developers/custom-token-claims/create-script)。
5. **委派**：[tenant-member-management](https://docs.logto.io/logto-cloud/tenant-member-management)。
6. **账号中心**：[account center UI](https://docs.logto.io/end-user-flows/account-settings/by-account-center-ui)（搜索摘要；与[产品页](https://logto.io/products/account-center)的 "no out-of-box UI" 说法矛盾）、[Account API](https://docs.logto.io/end-user-flows/account-settings/by-account-api)。
7. **通知**：[hooks.ts](https://github.com/logto-io/logto/blob/master/packages/schemas/src/foundations/jsonb-types/hooks.ts)；源码里没有 SCIM。
8. **导入**：[user-migration](https://docs.logto.io/user-management/user-migration)（Cloud 收到自定义 `id` 返回 501）；`passwordAlgorithm` 枚举见 users.sql；[Legacy 算法](https://github.com/logto-io/logto/blob/master/packages/schemas/alterations/1.25.0-1739429593-add-legacy-password-encryption.ts)。
9. **SDK**：[openapi.logto.io](https://openapi.logto.io/)、[swagger route](https://github.com/logto-io/logto/blob/master/packages/core/src/routes/swagger/index.ts)；`@logto/api` 1.46.0。
