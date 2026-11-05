# 开源认证平台的两种集成模式：API 集成与托管集成

- 调研日期：2026-11-05
- 问题（[#173](https://github.com/zibyn/polaris/issues/173)，属于地图 [#171](https://github.com/zibyn/polaris/issues/171)）：Keycloak、Zitadel、Logto、Ory（Kratos / Hydra / Keto）、Casdoor、Authentik、SuperTokens 各自怎样支持 **API 集成模式**和**托管集成模式**？术语以 [GLOSSARY.md](../../GLOSSARY.md) 为准。
- 范围：只看集成相关的 9 个维度。协议和登录能力已由 [auth-market-survey.md](auth-market-survey.md) 覆盖（各系统的基本面见那份文档的附录 A），本文不再重复。
- 核对的版本：

  | 系统 | 版本 |
  |---|---|
  | Keycloak | 26.8.1 |
  | Zitadel | v4.20.1 |
  | Logto OSS | v1.46.0 |
  | Ory Kratos / Hydra / Keto / Polis | v26.2.0；`@ory/elements-react` v1.3.0 |
  | Casdoor | v4.25.0（源码 master `07cad85`） |
  | Authentik | 2026.8.5 |
  | SuperTokens | core v12.4.1；supertokens-node v24.1.0 |

- 写法约定：
  - 每条非显然的事实都附一手来源（官方文档、API reference、GitHub 源码 / issue）。
  - 我自己的判断标 **【推断】**。
  - 没找到一手来源的标 **未验证**。
  - 所有结论都来自静态阅读文档和源码，没有部署任何实例实测。
- 取证方式：
  - 六路并行调查，各自读文档和 tagged 源码。
  - 我另外用 `gh api` 抽查了以下几项，结果与正文一致：
    - 下列 issue 当前都是 open：Logto #8821 / #9331，Keycloak #41065 / #53837 / #19691，Zitadel #6535 / #5524 / #6601，SuperTokens core#898。
    - Logto v1.46.0 里有 `koa-read-only-access.ts`。
    - Kratos 批量导入的上限是 1000 / 200。
    - Casdoor `cred/manager.go` 支持 8 种 passwordType。
    - Zitadel 和 Keycloak 的 latest release 号与上表一致。

## 1. 结论速览

**已验证的事实**

1. **授权粒度只有两档。**
   - Keycloak（FGAP v2）、Zitadel（分层的 Administrator 角色）和 Authentik（Django 对象权限）能把 M2M 凭据限定到只读、具体资源，或某个组织 / 组。
   - Logto（只有一个 `all` scope）、Ory（Admin API 本身不鉴权，Network 版的 API Key 不带 scope）、Casdoor（应用凭据就是整个组织的管理员）和 SuperTokens（core `api_keys` 不带 scope）都是"要么全有、要么全无"。
2. **没有一家能按应用限定 M2M 调用方看到的用户。**
   - 有隔离能力的系统，边界都落在组织 / realm / tenant / 组这一层：Zitadel 按 Org，Keycloak 按组或 realm，SuperTokens 按 app / tenant（付费）。用户本来就属于这一层。
   - 应用（client）这一层只管"能不能登录"，不管"API 调用方看得到谁"。
3. **禁用和删除都是全局的，每家都一样。** 所谓"按应用禁用"，实际都做成了准入策略，而不是用户身上的一个状态：
   - Logto：App-level access control。
   - Zitadel：Check Role Assignment 开关 + 撤销 Authorization。
   - Keycloak：客户端认证流程里配 Deny Access。
   - Authentik：应用的 policy binding。
   - Casdoor：Application 类型的 Permission。
4. **按应用划分命名空间的用户数据，没有一家原生支持。**
   - 各家都只有一份挂在用户身上的全局 JSON 或 KV：Logto `customData`、Zitadel metadata、Keycloak attributes、Kratos `metadata_public` / `metadata_admin`、Casdoor `properties`、Authentik `attributes`、SuperTokens UserMetadata。
   - Zitadel 的"按项目 metadata"（[#6535](https://github.com/zitadel/zitadel/issues/6535)）仍是 open。
   - 最接近的是 Authentik 的 Application Entitlements：它归属于单个应用，可以进 token，但它是授权对象，不是每个用户一份的私有数据。
   - 进 token 的手段各家都有：脚本、mapper、Actions、consent session 或 override。
5. **委派管理员**只有 Keycloak（FGAP 可以只管某个 client 或某些组）、Zitadel（Org / Project / Project Grant 管理员）和 Authentik（对象权限 + `Can access admin interface`）做得到。Logto、Ory、Casdoor、SuperTokens 的管理端角色都是全租户 / 全项目 / 全组织级的。
6. **Webhook：**
   - 有签名的：Logto（HMAC-SHA256）、Zitadel Actions v2（HMAC / JWT / JWE）、Keycloak SSF（JWS 签名 SET，实验功能）。
   - 有 Webhook 但不签名：Casdoor（但有持久化重试和重放）、Authentik（Notification Transport）。
   - 没有内置 Webhook：Keycloak（[#41065](https://github.com/keycloak/keycloak/issues/41065) open）、SuperTokens。
   - Ory OSS 只有自助流程的 hook，管理员改动不会产生事件。
7. **SCIM：**
   - 入站服务端：Keycloak（26.8 起 supported）、Zitadel（Preview，只有 Users）、Casdoor、Authentik（Source）、Ory（仅 Network）。
   - 出站：只有 Authentik 的 SCIM Provider 实现了，而且只同步绑定到该应用的用户。
   - 都没有：Logto、SuperTokens。
8. **导入哈希密码各家都支持，覆盖面差别很大。**
   - 最宽的是 Ory 和 Zitadel：bcrypt、argon2、pbkdf2、scrypt、md5 / sha 系列、crypt 系列，还有 Firebase scrypt 或 phpass。
   - 最窄的是 Keycloak：内置只有 argon2 / pbkdf2，bcrypt 要靠第三方 SPI。
   - 首次登录后自动升级到当前哈希算法是通行做法（Ory、Zitadel、Logto、Casdoor）。
   - 关联本地用户的做法：
     - 专用 `external_id` 字段：Ory、Casdoor。
     - 导入时自定义 user id：Zitadel v2、Logto（仅自托管）、Keycloak partialImport。
     - ID 映射表：SuperTokens UserIdMapping。
9. **SDK 形态：**
   - 由 OpenAPI 生成多语言客户端是主流：Zitadel（proto → OpenAPI → 6 种语言）、Ory（openapi-generator，11 种语言）、Authentik（4 种语言）。
   - 手写的：Keycloak（Java、JS 的 v1 部分）、Casdoor（10 余种语言）、SuperTokens（Node / Python / Go，以 recipe 的形式）。
   - Logto 只有一个 Node 的 `@logto/api`，类型是生成的，外层封装是手写的。

**【推断】我的判断**

- 七家里**没有一家同时把两种模式都做好**：
  - Zitadel 偏 API 集成：分层管理员、v2 生成式 SDK、签名 webhook 都有，但账户中心还在 Console 里。
  - Logto 偏托管集成：有 Account Center UI、App-level access control，但 Management API 只有一个 `all` scope。
  - Ory 和 SuperTokens 根本没有自托管的管理端，只能走 API 集成。
- Polaris 现在的问题（M2M 看得到整个池、没有按应用的数据）正是这个行业的普遍空白。补上会是差异点，但也意味着没有现成的形状可以照搬，需要在 grilling 里自己定边界。

## 2. 对比表

| 维度 | Keycloak | Zitadel | Logto | Ory | Casdoor | Authentik | SuperTokens |
|---|---|---|---|---|---|---|---|
| 1 M2M 凭据 / 粒度 | 服务账号（client_credentials）；realm-management 角色 + FGAP v2，可只读、可到资源级 | 服务账号（JWT / client credentials / PAT）；分层 Administrator 角色，有 `*_VIEWER` | M2M 应用；只有 `all`；v1.46 加了只读请求头（由调用方自己决定带不带） | OSS Admin API 不鉴权，只能靠网络隔离；Network 版的 API Key 无 scope | 应用 clientId/secret = 本组织管理员；细粒度权限只对真实用户有效 | 服务账号 token / OAuth JWT；对象级 RBAC，可只读 | core `api_keys`，无 scope |
| 2 按应用 / 组织限定可见用户 | 按组（FGAP），不按 client | 按 Org，不按 Project | 否（#8821 open） | 否（只有过滤参数） | 按组织，不按应用 | 按逐个授权的用户对象 | 按 app / tenant（付费），key 不绑定 tenant |
| 3 按应用禁用 | 认证流程 Deny Access | 撤销 Authorization + 项目开关 | App-level access control | 无（只能撤销 consent） | Application Permission / Tag | policy binding | 无（ban 插件是全局的） |
| 4 按应用的用户数据 | 无，attributes 是全局的；用 mapper 进 token | 无（#6535），metadata 是全局的；用 scope / Actions 进 token | 无，customData 是全局的且用户可写；用 Custom JWT 进 token | 无，metadata 是全局的；经 consent / token hook 进 token | 无，properties 是全局的；按应用配 token 字段 | Entitlements（归属应用）；用 mapping 进 token | 无，metadata 按 app 分；用 override 进 token |
| 5 委派管理员 | 是（FGAP 到 client / 组） | 是（Org / Project / Grant） | 否 | 否 | 仅到组织 | 是（对象权限） | 否（dashboard 只有"全权 / 只读"两档） |
| 6 嵌入组件 / 账户中心 | 托管 Account Console v3，可部分嵌入 React 应用 | 无嵌入组件；Console 里的 users/me；Login V2 可 fork | 托管 Account Center；嵌入组件未发布 | Elements 组件库；托管页仅 Network 有 | 弹窗 / iframe；托管 `/account` | 托管 `/if/user/`；无组件库（未验证） | Prebuilt UI 可嵌入；无托管账户中心 |
| 7 Webhook / SCIM | 无 webhook；SSF 实验；SCIM 入站 | Actions v2（签名、持久化队列）；SCIM 入站（Preview） | 签名 webhook，内存重试 3 次；无 SCIM | 只有自助流程的 hook；事件流和 SCIM 仅 Network | webhook 无签名，持久化重试；SCIM 入站；Syncer | 无签名 webhook；SCIM 入站 + 出站 | 都没有 |
| 8 导入 / 哈希 / 关联 | partialImport；argon2 / pbkdf2；导入可保留 id | ImportData / AddHumanUser；MCF 多算法；自定义 id | 只能逐条导入；8 种算法 + Legacy；自定义 id 仅自托管 | 批量 PATCH；最全；`external_id` | xlsx（明文）/ add-user；8 种算法；`ExternalId` | 无批量端点；Django 哈希 | bulk-import（每批 1 万）；argon2 / bcrypt / firebase；UserIdMapping |
| 9 SDK / OpenAPI | OpenAPI 3；Java / JS 手写 | proto → OpenAPI；6 种语言生成 | 实例上提供 swagger.json；仅 Node | OpenAPI；11 种语言生成 | Swagger（仅 dev 模式提供）；多语言手写 | OpenAPI；4 种语言生成 | CDI / FDI OpenAPI（落后于 core）；3 种语言手写 |

## 3. 逐维度取证

### 3.1 Management API 覆盖面与授权模型

- **Keycloak**
  - 凭据与覆盖面：
    - Admin REST API v1 有 274 条 path（[openapi.json](https://www.keycloak.org/docs-api/latest/rest-api/openapi.json)）。另有 Admin API v2（preview，只管客户端）（[admin-api-v2](https://www.keycloak.org/admin-api/admin-api-v2)）。
    - M2M 凭据是 confidential client 打开 Service accounts 后走 client_credentials，没有 PAT 或 API key（[service accounts](https://www.keycloak.org/docs/latest/server_admin/index.html#_service_accounts)）。
  - 粒度：
    - 粗粒度权限是 realm-management 客户端的角色，如 `view-users` / `query-users` / `manage-users`，可以做成只读（[per-realm admin](https://www.keycloak.org/docs/latest/server_admin/index.html#_per_realm_admin_permissions)）。
    - 细粒度权限是 FGAP v2，默认开启。资源类型有 Users / Groups / Clients / Roles / Organizations，scope 有 view、manage、map-roles、impersonate、reset-password、view-members、manage-members 等。持有 `realm-admin` 的主体不受 FGAP 约束（[fine-grained permissions](https://www.keycloak.org/docs/latest/server_admin/index.html#_fine_grained_permissions)）。
  - 缺口：v1 没有用户 PATCH（[#19691](https://github.com/keycloak/keycloak/issues/19691) open）。
- **Zitadel**
  - API：
    - v1 按使用者划分（Auth / Management / Admin / System），v2 按资源划分（User / Org / Project / Authorization / Session…）（[migration v1→v2](https://zitadel.com/docs/apis/migration_v1_to_v2)）。
    - 凭据挂在 Service Account 上，有三种：Private Key JWT（推荐）、client credentials、PAT（[authenticate service accounts](https://zitadel.com/docs/guides/integrate/service-accounts/authenticate-service-accounts)）。
  - 授权：
    - 权限不靠 OAuth scope 控制，靠给服务账号分配 Administrator 角色。角色分 IAM / Org / Project / Project Grant 四层。
    - 每个 RPC 在 proto 注释里写明所需权限，例如 CreateUser 要 `user.write`（[user_service.proto](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/user/v2/user_service.proto)）。
    - 角色到权限的映射在 [defaults.yaml](https://github.com/zitadel/zitadel/blob/main/cmd/defaults.yaml) 的 `InternalAuthZ.RolePermissionMappings`。只读角色有 `ORG_OWNER_VIEWER` 等。
    - 自定义角色只能改整个实例的配置，没有 API【推断】。
- **Logto**
  - 凭据：M2M 应用，分配含 Management API `all` 权限的角色后走 client_credentials（[interact with management API](https://docs.logto.io/integrate-logto/interact-with-management-api)）。
  - 粒度：
    - 内置 resource 只有 `all` 一个 scope，而且不能修改（[management-api.ts](https://github.com/logto-io/logto/blob/v1.46.0/packages/schemas/src/seeds/management-api.ts)）。
    - 鉴权中间件只检查 `scopes.includes(All)`（[koa-auth](https://github.com/logto-io/logto/blob/v1.46.0/packages/core/src/middleware/koa-auth/index.ts)）。
  - 只读：
    - v1.46.0 新增请求头 `logto-read-only-access`。带上后非 GET 请求返回 403，也读不到各类 secret（[koa-read-only-access.ts](https://github.com/logto-io/logto/blob/v1.46.0/packages/core/src/middleware/koa-read-only-access.ts)）。
    - 这个头由调用方自己决定带不带，不绑定在凭据上【推断】。
  - 细粒度权限的需求：[#8821](https://github.com/logto-io/logto/issues/8821) 仍 open，官方建议自己包一层代理。
- **Ory**
  - OSS 版：
    - Kratos Admin API 不鉴权，文档要求不能不加保护地暴露到公网（[kratos production](https://github.com/ory/docs/blob/master/docs/kratos/guides/production.md)）。
    - Hydra admin 端口"None of the administrative endpoints have any built-in access control"（[hydra production](https://github.com/ory/docs/blob/master/docs/hydra/self-hosted/production.md)）。
    - Keto 的读和写分两个端口，只读只能靠网络层实现【推断】。
  - Ory Network：项目 API Key 对整个项目有效，创建时只填名称和过期时间，没有 scope（[personal-access-token](https://github.com/ory/docs/blob/master/docs/concepts/personal-access-token.mdx)）。
- **Casdoor**
  - 覆盖面：控制台调的就是同一套 RPC 风格 API（`/api/get-users`、`/api/add-user`…）（[public-api](https://casdoor.ai/docs/basic/public-api)、[router.go](https://github.com/casdoor/casdoor/blob/07cad85/routers/router.go)）。
  - 应用凭据的权限：
    - 应用的 clientId/secret 被映射成虚拟用户 `app/<name>`，它是 `IsAdmin=true`、Owner 等于应用所属组织（[user_util.go#L1139-L1156](https://github.com/casdoor/casdoor/blob/07cad85/object/user_util.go#L1139-L1156)）。
    - 只要请求对象的 owner 等于该组织就放行，这个判断在 casbin 规则之前就返回（[authz.go#L183-L198](https://github.com/casdoor/casdoor/blob/07cad85/authz/authz.go#L183-L198)）。
  - 只读：应用凭据做不到。【推断】可以用"普通用户 + API 类型 Permission + User access key"拼出来，未实测。
- **Authentik**
  - 覆盖面：整个产品由 `/api/v3` 驱动（[schema.yml](https://github.com/goauthentik/authentik/blob/version/2026.8.5/schema.yml)）。
  - 凭据有三种：服务账号的 API Token、用户自己的 token、申请 `goauthentik.io/api` scope 拿到的 OAuth JWT（[service-accounts](https://docs.goauthentik.io/users-sources/user/account-types/service-accounts/)、[authentication.mdx](https://github.com/goauthentik/authentik/blob/version/2026.8.5/website/api/authentication.mdx)）。
  - 粒度：
    - Django 模型权限，分全局和对象两级，自 2025.12 起只能挂在角色上，可以只读（[permissions](https://docs.goauthentik.io/users-sources/access-control/permissions/)）。
    - 敏感动作各有独立权限，如 `reset_user_password`、`impersonate`（[users.py](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/core/api/users.py)）。
- **SuperTokens**
  - 三层结构：core 暴露 CDI，后端 SDK 封装 CDI 并对前端暴露 FDI（[CDI intro](https://supertokens.com/docs/references/cdi/introduction)）。
  - 凭据：
    - core 的 `api_keys` 默认为空，此时任何能连到 core 的调用方都能执行管理操作（[api-keys](https://supertokens.com/docs/platform-configuration/supertokens-core/api-keys)）。
    - 没有 scope【推断，依据是 [CoreConfig.java](https://github.com/supertokens/supertokens-core/blob/v12.4.1/src/main/java/io/supertokens/config/CoreConfig.java) 里它只是一个字符串】。

### 3.2 按应用 / 组织限定可见用户范围

- **Keycloak**
  - 只有 `view-users` 角色时能看到整个 realm 的用户。
  - FGAP v2 能按组成员关系或具体用户收窄范围，但只对父组授权时，子组成员不一定出现在搜索结果里（[group hierarchy](https://www.keycloak.org/docs/latest/server_admin/index.html#group-hierarchy-and-permission-inheritance)）。
  - 没有"能访问某个 client 的那批用户"这个维度。
  - FGAP 的 Organizations 资源类型管的是组织本身（[#47284](https://github.com/keycloak/keycloak/issues/47284)）。它能不能把用户查询限制在本组织成员内：**未验证**。
- **Zitadel**
  - 可见范围按 Org 切。文档原话是：实例管理员调 `GET /users` 拿到整个实例的用户，组织管理员只拿到本组织的（[migration v1→v2](https://zitadel.com/docs/apis/migration_v1_to_v2)）。
  - 源码按用户的 resource owner 做权限过滤（[query/user.go](https://github.com/zitadel/zitadel/blob/main/internal/query/user.go)）。
  - Project Grant 把项目连同部分角色授给另一个组织，是 Auth0 Organizations 的对应物（[granted projects](https://zitadel.com/docs/concepts/structure/granted_projects)）。
  - 只有 Project 级角色的服务账号能看到哪些用户：**未验证**（【推断】看不到用户列表）。
- **Logto**
  - 不能限定。`all` 不带对象范围（见 3.1），#8821 的评论原话："one credential reaches every customer organisation in the tenant"。
  - 组织级 M2M 只能用于自己的 API resource（[organization-level API resources](https://docs.logto.io/authorization/organization-level-api-resources)）。官方推荐自建后端，先校验组织 token，再用全权 M2M 去调 Management API（[setup app service](https://docs.logto.io/end-user-flows/organization-experience/setup-app-service-with-management-api)）。
- **Ory**
  - 一个项目就是一个身份池（[organizations](https://github.com/ory/docs/blob/master/docs/kratos/organizations/organizations.mdx)）。
  - `GET /admin/identities?organization_id=` 只是查询过滤，不是授权边界（[identity/handler.go](https://github.com/ory/kratos/blob/v26.2.0/identity/handler.go)）。
- **Casdoor**
  - `get-users` 只能按组织、组或字段过滤（[controllers/user.go#L86-L137](https://github.com/casdoor/casdoor/blob/07cad85/controllers/user.go#L86-L137)）。
  - 官方的 B2B 隔离做法是每个客户建一个组织加一个应用（[public-api](https://casdoor.ai/docs/basic/public-api)）。
- **Authentik**
  - 没有全局 `view_user` 时，API 只返回带对象级 view 权限的用户（[rbac/filters.py](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/rbac/filters.py)）。
  - "Initial permissions" 可以做到"只管自己建的用户"（[initial_permissions](https://docs.goauthentik.io/users-sources/access-control/initial_permissions/)，preview）。
  - 真正的租户隔离是 Enterprise 的 Tenancy：每个租户一个独立 schema，alpha 状态（[tenancy.mdx](https://github.com/goauthentik/authentik/blob/version/2026.8.5/website/docs/sys-mgmt/tenancy.mdx)）。
- **SuperTokens**
  - App 之间完全隔离（付费，[manage-apps](https://supertokens.com/docs/authentication/enterprise/manage-apps)）。Tenant 有各自的用户关联，一个用户可以关联多个 tenant（[important-concepts](https://supertokens.com/docs/authentication/enterprise/important-concepts)）。
  - API key 不绑定 tenant【推断】。

### 3.3 写操作与跨应用影响

| 系统 | 写操作（摘要） | 禁用 / 删除 | "按应用"的等价物 |
|---|---|---|---|
| Keycloak | CRUD、`reset-password`、`execute-actions-email`、`logout`、`DELETE consents/{client}`、impersonation（[openapi](https://www.keycloak.org/docs-api/latest/rest-api/openapi.json)） | `enabled` 是 realm 级的 | 客户端认证流程里 Condition - User Role + Deny Access（[server admin](https://www.keycloak.org/docs/latest/server_admin/index.html)） |
| Zitadel | Create / Update、SetPassword、Deactivate / Lock / Delete、metadata、IDP link（[user_service.proto](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/user/v2/user_service.proto)）；按用户删 Session（[session_service.proto](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/session/v2/session_service.proto)） | 全局；Delete 吊销所有 token（[self-deletion](https://zitadel.com/docs/guides/manage/user/self-deletion)）；Deactivate 是否立即吊销：未验证 | `DeactivateAuthorization` + 项目上的 "Check Role Assignment on Authentication"（[authorization_service.proto](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/authorization/v2/authorization_service.proto)、[projects](https://zitadel.com/docs/guides/manage/console/projects-overview)） |
| Logto | users / profile / custom-data / password / is-suspended / identities / mfa / sessions / grants（[admin-user routes](https://github.com/logto-io/logto/tree/v1.46.0/packages/core/src/routes/admin-user)） | 停用时调用 `signOutUser`，踢掉全部会话 | App-level access control：可按用户、角色、组织、组织角色配置，授权和刷新都会被拒（[app-level access control](https://docs.logto.io/authorization/app-level-access-control)）；`DELETE /users/:id/grants/:grantId` 撤销单个应用的 grant 及其 token 链 |
| Ory | CRUD、JSON Patch、删除单个凭据、`state` 设为 `inactive`、删除会话（[handler.go](https://github.com/ory/kratos/blob/v26.2.0/identity/handler.go)、[session/handler.go](https://github.com/ory/kratos/blob/v26.2.0/session/handler.go)） | `inactive` 后不能登录（[overview](https://github.com/ory/docs/blob/master/docs/kratos/manage-identities/01_overview.mdx)） | 只能按 client 撤销 consent，用户可以重新授权 |
| Casdoor | add / update / delete-user、set-password、logout-user、session、impersonate | `isForbidden` 或软删除时调用 `TerminateUserAccess`：所有应用的 token 过期，发 back-channel logout（[user.go#L1019-L1029](https://github.com/casdoor/casdoor/blob/07cad85/object/user.go#L1019-L1029)） | Application 类型的 Permission 在登录时检查（[check.go#L736](https://github.com/casdoor/casdoor/blob/07cad85/object/check.go#L736)）；组织管理员会跳过这个检查 |
| Authentik | CRUD、`set_password(_hash)`、recovery、impersonate、`account_lockdown`、按用户批量删 session（[schema.yml](https://github.com/goauthentik/authentik/blob/version/2026.8.5/schema.yml)） | `is_active=false` 吊销 session（[user_basic_operations](https://docs.goauthentik.io/users-sources/user/user_basic_operations/)） | 应用的 Policy / Group / User binding；没有任何 binding 时所有人可访问（[manage_apps](https://docs.goauthentik.io/add-secure-apps/applications/manage_apps/)） |
| SuperTokens | 改邮箱 / 密码、删除（可带 linked accounts）、吊销 session、关联 / 解除 tenant（[CDI spec](https://github.com/supertokens/core-driver-interface/blob/master/api_spec.yaml)） | 没有原生 ban；官方插件靠 `banned` 角色 + 吊销 session 实现（[user-banning](https://supertokens.com/docs/post-authentication/user-management/user-banning)） | 用户与 tenant 的关联 |

### 3.4 按应用的用户自定义数据与 token

- **Keycloak**
  - 只有 realm 级的 attributes，由 User Profile schema 管，可按属性设置 user / admin 的 view / edit 权限。
  - schema 之外的 unmanaged 属性最长 2048 字符（[user profile](https://www.keycloak.org/docs/latest/server_admin/index.html#user-profile)）。
  - 进 token 靠 User Attribute protocol mapper；26.8 可以用 client policy 限制允许哪些 mapper 类型（[protocol-mappers](https://www.keycloak.org/admin-api/protocol-mappers)）。
- **Zitadel**
  - metadata 是扁平的 KV：key 最长 200 字符，value 最大 500000 字节（见 user_service.proto 的 `SetMetadataEntry`）。
  - 按项目划分的需求 [#6535](https://github.com/zitadel/zitadel/issues/6535) 仍 open，对应的 PR 已关闭且未合并。
  - 进 token：
    - 请求 scope `urn:zitadel:iam:user:metadata` 后进 userinfo，值是 base64（[user-metadata](https://zitadel.com/docs/guides/manage/customize/user-metadata)）。
    - Actions v2 的 PreAccessToken / PreUserinfo 可以 `append_claims`（[actions usage](https://zitadel.com/docs/guides/integrate/actions/usage)）。
  - 唯一的约定式命名空间出现在 SCIM：`urn:zitadel:scim:{provisioningDomain}:externalId`（[scim2](https://zitadel.com/docs/guides/manage/user/scim2)）。
- **Logto**
  - `profile` 只放 OIDC 标准 claims，`customData` 是任意 JSONB。
  - Account API 开放 Custom data 字段后，**终端用户自己也能改 customData**（[user-data](https://docs.logto.io/user-management/user-data#custom-data)），所以没有"只有服务端可写"的区域。
  - 更新语义：`PATCH /users/:id/custom-data` 对顶层 key 做合并。文档正文写的是"completely overwrite"，与源码和 openapi 不一致，以源码为准。
  - 进 token：Custom JWT 脚本里有 `context.user` 和 `token.clientId`，可以按应用分支处理（[custom token claims](https://docs.logto.io/developers/custom-token-claims/create-script)）。
- **Ory**
  - 三层字段：
    - `traits`：用户可写，受 schema 校验。
    - `metadata_public`：只能经 admin API 写，会出现在 session 里。
    - `metadata_admin`：只有 admin API 能读写。
    - 来源：[metadata](https://github.com/ory/docs/blob/master/docs/kratos/manage-identities/10_managing-users-identities-metadata.mdx)。
  - 进 Hydra token：接受 consent 时传 `session.access_token` / `id_token`，默认放在 `ext` 下（[jwt-access-token](https://github.com/ory/docs/blob/master/docs/oauth2-oidc/jwt-access-token.mdx)）；也可以用 token hook（[oauth2-webhooks](https://github.com/ory/docs/blob/master/docs/hydra/guides/oauth2-webhooks.mdx)）。
  - 大小上限：**未验证**。
- **Casdoor**
  - 用户上有一个 `Properties map[string]string`，属于组织级（[user.go#L237](https://github.com/casdoor/casdoor/blob/07cad85/object/user.go#L237)）。
  - token 内容按应用配置：`TokenFormat` 为 JWT-Custom 时，`TokenFields` / `TokenAttributes` 可以把 `Properties.x` 写成 claim（[token_jwt.go](https://github.com/casdoor/casdoor/blob/07cad85/object/token_jwt.go)）。也就是说，**进 token 是按应用决定的，存储却是全局的**。
- **Authentik**
  - `attributes` 是全局 JSON。2026.8 起可以给它定义带类型的字段（[object-attributes](https://docs.goauthentik.io/sys-mgmt/object-attributes/)，preview）。
  - **Application Entitlements**：归属单个应用，可绑定到用户或组，自带 attributes，应用删除时随之删除。经 mapping 用 `request.user.app_entitlements(provider.application)` 进 token（[manage_apps](https://docs.goauthentik.io/add-secure-apps/applications/manage_apps/)、[property-mappings](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)）。
- **SuperTokens**
  - UserMetadata 是 app 级的，只做顶层合并（[user-metadata](https://supertokens.com/docs/post-authentication/user-management/user-metadata)）。
  - 进 token 靠 override `createNewSession`（[claim-validation](https://supertokens.com/docs/additional-verification/session-verification/claim-validation)）。

### 3.5 委派管理员

- **Keycloak**
  - realm 内的用户分到 realm-management 角色后，可以用该 realm 的控制台 `/admin/{realm}/console`，只看到对应模块。
  - FGAP v2 能做"只管某个 client"或"只管某些组的成员"的受限管理员（[types of realm admins](https://www.keycloak.org/docs/latest/server_admin/index.html#_understanding_different_types_realm_admins_)）。
  - 组织级的自助管理还没交付（#47284）。
- **Zitadel**
  - 控制台管理员可以限定到单个 Org / Project / Project Grant（[administrators](https://zitadel.com/docs/concepts/structure/administrators)），也能经 InternalPermissionService v2 用程序分配（[proto](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/internal_permission/v2/internal_permission_service.proto)）。
  - 注意 PROJECT_OWNER 有 `user.grant.*` 和 `user.read`，**没有 `user.write`**：项目管理员能给用户分配角色，不能创建或修改用户（defaults.yaml）。
- **Logto**
  - Cloud 租户成员只有 Admin / Collaborator / Viewer 三种角色，都是全租户级的（[tenant member management](https://docs.logto.io/logto-cloud/tenant-member-management)）。
  - OSS 默认只有单个管理员，多成员需要 Pro license（[self-hosted license](https://docs.logto.io/logto-oss/self-hosted-license)）。
- **Ory**
  - OSS 没有管理控制台。
  - Network 的 Console 只有 Owner / Developer 两种角色，项目 Developer 对 Identities 全权读写（[roles-and-permissions](https://github.com/ory/docs/blob/master/docs/console/roles-and-permissions.mdx)）。
- **Casdoor**
  - 管理员分两级：`built-in` 组织的用户是全局管理员，普通组织里 `isAdmin` 的用户是该组织管理员（[user.go#L1769-L1775](https://github.com/casdoor/casdoor/blob/07cad85/object/user.go#L1769-L1775)、[org admin](https://casdoor.ai/docs/user/overview)）。
  - 不能限定到某一个应用。
- **Authentik**
  - 角色授予 `Can access admin interface`，再加有限的全局或对象权限，就能进管理界面（[manage_permissions](https://docs.goauthentik.io/users-sources/access-control/manage_permissions/)）。
  - 可以对单个 Application / Provider 授对象权限，只让此人管这个应用的配置。
- **SuperTokens**
  - Dashboard 只有一种限制：配置 `admins` 邮箱列表，不在列表里的 dashboard 用户只能读（[dashboard initial-setup](https://supertokens.com/docs/post-authentication/dashboard/initial-setup)）。
  - tenants 插件在集成方自己的应用里提供租户内管理（[tenant-management-plugin](https://supertokens.com/docs/authentication/enterprise/tenant-management-plugin)）。

### 3.6 嵌入式组件与账号中心

- **Keycloak**
  - 登录只走托管页加重定向。
  - 账户中心 Account Console v3 是 React 写的；`@keycloak/keycloak-account-ui` 可以派生主题，也能把部分页面嵌进自己的 React 应用（[creating your own console](https://www.keycloak.org/ui-customization/creating-your-own-console)）。
  - 26.8 新增按应用终止会话（[26.8.0 release](https://github.com/keycloak/keycloak/releases/tag/26.8.0)）。
- **Zitadel**
  - 没有嵌入组件【推断】。
  - Login V2 是独立的 Next.js 应用，可以 fork 后自己部署（[login-app](https://zitadel.com/docs/guides/integrate/login-ui/login-app)）。
  - 账户中心是 Console 里的 `users/me`（[selfservice](https://zitadel.com/docs/concepts/features/selfservice)）。Login V2 的"改资料""改密码"还没完成。
- **Logto**
  - 托管的 Account Center UI 在 `/account/*`。接入方式是跳转链接加 `?redirect=` 回到应用；前提是先开启 Account API，并逐个字段设成 Edit / ReadOnly / Off（[account center UI](https://docs.logto.io/end-user-flows/account-settings/by-account-center-ui)）。
  - Account API 在 `/api/my-account/*`（[account API](https://docs.logto.io/end-user-flows/account-settings/by-account-api)）。
  - `@logto/elements` Web Components 还没发布（[README](https://github.com/logto-io/logto/blob/v1.46.0/packages/elements/README.md)）。
- **Ory**
  - Ory Elements（Apache-2.0）覆盖 login / registration / settings / consent，会按 identity schema 自动渲染表单（[elements](https://github.com/ory/docs/blob/master/docs/elements/index.mdx)）。
  - OSS 必须自己托管 UI。托管的 Account Experience 只有 Network 有（[account-experience](https://github.com/ory/docs/blob/master/docs/account-experience/index.mdx)）。
- **Casdoor**
  - 嵌入方式只有 js-sdk 的弹窗 / iframe 和 silentSignin（[casdoor-js-sdk](https://github.com/casdoor/casdoor-js-sdk)）。
  - 托管账户中心在 `/account`，字段可见性由组织的 AccountItems 控制（[accountCustomization](https://casdoor.ai/docs/organization/accountCustomization)）。
- **Authentik**
  - 托管的 `/if/user/` 包含应用仪表盘、资料、Sessions、Consent、MFA、token（[user-interface](https://docs.goauthentik.io/users-sources/user/user-interface/)）。
  - flow executor 可以无头执行流程，依赖 cookie（[flow-executor.mdx](https://github.com/goauthentik/authentik/blob/version/2026.8.5/website/api/flow-executor.mdx)）。
  - 嵌入组件库：**未验证**。
- **SuperTokens**
  - Prebuilt UI 可以嵌入登录表单（[embed form](https://supertokens.com/docs/references/frontend-sdks/prebuilt-ui/embed-sign-in-up-form)）。
  - 没有托管账户中心，profile 插件把资料页渲染在集成方自己的前端里（[user-profile](https://supertokens.com/docs/post-authentication/user-management/user-profile)）。
  - Unified Login（托管式）只在 Managed Service 上有（[unified-login](https://supertokens.com/docs/authentication/unified-login/introduction)）。

### 3.7 变更通知与同步

| 系统 | Webhook / 事件 | 签名 | 投递 | SCIM |
|---|---|---|---|---|
| Keycloak | 没有内置 webhook（[#41065](https://github.com/keycloak/keycloak/issues/41065)）；Event Listener SPI 属于 internal SPI（[events](https://www.keycloak.org/docs/latest/server_development/index.html#_events)）；SSF Transmitter 是实验功能（[ssf-support](https://www.keycloak.org/securing-apps/ssf-support)） | SSF 用 JWS 签名的 SET | SSF 有持久化 outbox、指数退避、dead letter | 入站 `/realms/{realm}/scim/v2`，26.8 起 supported，不支持 Bulk（[managing SCIM](https://www.keycloak.org/docs/latest/server_admin/index.html#_managing_scim)）；出站只是提案（[#53837](https://github.com/keycloak/keycloak/issues/53837)） |
| Zitadel | Actions v2 的 Target + Execution，可在 Request / Response / Function / Event 触发（[actions usage](https://zitadel.com/docs/guides/integrate/actions/usage)）；只有 IAM_OWNER 能配置 | HMAC（`ZITADEL-Signature`，含时间戳）/ JWT / JWE（[target.proto](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/action/v2/target.proto)） | 事件型执行进 Postgres 上的 River 队列，单次超时 10s、MaxTtl 5m（[worker.go](https://github.com/zitadel/zitadel/blob/main/internal/execution/worker.go)）；重试策略：未验证 | 入站 `/scim/v2/{orgId}`，Preview，只有 Users（[scim2](https://zitadel.com/docs/apis/scim2)）；出站 [#6601](https://github.com/zitadel/zitadel/issues/6601) open |
| Logto | User.Created / Deleted / Data.Updated / SuspensionStatus.Updated、Role.\*、Organization.\* 等，文档有端点到事件的映射表（[events](https://docs.logto.io/developers/webhooks/events)）；webhook 是租户级的 | `logto-signature-sha-256`（HMAC，[secure webhooks](https://docs.logto.io/developers/webhooks/secure-webhooks)） | 只有 5xx 才重试，最多 3 次，超时 10s，有 `deliveryId`（[hook utils](https://github.com/logto-io/logto/blob/v1.46.0/packages/core/src/libraries/hook/utils.ts)）；没有持久化队列【推断】 | 无（[#9331](https://github.com/logto-io/logto/issues/9331)，官方说在路线图上） |
| Ory | OSS 只有自助流程的 before / after hook（[configure hooks](https://github.com/ory/docs/blob/master/docs/kratos/hooks/01_configure-hooks.mdx)）；Admin API 的改动不产生事件【推断】；Live events 只对 Network 企业合同开放（[live-events](https://github.com/ory/docs/blob/master/docs/actions/live-events.mdx)） | — | — | 入站只有 Network 有，按组织划分（[scim](https://github.com/ory/docs/blob/master/docs/kratos/manage-identities/50_scim.mdx)）；出站：未验证 |
| Casdoor | 事件名就是 API 的 action 名，由审计 Record 触发（[record.go](https://github.com/casdoor/casdoor/blob/07cad85/object/record.go)、[webhooks](https://casdoor.ai/docs/webhooks/overview)） | 无，只能加自定义 header | WebhookEvent 表持久化，默认重试 3 次、间隔 60s，可以重放（[webhook_worker.go](https://github.com/casdoor/casdoor/blob/07cad85/object/webhook_worker.go)） | 入站 `/scim/Users`、`/scim/Groups`（[scim](https://casdoor.ai/docs/scim/overview)）；Syncer 默认双向同步（[syncer.go](https://github.com/casdoor/casdoor/blob/07cad85/object/syncer.go)） |
| Authentik | Notification Rule + Webhook Transport，用 Event Matcher 筛选事件（[transports](https://docs.goauthentik.io/sys-mgmt/events/transports/)） | 无（[events/models.py](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/events/models.py)） | dramatiq 默认重试 5 次【推断】 | **出站** SCIM Provider：只推送绑定到该应用的用户，失去访问后 deprovision（[scim provider](https://docs.goauthentik.io/add-secure-apps/providers/scim/)）；入站 Source 会按 userName 在全租户范围关联用户（[scim source](https://docs.goauthentik.io/users-sources/sources/protocols/scim/)） |
| SuperTokens | 无，只能用 override 代替（[api-overrides](https://supertokens.com/docs/references/backend-sdks/api-overrides)） | — | — | 无（[core#898](https://github.com/supertokens/supertokens-core/issues/898)、[core#1009](https://github.com/supertokens/supertokens-core/issues/1009)） |

### 3.8 已有用户导入与本地用户关联

- **Keycloak**
  - 三条途径：`POST /users`、`partialImport`、离线的 `kc.sh import`（[importExport](https://www.keycloak.org/server/importExport)）。
  - 导入已有哈希：在 `credentials[]` 里给 `credentialData` / `secretData` 就会原样存入（[RepresentationToModel.java](https://github.com/keycloak/keycloak/blob/26.8.1/server-spi-private/src/main/java/org/keycloak/models/utils/RepresentationToModel.java)）。
  - 内置算法只有 argon2 / pbkdf2 系列（[hashAlgorithm](https://www.keycloak.org/docs/latest/server_admin/index.html#hashalgorithm)）；bcrypt 要用第三方 SPI（[#34752](https://github.com/keycloak/keycloak/issues/34752)）。
  - partialImport 会保留传入的 `id`（[UsersPartialImport.java](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/partialimport/UsersPartialImport.java)）。
- **Zitadel**
  - v2 `AddHumanUser` 可以指定自定义 `user_id`、metadata、`hashed_password`（MCF 格式）、`idp_links`（[migrate users](https://zitadel.com/docs/guides/migrate/users)）。
  - 批量导入只有 v1 的 `ImportData`，改进需求 [#5524](https://github.com/zitadel/zitadel/issues/5524) 仍 open。
  - 支持的算法基于 passwap 库：argon2、bcrypt、md5 系列、phpass、drupal7、sha2 crypt、scrypt、pbkdf2；首次登录后重新哈希（[secrets](https://zitadel.com/docs/concepts/architecture/secrets)、[passwap](https://github.com/zitadel/passwap)）。
- **Logto**
  - 没有批量端点，官方方案是逐条调 `POST /api/users`，或者首次登录时 JIT 迁移（[user-migration](https://docs.logto.io/user-management/user-migration)）。
  - `passwordAlgorithm` 支持 Argon2i / id / d、SHA1、SHA256、MD5、Bcrypt，外加 Legacy（任意 Node crypto 算法、PBKDF2、Firebase scrypt），首次登录后升级为 Argon2。
  - 自定义 `id` 只有自托管版可用，Cloud 返回 501。没有 externalId 字段。
- **Ory**
  - 单条导入是 `POST /admin/identities` 带上 `credentials`，批量导入是 `PATCH /admin/identities`，上限 1000 条，带密码时 200 条（[import](https://github.com/ory/docs/blob/master/docs/kratos/manage-identities/25_import-user-accounts-identities.mdx)、[handler.go#L51-L52](https://github.com/ory/kratos/blob/v26.2.0/identity/handler.go#L51-L52)）。
  - 支持的算法最全：bcrypt、argon2、pbkdf2、scrypt、firescrypt、ssha、sha、md5、crypt 系列、hmac（[hash_comparator.go](https://github.com/ory/kratos/blob/v26.2.0/hash/hash_comparator.go)）。
  - 不支持的格式可以走 `password_migration` webhook。
  - 顶层的 `external_id` 字段全局唯一，可以用 `GET /admin/identities/by/external/{id}` 查询（[external-id](https://github.com/ory/docs/blob/master/docs/kratos/manage-identities/60_external-id.mdx)）。
- **Casdoor**
  - xlsx 上传按 `plain` 原样写入密码，同名用户跳过（[user_upload.go](https://github.com/casdoor/casdoor/blob/07cad85/object/user_upload.go)）。
  - `add-user` 带上 `passwordType` 和 `passwordSalt` 就能原样导入已有哈希。支持 8 种算法：plain、salt、sha512-salt、md5-salt、bcrypt、pbkdf2-salt、argon2id、pbkdf2-django（[cred/manager.go](https://github.com/casdoor/casdoor/blob/07cad85/cred/manager.go)）。
  - 用户上有带索引的 `ExternalId` 字段。
- **Authentik**
  - 没有批量端点，要先 `POST /core/users/` 再调 `set_password_hash`（Django 编码格式，[validators.py](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/lib/validators.py)）。
  - 支持的算法清单只出现在 main 分支的文档里（pbkdf2_sha256 / argon2 / bcrypt_sha256 / scrypt，[password-hashes.mdx](https://github.com/goauthentik/authentik/blob/main/website/docs/core/password-hashes.mdx)），2026.8.5 版没有这份文档。
- **SuperTokens**
  - `POST /bulk-import/users` 每批最多 1 万条，由 cron 异步处理；导入记录可以带 `externalUserId`、metadata、roles、哈希（argon2 / bcrypt / firebase_scrypt）（[account-migration](https://supertokens.com/docs/migration/account-migration)）。
  - UserIdMapping 映射完成后，SDK 返回的 userId 就是外部 ID（[user-id-mapping](https://supertokens.com/docs/migration/legacy/account-creation/user-id-mapping)）。

### 3.9 SDK / OpenAPI 文档形态

- **Keycloak**：
  - 官方发布 OpenAPI 3.0.3。
  - 官方 SDK 只有两个：Java 的 `keycloak-admin-client`（手写，[keycloak-client](https://github.com/keycloak/keycloak-client)），以及 JS 的 `@keycloak/keycloak-admin-client`（v1 手写，v2 的 clients 部分由 Kiota 生成，[js/libs](https://github.com/keycloak/keycloak/tree/26.8.1/js/libs/keycloak-admin-client)）。
  - 另有 CLI `kcadm.sh`。
- **Zitadel**：
  - proto 是唯一的接口定义，同时提供 gRPC、Connect 和 REST。文档站从 proto 生成 OpenAPI（[buf.gen.yaml](https://github.com/zitadel/zitadel/blob/main/apps/docs/buf.gen.yaml)）。
  - Python / Node / Java / PHP / Ruby / .NET 客户端都由 OpenAPI Generator 自动生成，只覆盖 v2（如 [client-python](https://github.com/zitadel/client-python)）。
  - 另有 Go 的 [zitadel-go](https://github.com/zitadel/zitadel-go)（是否生成：未验证）。
- **Logto**：
  - 每个实例提供 `/api/swagger.json`，以及按用途分开的 `/.well-known/management.openapi.json` 等，由 zod guard 自动生成后合并手写的描述。
  - 托管的参考文档是 [openapi.logto.io](https://openapi.logto.io/)。
  - 唯一的 Management SDK 是 `@logto/api`（Node）：类型由 openapi-typescript 生成，token 获取由手写代码封装（[packages/api](https://github.com/logto-io/logto/tree/v1.46.0/packages/api)）。
- **Ory**：
  - 每个仓库提交了 OpenAPI 规范（[kratos/spec](https://github.com/ory/kratos/tree/v26.2.0/spec)）。
  - SDK 全部由 openapi-generator 生成，共 11 种语言（[ory/sdk](https://github.com/ory/sdk/tree/master/clients)、[sdk overview](https://github.com/ory/docs/blob/master/docs/kratos/sdk/01_overview.md)）。
- **Casdoor**：
  - Swagger 由注释生成，`/swagger` 只在 dev 模式下提供（[developer-guide/swagger](https://casdoor.ai/docs/developer-guide/swagger)）。
  - 后端 SDK 覆盖 10 余种语言（[sdk](https://casdoor.ai/docs/how-to-connect/sdk)）。Go SDK 是手写的，直接拿应用凭据当管理凭据（[casdoor-go-sdk](https://github.com/casdoor/casdoor-go-sdk/tree/master/casdoorsdk)）。
- **Authentik**：
  - [schema.yml](https://api.goauthentik.io/schema.yml) 生成 Go / Python / Rust / TS 四种客户端。
  - 文档说明这些客户端用来管理配置对象，不是拿来给应用接 SSO 的（[clients.mdx](https://github.com/goauthentik/authentik/blob/version/2026.8.5/website/api/clients.mdx)）。
- **SuperTokens**：
  - CDI 和 FDI 都是 OpenAPI 3，但 master 上的 spec 停在 5.2.0，落后于 core 支持的 5.7（[api_spec.yaml](https://github.com/supertokens/core-driver-interface/blob/master/api_spec.yaml)、[coreDriverInterfaceSupported.json](https://github.com/supertokens/supertokens-core/blob/v12.4.1/coreDriverInterfaceSupported.json)）。
  - 后端 SDK 是手写的 recipe 库，没有独立的 management client【推断】。

## 4. 对 Polaris 的启示

现状的依据是 [#171](https://github.com/zibyn/polaris/issues/171) 的现状说明和已有 ADR：
- Management API 权限是实例级的，持有 Role 的 M2M Application 看得到整个用户池。
- 没有按 Application 存的用户数据。
- Webhook（薄事件，[ADR 0022](../adr/0022-webhook-thin-events-and-back-channel-logout.md)）和 Back-Channel Logout 已有。
- Application 可以要求持有 Role 才能登录。
- 不合并 User（[ADR 0003](../adr/0003-no-user-merge.md)）。

有一处需要核对：#171 写着"Management API 无 OpenAPI"，但 `internal/management/management.go` 的注释和 [docs/management-api.md](../management-api.md) 都指向 `{issuer}/v1/management/openapi.json`，`audit_test.go` 也请求了它。看来已经有 OpenAPI，只是没有 SDK。

### #174 可见范围

- **主流做法**：限制可见范围的边界都落在"用户所属的分组"上（Zitadel Org、Keycloak 组 / realm、SuperTokens tenant），没有一家落在"应用"上。
  - Logto、Ory、Casdoor 干脆不做，官方都建议在集成方后端外面包一层代理（Logto #8821 的官方回复）。
  - Authentik 能精确到逐个用户对象，但要靠 initial permissions 一个个授出去。
- **分歧点**：
  1. 边界取什么：用"用过该 Application 的 User"（Polaris 没有组或组织，这是唯一现成的集合），还是"持有该 Application 默认 API 上某个 Role 的 User"。后者与 ADR 0007 和"要求持有 Role 才能登录"是同一个集合，【推断】更自洽。
  2. 越界时返回 404 还是 403。【推断】Zitadel 的做法是过滤，不报错。
  3. 范围外的 User 能不能被"引入"范围，例如集成方想给一个池里已有的人分配 Role。这本身就是一种跨应用可见：Zitadel PROJECT_OWNER 能 `user.read` 和 `user.grant`，但不能写用户。
- 【推断】行业里没有可以照搬的形状，这正是 Polaris 能做出差异的地方；但不要发明组织模型（#171 已把多租户划在范围外）。

### #175 写操作

- **主流做法**：
  - 禁用和删除一律是全局的。
  - "按应用禁用"由准入策略实现，不是用户状态：Logto App-level access control 是最完整的产品形态，Zitadel 用"撤销 Authorization + 登录时检查 Role"，Polaris 已有的"Application 要求持有 Role 才能登录"与后者同构。
  - 按应用撤销会话或授权：Logto `DELETE /users/:id/grants/:grantId`、Keycloak `DELETE consents/{client}`、Hydra 撤销 consent。
- **分歧点**：
  1. 受限的 M2M 能不能做全局写（禁用 / 删除 / 改 Identifier / 改密码）。Zitadel 的答案是项目级不能写用户，Casdoor 和 Logto 是能。
  2. 改 Identifier 和用户资料：Polaris 的这两样跨所有 Application 共享（GLOSSARY），集成方改了会影响别的应用。
  3. 管理员代填的 Identifier 算已验证（ADR 0016）；如果 M2M 也能代填，就等于集成方能替任意人认领邮箱或手机号。
- 【推断】给受限 M2M 的默认可写范围是"本应用的 Role 和本应用的数据，再加按应用撤销 Session"；全局写操作单独授予。

### #176 应用自定义数据

- **主流做法**：七家都只有一份挂在用户上的全局 JSON / KV，按应用区分全靠约定 key 前缀。进 token 都由服务端规则决定（mapper / 脚本 / Actions），而且 Casdoor、Logto 可以按应用决定写不写。
- **分歧点**：
  1. **谁能写**：Logto customData 用户自己也能写（坑）；Kratos 把用户可写的 `traits` 和只有管理员可写的 `metadata_admin` 分开，Auth0 是 `user_metadata` 和 `app_metadata` 分开。
  2. **命名空间**：没有一家原生按应用划分（Zitadel #6535 被搁置）。Authentik Entitlements 是"归属应用的授权对象"，形状不同。
  3. **进 token 的方式**：整块放进一个 claim（Zitadel 的 base64 metadata），还是由配置决定。还要考虑与 RFC 9068 `aud` 的关系，【推断】只进发给该 Application 默认 API 的 access token 最自然。
  4. **大小限制**：只有 Zitadel（500KB）和 Keycloak（2048 字符）写明了，其余未验证。
  5. **同步**：Webhook 是薄事件，所以数据变更是否也发 `user.updated` 加 `changed`，需要一并决定。

### #177 委派管理员

- **主流做法**：只有 Keycloak（FGAP 到 client / 组）、Zitadel（Project 管理员）和 Authentik（对象权限）支持"只管一个应用"，而且管的主要是**应用配置和角色分配**，不是用户本身。Logto、Ory、Casdoor、SuperTokens 都不支持。
- **分歧点**：
  1. 委派管理员看到的用户范围，是否直接复用 #174 的边界。【推断】应该复用：Zitadel 的项目管理员和受限 M2M 用的是同一套权限模型。Polaris 的管理端本身也是 Management API 的一个调用方（GLOSSARY），可以天然共用。
  2. 委派管理员能不能改 Application 的安全配置（重定向 URI、密钥、登录方式）。Keycloak 和 Authentik 能做到"管这个 client"，Zitadel PROJECT_OWNER 也能管应用。
  3. Role 的作用域：Polaris 的 Role 挂在 API 上（ADR 0007），而委派是按 Application 划分的。多个 Application 共用一个 API 时，作用域的单位应该是 API 还是 Application，需要定。

### #178 导入与关联

- **主流做法**：
  - 接受已有哈希，首次登录后升级到当前算法。
  - 最低支持 bcrypt + argon2 + pbkdf2；Ory 和 Zitadel 还加了 scrypt、md5 / sha、crypt 系列、Firebase scrypt。
  - 不支持的格式走登录时 JIT 校验：Ory `password_migration` webhook、Logto 的 Action。
- **关联本地用户的三种形状**：
  - 专用 `external_id`，全局唯一、可以按它查询：Ory、Casdoor。
  - 导入时自定义 user id：Zitadel、Logto 自托管、Keycloak partialImport。
  - 映射表：SuperTokens UserIdMapping。
- **分歧点**：
  1. Polaris 的 `sub` 是所有 Application 的主键（ADR 0003）。如果允许自定义 id，就要定格式和冲突规则。`external_id` 是全局的还是按 Application 划分（这与 #176 有关）也要定。
  2. 批量接口：同步批量（Ory 每批 1000）还是异步任务（SuperTokens 每批 1 万）。Logto 和 Authentik 只能逐条导入。
  3. 导入时 Identifier 算不算已验证：与 ADR 0016 的"代填即已验证"同一个问题。
  4. 导入的 External Identity（微信 openid / unionid 等）如何带入；ADR 0003 不做自动合并，所以导入时的冲突要直接报错。

### #179 SDK / 文档形态

- **主流做法**：
  - 发布 OpenAPI，并由它生成多语言客户端：Zitadel、Ory、Authentik。
  - 手写 SDK 的（Casdoor、Keycloak）也照样能用，只是要逐个语言维护。
  - Logto 走中间路线：类型生成、外层手写封装 token 获取，只有一种语言。
- **分歧点**：
  1. 生成还是手写。【推断】Polaris 已经有 `openapi.json`，生成路线的边际成本最低；手写只值得给 Go 一个薄封装（负责 token 缓存）。
  2. 语言优先级：#171 的场景是国内 native app 和小程序的业务后端，常见 Go / Java / Node / Python。【推断】先 Go 和 Node。
  3. 是否像 Zitadel / Logto 那样每个实例都提供 spec，还是统一发布一份。实例上提供的 spec 能反映该实例的版本，Logto 就让 OSS 用户以实例上的为准。
  4. 文档要不要把"集成方后端代理 Management API"写成推荐架构：Logto 的官方指南就是这么写的，它也正是 #174 不做时的退路。

### 未单列 ticket 的维度

- **嵌入式组件 / 账号中心**（#171 Not yet specified）：
  - 托管账户中心是主流：Keycloak、Zitadel、Logto、Casdoor、Authentik 都有。
  - 嵌入组件真正可用的只有 SuperTokens Prebuilt UI 和 Ory Elements，两者都是"没有托管页时的替代品"；Logto 的组件还没发布。
  - 【推断】Polaris 已有托管页和账号中心，嵌入组件不是行业标配，可以先不做第三种模式。
- **SCIM**：
  - 入站 SCIM 服务端常见，是给企业从目录推用户进来用的。
  - 出站 SCIM 只有 Authentik 做了，形状是"只推绑定到该应用的用户"，与 #174 的边界同构。
  - 【推断】先定 #174，再看出站 SCIM 能否直接复用那个边界；Webhook 薄事件加 Management API 已经覆盖了"同步"的基本需求。

## 5. 未验证事项

- **Keycloak**：FGAP 的 Organizations 权限会不会把用户查询限制在本组织成员内；Event Listener 是否与事务同步执行。
- **Zitadel**：
  - 只有 Project 级角色的服务账号调 ListUsers 实际能看到谁。
  - Deactivate / Lock 是否立即吊销已签发的 token。
  - Actions v2 的重试次数和顺序保证。
  - SCIM 是否已正式 GA：PR #10350 移除了 preview 提示，但文档标题仍写着 Preview。
  - zitadel-go 是生成的还是手写的。
- **Logto**：
  - customData 和自定义 JWT claims 的大小上限。
  - 组织角色能否绑定 Management API。
  - webhook 在进程重启时是否丢失投递。
  - App-level access control 在 Cloud 各套餐里是否收费。
- **Ory**：
  - metadata 的大小上限。
  - Network API Key 能否收窄权限。
  - 出站 SCIM。
  - OSS 版 admin API 的改动有没有事件。
  - Account Experience 能否在 OEL 下自托管。
- **Casdoor**：
  - Organization 类型的 access key：文档说"valid for all operations within the organization"，代码看起来按匿名处理（[base.go#L209-L222](https://github.com/casdoor/casdoor/blob/07cad85/routers/base.go#L209-L222)）。
  - 用 User key 加 API Permission 实现只读 M2M 的可行性。
  - `logPostOnly` 对 webhook 触发的影响。
- **Authentik**：webhook 的实际重试策略；有无官方嵌入组件；`password-hashes.mdx` 会在哪个正式版发布；Admin UI 能否只显示被授了对象权限的用户。
- **SuperTokens**：`activity_log` 有无读取 API；CDI 5.3–5.7 的完整 spec；dashboard 能否按 tenant 限定；多租户的价格。
