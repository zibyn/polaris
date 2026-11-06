# 上游 Provider 的 email 与用户资料：主流平台怎么做

- 调研日期：2026-11-06
- 问题：用户通过上游 Provider（Google、通用 OIDC、GitHub、飞书 / Lark、企业微信、钉钉）登录时，主流认证平台：
  1. 会不会导入上游的 email？会不会标为已验证？标记规则是什么，默认值是什么？
  2. 上游 email 和已有本地用户的 email 相同时怎么处理：自动关联、要求用户证明拥有已有账号、拒绝，还是新建一个重复用户？
  3. name、avatar 等资料只在首次登录时导入，还是每次登录都同步？用户自己改过的值会不会被覆盖？
  4. 手机号会不会导入？会不会标为已验证？
  5. 飞书 / 企业微信 / 钉钉连接器分别映射哪些字段（email 还是企业邮箱、name、avatar、mobile），email 算不算已验证？
- 判断标准：只看主流平台的实际做法，不参考 Polaris 现有的 ADR。
- 范围：
  - 飞书 / 企业微信 / 钉钉的 API 本身返回哪些字段，见另一份调研 [cn-idp-user-profile.md](cn-idp-user-profile.md)，本文不重复。本文只看各平台的连接器从这些字段里**取了什么、怎么处理**。
  - Microsoft Entra 只看 External ID（面向客户的 CIAM），不看 workforce 租户里的 B2B guest。
- 写法约定：
  - **[已验证]**：读过官方文档原文或源码。
  - **[未验证：搜索摘要]**：只看到搜索引擎摘要，没读到原文。
  - **[推断]**：我自己的判断。
  - 每条结论都附一手来源 URL。
- 取证方式：
  - 本次运行环境访问不了大部分厂商官网（keycloak.org、zitadel.com、auth0.com、docs.aws.amazon.com 等都被代理拦截），但能访问 github.com。所以开源平台读的是 GitHub 上 `main` / `master` 的源码和仓库内文档。
  - 商业平台中，Okta（`okta/okta-developer-docs`）、Microsoft Entra（`MicrosoftDocs/entra-docs`）、Clerk（`clerk/clerk-docs`）、Authing（`Authing/docs`）的官方文档源都托管在 GitHub 上，读的是原文。
  - Auth0 读的是 `auth0/docs` 仓库。这是 Auth0 旧版文档的源码，现行官网的措辞可能已经改过。
  - AWS Cognito 的文档仓库已归档、没有正文，只能依赖搜索摘要。
  - 没有部署任何实例实测。

## 1. 结论速览

1. **导入 email：几乎所有平台都会导入。** 各平台的分歧不在"导不导入"，而在**导入后算不算已验证**。
   - 例外一：MaxKey 根本不按 Provider 建用户，第三方账号必须先绑定到已有用户。
   - 例外二：Dex 不存用户，只把上游的 claim 透传给下游。
2. **email 是否已验证，主流做法是"照搬上游的 `email_verified`；上游没给时，按每个 Provider 的管理员开关决定，开关默认关（即不信任）"。**
   - Auth0 [已验证]：federated 连接的 `email_verified` 等于 IdP 返回的值，IdP 没返回就是 `false`。Azure AD / ADFS 改由管理员显式选择"总是 true / 总是 false"。
   - Keycloak [已验证]："Trust Email"默认关。关的时候，新用户的 email 一律未验证；开的时候，照搬上游 `email_verified`，上游没给时才当作已验证。
   - Logto [已验证]：只接收已验证的 email，未验证的直接丢弃。OIDC 连接器的 `trustUnverifiedEmail` 默认 `false`，而且它只在上游**没有给出** `email_verified` 时才生效。
   - Entra External ID [已验证]：自定义 OIDC 上游返回了 email 时，必须带 `email_verified=true` 才允许创建账号。
   - Zitadel [已验证]：照搬上游 `email_verified`，GitHub 固定视为已验证。
   - Ory Kratos [已验证]：默认一律未验证，需要在 Jsonnet 映射里显式声明 `verified_addresses`。
   - 有一家逐个 Provider 硬编码，并把企业通讯录的邮箱当作已验证：Casdoor 对飞书、钉钉"非空即已验证"，对企业微信则不标验证。
3. **email 冲突：默认既不静默合并，也不允许建出两个同 email 的用户。主流是"提示用户，并要求证明自己拥有已有账号"。**
   - Keycloak 默认的 first broker login 流程 [已验证]：先确认要关联，再通过邮件或重新登录证明拥有已有账号。
   - Ory [已验证]：先输入已有账号的密码，再关联。
   - Logto [已验证]：默认出一个关联页，让用户选择"关联"或"新建"。
   - Zitadel [已验证]：默认不按 email 自动关联。
   - 默认会建出重复账号的：Auth0（"所有身份默认是独立的"）、Authing（默认"创建新用户"）、Authentik（默认 `identifier` 模式，不按 email 匹配）。
   - 默认自动关联的：Casdoor（`BindingRule` 默认是 Email 加 Phone，前提是上游已验证）、Clerk（两边的 email 都已验证时直接关联，连密码也跳过）。
   - 文档里明确警告过账号接管风险的 [已验证]：Keycloak（AutoLink "dangerous"）、Auth0（"should not automatically link accounts based on the user's emails"）、Authentik（email_link "can have security implications"）、Ory（"Never trust unverified email addresses"）、Zitadel（源码注释 "prevent potential account takeovers"）、Clerk、Casdoor（源码注释）、Authing（"存在用户身份信息被第三者冒用的风险"）。
4. **name / avatar 等资料的同步，开源平台默认"只在首次登录时导入"，Auth0 默认"每次登录覆盖"。**
   - 默认只导入一次的 [已验证]：Keycloak 的 Sync Mode 在管理界面上默认是 `IMPORT`；Logto 默认"只在注册时同步"；Ory 的 `update_identity_on_login` 默认关；Authentik 的默认 source authentication flow 只有登录这一步；Casdoor 只填补本地为空的字段。
   - 默认每次覆盖的 [已验证]：Auth0。它的"Sync user profile attributes at each login"默认开，所以 root 属性不可编辑。要让属性可编辑，就得把这个开关关掉。
   - Zitadel 由每个 IdP 上的"Automatic update"开关控制 [已验证]，默认值未核实。Okta 要把 IdP 设成 profile source 才会在每次登录时更新 [未验证：搜索摘要]。Cognito 每次登录都会更新映射的属性 [未验证：搜索摘要]。
   - 凡是开了"每次同步"的，都会覆盖用户自己改过的值。Logto 和 Auth0 的文档都明说了这一点 [已验证]。
5. **手机号：规则与 email 一致，但没有一个平台把手机号当作关联依据的默认首选。**
   - Logto 只接收 `phone_verified` 为真的手机号。
   - Zitadel 照搬 `phone_number_verified`。
   - Entra External ID 有 `phone_number_verified` 映射。
   - 中国连接器（Logto 的飞书、钉钉、企业微信，以及 Casdoor 的飞书、钉钉）直接把通讯录手机号当作可信号码导入 [已验证]。
6. **中国连接器（飞书 / 企业微信 / 钉钉）的共同点：都导入 name、avatar、email、mobile。email 默认被当作可信（已验证）。** 各家的具体处理见第 7 节。
   - Logto：三个连接器都提供 `disableEmailSync` 开关，可以不导入 email。
   - Casdoor：飞书优先取个人 `email`，为空时回退到 `enterprise_email`。
   - Authing：飞书、企业微信可以用手机号或邮箱"字段匹配"到已有账号，但这个功能默认关。

## 2. 开源平台

### 2.1 Keycloak（`main`，commit `30cf683`）

**email 与验证**

- "Trust Email"开关 [已验证]：
  - 官方文档原文："When ON, Keycloak trusts email addresses from the identity provider ... If the claim is absent, the Trust Email setting provides the default verification status."
  - 来源：[configuration.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/identity-broker/configuration.adoc)
- 源码里的实际行为 [已验证]：
  - `OIDCIdentityProvider` 的规则：`isTrustEmail()` 为假，或者上游没有 `email_verified` 时，交给父类处理；否则 `user.setEmailVerified(emailVerified)`，即照搬上游的值。来源：[OIDCIdentityProvider.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/broker/oidc/OIDCIdentityProvider.java)
  - 父类的规则：新用户，或者 email 发生变化时，把 email 设为 `trustEmail` 的值，也就是关的时候设为未验证。来源：[AbstractIdentityProvider.java](https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/broker/provider/AbstractIdentityProvider.java)
  - 结论：**Trust Email 关着的时候，即使上游给了 `email_verified=true`，Keycloak 也把 email 标为未验证。**
- 默认值 [已验证]：
  - `IdentityProviderRepresentation.trustEmail` 是 `Boolean`。管理界面里它是一个默认关的开关（`SwitchField field="trustEmail"`），源码中 `Booleans.isTrue(null)` 的结果为假。
  - 来源：[AdvancedSettings.tsx](https://github.com/keycloak/keycloak/blob/main/js/apps/admin-ui/src/identity-providers/add/AdvancedSettings.tsx)

**email 冲突** [已验证]

来源：[first-login-flow.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/identity-broker/first-login-flow.adoc)

- 默认流程是 `first broker login`：
  1. `Review Profile`：默认值是 `missing`，即上游缺少 email 等必填项时才显示资料页。
  2. `Create User If Unique`：没有同 email 或同用户名的本地账号时，直接新建并关联。
  3. 已有同名账号时，进入 `Handle Existing Account` 子流程：
     - `Confirm Link Existing Account`：提示用户"已有账号，是否关联"。
     - `Verify Existing Account By Email`：realm 配了 SMTP 时，向已有账号的邮箱发确认邮件。
     - `Verify Existing Account By Re-authentication`：用已有账号的密码（或者另一个已关联的 IdP）重新登录。
- 文档原文："Automatically linking the existing local account to the external identity provider is a potential security hole."
- 可以配置成静默关联：自建一个流程，加入 `Automatically Set Existing User`。文档给了 WARNING："The AutoLink authenticator is dangerous in a generic environment where users can register themselves using arbitrary usernames or email addresses."
- 也可以配置成拒绝：把 `Create User If Unique` 设为 REQUIRED，有冲突时直接显示错误页。

**资料同步** [已验证]

- 可选的 Sync Mode：
  - `import`：只在首次登录导入。
  - `force`：每次登录都更新。
  - `legacy`：旧版本的行为。
  - 每个 mapper 还能单独覆盖（`inherit` 表示沿用 IdP 上的设置）。
  - 来源：[mappers.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/identity-broker/mappers.adoc)
- 管理界面的默认值是 `SYNC_MODES[0]`，即 `"IMPORT"`。来源：[AdvancedSettings.tsx](https://github.com/keycloak/keycloak/blob/main/js/apps/admin-ui/src/identity-providers/add/AdvancedSettings.tsx)
- 用户可以在 Account Console 里改自己的资料。在 `force` 模式下，下一次登录会把改过的值覆盖掉。[推断]（由"force updates user data at each user login"得出。）

**手机号**

- 没有内置的手机号字段，只能用 attribute importer mapper 导入成普通属性，不带验证状态。[推断]

**中国连接器**

- Keycloak 官方不带飞书、企业微信、钉钉连接器，社区扩展（各种 `keycloak-services-social-*`）需要自己装。它们产出的 email 同样受 Trust Email 和 first broker login 的约束。[推断]

### 2.2 Zitadel（`main`）

**email 与验证** [已验证]

- 每种上游的 `idp.User` 都要实现 `IsEmailVerified()`：
  - 通用 OIDC 返回上游的 `email_verified`。来源：[oidc/session.go](https://github.com/zitadel/zitadel/blob/main/internal/idp/providers/oidc/session.go)
  - GitHub 固定返回 `true`，注释原文是 "because GitHub validates emails themselves"。来源：[github/github.go](https://github.com/zitadel/zitadel/blob/main/internal/idp/providers/github/github.go)
- 创建用户时，用户的 email 验证状态就取这个值。来源：[external_provider_handler.go](https://github.com/zitadel/zitadel/blob/main/internal/api/ui/login/external_provider_handler.go)

**email 冲突** [已验证]

- 每个 IdP 上有四个开关："Automatic creation"、"Automatic update"、"Account creation allowed"、"Account linking allowed"。来源：[_general_config_description.mdx](https://github.com/zitadel/zitadel/blob/main/apps/docs/content/guides/integrate/identity-providers/_general_config_description.mdx)
- 另有一项"Automatic linking options"，可选按 username 或 email 匹配。文档原文："ZITADEL will check for an existing account with the configured criteria (username or email) and prompt the user to link the account"。来源：[introduction.mdx](https://github.com/zitadel/zitadel/blob/main/apps/docs/content/guides/integrate/identity-providers/introduction.mdx)
- 源码中，按 email 自动关联的前提是上游已验证，并且 Zitadel 这边的 email 也已验证（用的查询是 `NewUserVerifiedEmailSearchQuery`）。注释原文："both ... are verified to prevent potential account takeovers"。
- 默认值是 `AutoLinkingOptionUnspecified`，即不自动关联。这时登录页会让用户选择"新建账号"或"关联已有账号"，后者需要登录已有账号。

**资料同步** [已验证]

- 只有开了"Automatic update"（`provider.IsAutoUpdate`）才会在每次登录时更新。文档原文："if the lastname changes on the ... account, the information will be changed on the ZITADEL account on the next login"。
- 这个开关的默认值**未核实**。从 API 的 bool 零值看是 `false`。[推断]

**手机号** [已验证]

- 通用 OIDC 的 `IsPhoneVerified()` 返回 `phone_number_verified`。GitHub 不提供手机号。

### 2.3 Logto（`master`）

**email 与验证** [已验证]

Logto 的用户表没有 `email_verified` 字段，`primaryEmail` 本身就代表"已验证"。所以 Logto 的做法是：**连接器只把已验证的 email 交给核心，未验证的直接丢弃。**

- Google 连接器：`email: conditional(email_verified && email)`。来源：[connector-google](https://github.com/logto-io/logto/blob/master/packages/connectors/connector-google/src/index.ts)
- GitHub 连接器：取公开 email，没有公开 email 时取 `/user/emails` 里 `verified && primary` 的那一个。来源：[connector-github](https://github.com/logto-io/logto/blob/master/packages/connectors/connector-github/src/index.ts)
- OIDC 社交连接器和企业 SSO 连接器：`email: (email_verified ?? trustUnverifiedEmail) && email`，`trustUnverifiedEmail` 默认 `false`（`z.boolean().optional().default(false)`）。
  - 上游明确给出 `email_verified=false` 时，即使打开这个开关也不会接收。
  - 来源：[connector-oidc](https://github.com/logto-io/logto/blob/master/packages/connectors/connector-oidc/src/index.ts)、[sso/OidcConnector/index.ts](https://github.com/logto-io/logto/blob/master/packages/core/src/sso/OidcConnector/index.ts)、[sso/types/oidc.ts](https://github.com/logto-io/logto/blob/master/packages/core/src/sso/types/oidc.ts)
- 新用户只在 email 没被别人占用时才写入 `primaryEmail`，注释原文 "Sync the email only if the email is not used by other users"。来源：[social-verification.ts](https://github.com/logto-io/logto/blob/master/packages/core/src/routes/experience/classes/verifications/social-verification.ts)
- 社交身份没有提供已验证的 email、而 email 又是必填的注册标识时，Logto 会让用户自己填一个 email 并用验证码验证。来源：[social-sign-in.mdx](https://github.com/logto-io/docs/blob/master/docs/end-user-flows/sign-up-and-sign-in/social-sign-in.mdx)

**email 冲突** [已验证]

- 文档原文："By default, a related account linking page is shown to users during social sign-up, allowing them to link their social account to an existing account or create a new one."
- 打开 "Automatic account linking" 后会静默关联。
- 如果用户选择"新建"，email 和手机号不会写入新账号，以保证唯一。
- 来源：[social-sign-in.mdx](https://github.com/logto-io/docs/blob/master/docs/end-user-flows/sign-up-and-sign-in/social-sign-in.mdx)
- 企业 SSO 的行为不同："The SSO identities will be linked to existing accounts if the email matches."（来源：[enterprise-connectors.mdx](https://github.com/logto-io/docs/blob/master/docs/connectors/enterprise-connectors.mdx)）
- 【推断】Logto 的手动关联页只需要用户点"关联"，不要求重新验证已有账号。它敢这样做，前提是能进入关联流程的 email 都已经是上游验证过的。

**资料同步** [已验证]

- 每个连接器有一项 "Sync user profiles"。文档原文："The default is to 'sync only upon registration'. 'sync at each sign-in' is an alternative but may overwrite custom user data."（来源：[social.mdx](https://github.com/logto-io/docs/blob/master/docs/connectors/social.mdx)）
- 源码中，老用户在 `syncProfile` 打开时只同步 `name` 和 `avatar`，**email 和手机号只在注册时写入，之后不再同步**（见 `toSyncedProfile`）。

**手机号** [已验证]

- OIDC 连接器：`phone: phone_verified && phone`。新用户的手机号只在没被占用时写入 `primaryPhone`。

### 2.4 Casdoor（`master`）

**email 与验证** [已验证]

- `idp.UserInfo` 带有 `EmailVerified` 和 `PhoneVerified` 两个字段，注释原文："Providers that make no such assertion leave it false"。来源：[idp/provider.go](https://github.com/casdoor/casdoor/blob/master/idp/provider.go)
- 各 Provider 的赋值：
  - Google：照搬上游。
  - GitHub：`email != ""`，注释说明 GitHub 只返回已验证的邮箱。
  - 自定义 OAuth：通过 userMapping 映射 `emailVerified` 字段。
  - 飞书、钉钉、企业微信：见第 7 节。
- 新用户的 `EmailVerified` 直接取 `userInfo.EmailVerified`。来源：[controllers/auth.go](https://github.com/casdoor/casdoor/blob/master/controllers/auth.go)

**email 冲突** [已验证]

- `getExistUserByBindingRule`：`BindingRule` 为空时默认是 `["Email", "Phone"]`。
- 规则：上游 email 已验证，并且本地账号可以绑定（`isEmailBindable`：本地 email 已验证，或者不是用户自助注册的账号）时，**静默关联到已有用户**。手机号同理。
- 注释原文："a provider account with someone else's unverified email must not take over their account"。
- 匹配不上，但新建用户时 email 或手机号已存在：直接报错 "Email already exists"，不会建出重复账号。
- 来源：[controllers/auth.go](https://github.com/casdoor/casdoor/blob/master/controllers/auth.go)

**资料同步** [已验证]

- `SetUserOAuthProperties` 每次登录都会把上游值写进 `oauth_<type>_*` 属性。主字段（`DisplayName`、`Email`、`Avatar`）**只在本地为空时才填**，用户改过的值不会被覆盖。
- 来源：[object/user_util.go](https://github.com/casdoor/casdoor/blob/master/object/user_util.go)

### 2.5 Authentik（`main`）

**email 冲突** [已验证]

- `SourceUserMatchingModes` 有以下几种：
  - `identifier`：默认值，只按上游 ID 匹配。
  - `email_link`：原文 "Can have security implications when a source doesn't validate email addresses."
  - `email_deny`：email 已存在时拒绝注册。
  - `username_link` 和 `username_deny`。
- 来源：[authentik/core/models.py](https://github.com/goauthentik/authentik/blob/main/authentik/core/models.py)
- 默认的 `identifier` 模式不看 email，所以 email 相同时会走注册流程，新建一个用户。【推断】Authentik 的 email 字段不是唯一约束，因此会出现两个同 email 的用户。

**email 验证**

- 用户模型没有 email 已验证这一状态。【推断】（`authentik/core/models.py` 里没有相应字段。）

**资料同步** [已验证]

- 老用户登录时，source 把 property mapping 的结果放进 `PLAN_CONTEXT_PROMPT`，交给 authentication flow 处理。来源：[flow_manager.py](https://github.com/goauthentik/authentik/blob/main/authentik/core/sources/flow_manager.py)
- 默认的 `default-source-authentication` 流程里只有 `userloginstage`，没有 user write stage。所以**默认不会在登录时更新资料**，管理员要自己加一个 User Write stage。来源：[flow-default-source-authentication.yaml](https://github.com/goauthentik/authentik/blob/main/blueprints/default/flow-default-source-authentication.yaml)

### 2.6 Ory Kratos / Ory Network

**email 与验证** [已验证]

- 由 Jsonnet data mapper 决定写入哪些 traits。文档给的是 danger 级别的提示："Never trust unverified email addresses and phone numbers."
- GitHub 示例只在 `email_verified` 为真时才写入 email。
- mapper 可以输出 `identity.verified_addresses`，把地址标为已验证。不输出时地址就是未验证。
- 来源：[90_data-mapping.mdx](https://github.com/ory/docs/blob/master/docs/kratos/social-signin/90_data-mapping.mdx)、[strategy_registration.go](https://github.com/ory/kratos/blob/master/selfservice/strategy/oidc/strategy_registration.go)

**email 冲突** [已验证]

- 默认行为：email 已存在时，提示用户输入已有账号的密码，输对后才关联。文档原文："Email verification is not required for this flow due to the verification step that follows"。
- 可以打开 `account_linking_mode: automatic`，但只支持 Google 消费者账号和 Apple，而且要求两边的 email 都已验证。Google Workspace 被排除在外，原因是域名过期后可能被别人重新注册。
- 来源：[95_account-linking.mdx](https://github.com/ory/docs/blob/master/docs/kratos/social-signin/95_account-linking.mdx)

**资料同步** [已验证]

- 文档原文："By default, the data mapper runs only during registration."
- `update_identity_on_login: automatic` 可以让 mapper 每次登录都重跑。mapper 能读到当前 identity，可以选择保留用户改过的值。重跑**不会改动 verified addresses**。

**中国连接器** [已验证]

- Kratos 内置 Lark 和钉钉 Provider。文档示例的 mapper 直接写入 `claims.email`，不检查是否已验证。来源：[81_lark.mdx](https://github.com/ory/docs/blob/master/docs/kratos/social-signin/81_lark.mdx)、[80_dingtalk.mdx](https://github.com/ory/docs/blob/master/docs/kratos/social-signin/80_dingtalk.mdx)

### 2.7 Dex [已验证]

- Dex 不存用户，每次登录都把上游 claim 透传给下游。所以不存在"同步"和"冲突"的问题：每个 connector 的身份互相独立。
- OIDC connector：上游缺少 `email_verified`、并且请求了 email scope 时，直接报错 `missing "email_verified" claim`，除非配置了 `insecureSkipEmailVerified`（打开后视为 `true`）。来源：[connector/oidc/oidc.go](https://github.com/dexidp/dex/blob/master/connector/oidc/oidc.go)
- GitHub connector 固定 `EmailVerified: true`。来源：[connector/github/github.go](https://github.com/dexidp/dex/blob/master/connector/github/github.go)

### 2.8 Authelia

- 目前不能作为 Relying Party 对接上游 IdP，官方路线图把 "OpenID Connect 1.0 Relying Party" 标为 needs-design，所以不适用本文的问题。[未验证：搜索摘要]（[roadmap](https://www.authelia.com/roadmap/planning/openid-connect-1.0-relying-party/)）

### 2.9 MaxKey（`main`）[已验证]

- 社交登录回调查不到绑定关系时，返回 `Message.PROMPT`，要求用户先登录已有账号再绑定。**不按 Provider 自动建用户，也不按 email 匹配。**
- 已绑定的用户每次登录时，上游原始 JSON 会写入关联记录的 `socialUserInfo`，但不改用户主资料。
- 来源：[SocialSignOnEndpoint.java](https://github.com/dromara/MaxKey/blob/main/maxkey-starter/maxkey-starter-social/src/main/java/org/dromara/maxkey/authn/support/socialsignon/SocialSignOnEndpoint.java)

## 3. 商业平台

### 3.1 Auth0（来源：`auth0/docs` 仓库）

**email 与验证** [已验证]

- 文档原文："When users authenticate with a federated identity provider ..., the value of the `email_verified` field will match what the identity provider returns in the user profile. If the identity provider does not return any value, it will be set to `false`."（来源：[email-verified.md](https://github.com/auth0/docs/blob/master/articles/users/guides/email-verified.md)，现行页面是 <https://auth0.com/docs/manage-users/user-accounts/user-profiles/verified-email-usage>）
- Azure AD / ADFS 连接有一项 "Email Verification"，可选 "Always set `email_verified` to `true` / `false`"。用 common endpoint 时必须选 `false`。
- 租户可以打开"登录时为 Azure AD / ADFS 用户补做邮箱验证"，用一次性验证码确认。
- 来源：[azuread-adfs-email-verification.md](https://github.com/auth0/docs/blob/master/articles/connections/enterprise/azuread-adfs-email-verification.md)

**email 冲突** [已验证]

- 文档原文："Auth0 treats all identities as separate by default."（来源：[overview-user-account-linking.md](https://github.com/auth0/docs/blob/master/articles/users/concepts/overview-user-account-linking.md)）也就是说，同一个 email 默认会有两个用户。
- 关联只能由应用显式发起（Account Link 扩展、Actions、Management API）。
- 文档原文："You **should not automatically link accounts based on the user's emails**. Always prompt users to authenticate again before doing that."
- 文档还要求关联前检查 `email_verified`，并给出了攻击者预先注册受害者 email 的场景。

**资料同步** [已验证]

- 文档原文："By default, user profile attributes provided by identity providers ... are not directly editable because they are updated from the identity provider each time the user logs in."（来源：[_users_update_normalized_profile_attributes.md](https://github.com/auth0/docs/blob/master/articles/_includes/_users_update_normalized_profile_attributes.md)）
- 关掉每个连接上的 "Sync user profile attributes at each login" 后，只在创建时写入，之后 `name`、`picture` 等属性就可以编辑了。来源：[configure-connection-sync.md](https://github.com/auth0/docs/blob/master/articles/dashboard/guides/connections/configure-connection-sync.md)
- 同步开着时，`email_verified` 也会在下一次登录时被刷新。（见 Azure AD 那一页："users will get `email_verified` set to `false` the next time they log in, unless ... Sync ... is disabled"。）

**手机号**

- 用户资料里有 `phone_number` / `phone_verified`，但 federated 连接怎样写入这两个字段，没有找到原文。[推断]

### 3.2 Okta / Okta Customer Identity（来源：`okta/okta-developer-docs`）

**email 冲突** [已验证]

- 新建 IdP 时的默认值：`Account Link Policy: Disabled`，`Match Against: Okta Username`，`IdP username: idpuser.email`。
- 改成 `Automatic` 后，用上游 email 去匹配 Okta 的 username，匹配上就静默关联。
- 文档还建议："consider disabling account linking after all existing users from the external IdP have signed in"。
- 来源：[concepts/identity-providers/index.md](https://github.com/okta/okta-developer-docs/blob/master/packages/@okta/vuepress-site/docs/concepts/identity-providers/index.md)、[accountlink.md](https://github.com/okta/okta-developer-docs/blob/master/packages/@okta/vuepress-site/docs/guides/add-an-external-idp/main/openidconnect/accountlink.md)
- 【推断】Link Policy 为 Disabled 并开着 JIT 时，"JIT account creation ... only work for end users who aren't already Okta users"。所以如果上游 email 和已有用户的 username 冲突，JIT 建不出用户，登录会失败，而不是建出重复用户。

**资料同步**

- 概念页写的是 "Profile sync: If a user updates their profile at the IdP, those changes appear in Okta the next time they use the provider to sign in." [已验证]（同上，来源 concepts/identity-providers）
- 实际要在 IdP 的 JIT 设置里勾选 "Update attributes for existing users"，并把 IdP 设成 profile source（属性的 source priority），否则映射只在创建用户时生效。[未验证：搜索摘要]（[Okta support](https://support.okta.com/help/s/article/Mappings-for-IdP-to-Okta-do-not-Have-Option-for-Create-and-Update)）

**email 验证**

- 没找到 Okta 对上游 `email_verified` 的处理规则。[未验证]

### 3.3 Microsoft Entra External ID（来源：`MicrosoftDocs/entra-docs`）

**email 与验证** [已验证]

- 自定义 OIDC 上游的映射表原文："`email_verified` ... If the email claim is present, a value of `true` is required for account creation."
- `phone_number_verified` 也在映射表里。
- 来源：[reference-oidc-claims-mapping-customers.md](https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/external-id/customers/reference-oidc-claims-mapping-customers.md)
- email 默认是必填的，可以通过 user flow 改成可选。来源：[how-to-custom-oidc-federation-customers.md](https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/external-id/customers/how-to-custom-oidc-federation-customers.md)

**email 冲突与资料同步**

- 没有找到原文。[未验证]

**nOAuth 相关**

- 微软的 "Migrate away from using email claims for user identification or authorization" 一文要求：用 `tid` 加 `oid` 作为主键，不用 email。2023-06 以后创建的多租户应用，默认会从 token 里移除未验证域名的 email。还提供了 `xms_edov` claim，表示 email 的域名所有者是否已验证。[未验证：搜索摘要]（[learn.microsoft.com](https://learn.microsoft.com/entra/identity-platform/migrate-off-email-claim-authorization)）

### 3.4 AWS Cognito

以下均为 [未验证：搜索摘要]：

- 每次 federated 登录时，Cognito 都会用 IdP 的最新值更新已映射的属性。（[attribute mapping](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)）
- 映射进来的 email 默认未验证。（[re:Post](https://repost.aws/knowledge-center/cognito-email-verified-attribute)）要标为已验证，需要把上游的 `email_verified` 映射过来。
- federated 用户默认是一个独立的用户（用户名形如 `Google_xxx`），不会和同 email 的本地用户合并。要关联，得在 Pre sign-up 触发器里调用 `AdminLinkProviderForUser`。API 文档原文警告："it is critical that it only be used with external IdPs and provider attributes that have been trusted by the application owner"。（[AdminLinkProviderForUser](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminLinkProviderForUser.html)）

### 3.5 Clerk（来源：`clerk/clerk-docs`）

**email 冲突** [已验证]

- 社交连接：两边的 email 都已验证时，直接关联并登录，"This even applies to password-protected accounts"。
- 上游 email 未验证时，先走一遍邮箱验证再关联。
- 本地 email 未验证时，要求用户先改密码，以防账号接管。
- 来源：[social-connections/account-linking.mdx](https://github.com/clerk/clerk-docs/blob/main/docs/guides/configure/auth-strategies/social-connections/account-linking.mdx)
- 企业 SSO："Email addresses from IdPs are considered verified by default"。上游返回未验证的 email 时，不关联，而是新建账号。来源：[enterprise-connections/account-linking.mdx](https://github.com/clerk/clerk-docs/blob/main/docs/guides/configure/auth-strategies/enterprise-connections/account-linking.mdx)

**资料同步**

- 企业连接有一个 "sync user attributes" 字段，控制是否在每次登录时更新属性。默认值未核实。[未验证：搜索摘要]（[Backend EnterpriseConnection](https://clerk.com/docs/reference/backend/types/backend-enterprise-connection)）

### 3.6 Authing（来源：`Authing/docs`）

**email 冲突** [已验证]

- 文档原文："不开启「账号身份关联」时，用户通过身份源登录时默认创建新用户。"
- 开启后有两种方式：
  - 「字段匹配」：按手机号、邮箱或其他字段匹配，匹配上就直接登录到已有账号并绑定。
  - 「询问绑定」：让用户选择"创建新账号"或"绑定已有账号"。绑定时需要用手机验证码、邮箱验证码或密码登录已有账号。
- 来源：[account-association.md](https://github.com/Authing/docs/blob/main/docs/guides/connections/account-association.md)、[account-binding.md](https://github.com/Authing/docs/blob/main/docs/guides/connections/account-binding.md)
- 风险提示原文："如果身份源中的对应匹配字段不可信，将存在用户身份信息被第三者冒用的风险，请谨慎使用本功能。"（来源：[user-mapping.md](https://github.com/Authing/docs/blob/main/docs/guides/connections/user-mapping.md)）

**email 验证与资料同步**

- 没有找到原文。[未验证]

## 4. 跨平台对比表

| 平台 | 导入 email | 已验证规则（默认） | email 冲突（默认 → 可选） | 资料同步（默认 → 可选） | 手机号 |
|---|---|---|---|---|---|
| Keycloak | 是 | Trust Email 开关，**默认关**：关时一律未验证；开时照搬上游 `email_verified`，缺省视为已验证 | 提示用户，并通过邮件或重新登录证明拥有已有账号 → 可改成 AutoLink（文档标为 dangerous）或拒绝 | **IMPORT**（只导入一次）→ FORCE / LEGACY，可按 mapper 单独设置 | 无内置字段，靠 mapper 导入成属性 [推断] |
| Zitadel | 是 | 照搬上游 `email_verified`；GitHub 固定 true | 不自动关联，由用户选择新建或关联（关联需登录已有账号）→ 按 email 自动关联要求两边都已验证 | 开了 Automatic update 才在每次登录时更新（默认值未核实） | 是，照搬 `phone_number_verified` |
| Logto | 只接收已验证的 | 未验证就丢弃；OIDC `trustUnverifiedEmail` 默认 false（只在上游没给该 claim 时生效） | 出关联页让用户选"关联"或"新建" → Automatic account linking；企业 SSO 默认按 email 关联 | **只在注册时同步** → 每次登录同步 name/avatar（会覆盖用户改动）；email/手机号只在注册时写入 | 只接收 `phone_verified` 为真的 |
| Casdoor | 是 | 逐个 Provider 硬编码：Google 照搬，GitHub、飞书、钉钉非空即 true，企业微信 false | **静默关联**（BindingRule 默认 Email+Phone，要求上游已验证）；新建时遇到重复则报错 | 每次登录只填补本地为空的字段，不覆盖 | 是，飞书、钉钉标为已验证 |
| Authentik | 是 | 用户模型没有验证状态 [推断] | **identifier**：不看 email，会新建重复用户 [推断] → email_link / email_deny 等 | 默认流程不更新资料 → 管理员手动加 User Write stage | 看 property mapping |
| Ory Kratos | 看 mapper | 默认未验证；mapper 显式输出 `verified_addresses` 才算已验证 | 提示输入已有账号密码后关联 → Google/Apple 可自动关联（要求两边都已验证） | **只在注册时** → `update_identity_on_login: automatic`（不改 verified addresses） | 看 mapper |
| Dex | 透传 | 照搬上游；OIDC 缺少该 claim 时报错，除非配置 `insecureSkipEmailVerified` | 不存用户，不适用 | 不存用户，每次透传 | 不适用 |
| MaxKey | 否 | 不适用 | 必须先绑定已有用户，不自动建用户 | 只存原始 JSON | 否 |
| Auth0 | 是 | 照搬上游，缺省为 false；Azure AD/ADFS 由管理员选择 | **默认独立**，会出现同 email 的两个用户；文档明确反对按 email 自动关联 | **每次登录覆盖**（默认开）→ 关掉后只在创建时写入 | 有字段，federated 规则未找到 |
| Okta | 是 | 未找到 | Account Link Policy **默认 Disabled** → Automatic 按 email=username 静默关联 | 概念上会同步；实际需要开 "Update attributes for existing users" 并设 profile source [搜索摘要] | 未找到 |
| Entra External ID | 是（默认必填） | 上游有 email 时，`email_verified` 必须为 true 才能建账号 | 未找到 | 未找到 | 有 `phone_number_verified` 映射 |
| Cognito | 是 | 默认未验证，需要映射 `email_verified` [搜索摘要] | 默认独立用户 → Pre sign-up 触发器加 `AdminLinkProviderForUser` [搜索摘要] | **每次登录更新**映射的属性 [搜索摘要] | 看映射 |
| Clerk | 是 | 社交照搬上游；企业 SSO 默认视为已验证 | **两边都已验证就自动关联**；上游未验证时先做邮箱验证；企业 SSO 未验证时新建账号 | 企业连接有 sync 开关 [搜索摘要] | 未找到 |
| Authing | 是 | 未找到 | **默认新建用户** → 字段匹配（静默）/ 询问绑定（需要证明拥有已有账号） | 未找到 | 飞书、企业微信可按手机号匹配 |

## 5. 公众标准

**多数平台默认这样做**

1. **身份主键是 (Provider, 上游 sub)，不是 email。**
   - 所有平台都按上游 ID 识别回访用户。email 只用来填资料，或者作为关联候选。
   - OpenID Connect Core 1.0 §5.7 "Claim Stability and Uniqueness" 写明，`iss` 加 `sub` 是唯一可依赖的稳定标识，email 可能变化、可能被复用。[未验证：搜索摘要]（[OIDC Core §5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability)）
   - 微软在 nOAuth 事件后的迁移指南也是同一个立场。
2. **上游的 email 要导入。** 导入后，下游的 OIDC 客户端（Grafana、Sentry 等）才能拿到 `email` claim。除 MaxKey 和 Dex 外，每家都会导入。
3. **email 是否已验证，以上游的 `email_verified` 为准；上游没给时，按每个 Provider 的管理员开关决定，开关默认"不信任"。**
   - Keycloak、Auth0、Logto、Zitadel、Entra External ID、Cognito 都属于这一类。
   - 已知只返回已验证邮箱的社交 Provider（GitHub 的 primary verified email），多家直接硬编码为已验证：Zitadel、Casdoor、Dex、Logto。
4. **email 冲突时，默认既不静默合并，也不允许建出两个同 email 的用户。默认做法是"提示用户，并要求证明拥有已有账号"。**
   - 证明方式包括：输入已有账号的密码、点击发到已有邮箱的确认链接，或者用已有账号重新登录。Keycloak、Ory、Zitadel、Authing 的询问绑定都是这样。
   - 静默自动关联是可选项，各家文档都附带了安全警告。即使打开，也要求**两边的 email 都已验证**（Zitadel、Clerk、Ory、Casdoor 的源码或文档都写明了这一条）。
5. **name / avatar 默认只在首次登录导入，"每次登录同步"是可选开关。** 文档都会提示，打开后会覆盖用户自己的修改。Keycloak、Logto、Ory、Authentik、Casdoor 都是这样。
6. **手机号与 email 同规则，只有上游声明已验证时才算已验证。** 手机号作为冲突关联的依据只是可选项（Casdoor、Authing、Logto 支持）。

**明显的分歧**

- **Auth0 和 Cognito 默认"每次登录都用上游覆盖资料"。** 这是 SaaS 平台把上游当作资料源头的取向。在 Auth0 上，代价是资料不能编辑。
- **默认会建出重复账号的：Auth0、Authing、Authentik。** 它们把"所有身份独立"作为安全默认，关联交给应用或管理员去做。
- **默认静默关联的：Casdoor 和 Clerk。** 它们把"两边都已验证"当作足够的证据，不再要求用户重新证明。
- **对飞书、企业微信、钉钉的 email 一律信任：Casdoor（飞书、钉钉）和 Logto（三家都是）。** 理由是这些邮箱来自企业通讯录。但企业通讯录里的邮箱是管理员录入的，可能并没有验证过；Auth0 正是以同样的理由，不肯默认信任 Azure AD / ADFS 的邮箱。【推断】这是中国连接器生态和国际主流做法最大的差异。
- **Okta 的 Account Link Policy 默认 Disabled，但设为 Automatic 后按 email 等于 username 匹配，且不要求 email 已验证。** 它把安全性交给管理员"只对可信 IdP 开启"。

## 6. 对 Polaris 的直接含义【推断】

- 只存上游 ID、不存 email，偏离了上面第 2 条，正是下游客户端拿不到 email 的原因。按公众标准，Provider 登录应当导入 email 和 name，并且：
  - 用上游的 `email_verified`（加上每个 Provider 一个默认关闭的"信任 email"开关）来决定 Polaris 本地是否把它标为已验证。
  - 冲突时不要静默合并，按 Keycloak 的默认流程处理：提示用户，并通过邮件或登录证明拥有已有账号。
- 飞书、企业微信、钉钉的 email 是否默认可信，业界没有统一答案：
  - Casdoor、Logto 默认信任。
  - Keycloak、Auth0 的思路是由管理员显式开启。
  - 这是一个需要拍板的决策点，建议走 ADR。

## 7. 中国连接器字段映射明细

各 API 返回哪些字段，见 [cn-idp-user-profile.md](cn-idp-user-profile.md)。

| 平台 / 连接器 | name | avatar | email 取哪个字段 | email 是否视为已验证 | mobile | 来源 |
|---|---|---|---|---|---|---|
| Logto 飞书 | `name` | `avatar_url` | `email`（个人邮箱字段） | 是（Logto 只存已验证的 email），可以用 `disableEmailSync` 关掉 | `mobile` → 主手机号 | [connector-feishu-web](https://github.com/logto-io/logto/blob/master/packages/connectors/connector-feishu-web/src/index.ts) |
| Logto 企业微信 | `getuserdetail.name`，缺省用 userid | `avatar` | `getuserdetail.email` | 是，可关 | `mobile` | [connector-wecom](https://github.com/logto-io/logto/blob/master/packages/connectors/connector-wecom/src/index.ts) |
| Logto 钉钉 | `nick` | `avatarUrl` | `email` | 是，可关 | `stateCode` + `mobile` | [connector-dingtalk-web](https://github.com/logto-io/logto/blob/master/packages/connectors/connector-dingtalk-web/src/index.ts) |
| Casdoor 飞书 | `name` | `avatar_url` | 优先 `email`，为空时用 `enterprise_email` | 是（非空即 true，注释写的是 "enterprise directory email"） | `mobile`，非空即视为已验证 | [idp/lark.go](https://github.com/casdoor/casdoor/blob/master/idp/lark.go) |
| Casdoor 企业微信（自建） | `name` | `avatar` | `getuserdetail.email` 或 `user/get.email` | **否**（未赋值，默认 false） | 不取 | [idp/wecom_internal.go](https://github.com/casdoor/casdoor/blob/master/idp/wecom_internal.go) |
| Casdoor 企业微信（第三方） | `name` | `avatar` | 不取 | 不适用 | 不取 | [idp/wecom_third_party.go](https://github.com/casdoor/casdoor/blob/master/idp/wecom_third_party.go) |
| Casdoor 钉钉 | `nick` | `avatarUrl` | `email` | 是（非空即 true） | `mobile`，非空即视为已验证 | [idp/dingtalk.go](https://github.com/casdoor/casdoor/blob/master/idp/dingtalk.go) |
| Ory 的 Lark / 钉钉 | 看 mapper | 看 mapper | 文档示例取 `claims.email` | 默认否（要在 mapper 里声明 `verified_addresses`） | 看 mapper | [81_lark.mdx](https://github.com/ory/docs/blob/master/docs/kratos/social-signin/81_lark.mdx) |
| Authing 飞书 / 企业微信 / 钉钉 | 未找到 | 未找到 | 文档要求开通"邮箱"和"企业邮箱"两个权限 | 未找到；"字段匹配"可按邮箱或手机号关联（默认关） | 是，可以用来匹配 | [lark-internal](https://github.com/Authing/docs/blob/main/docs/guides/connections/enterprise/lark-internal/README.md)、[account-binding.md](https://github.com/Authing/docs/blob/main/docs/guides/connections/account-binding.md) |
| MaxKey 飞书 / 企业微信 / 钉钉 | 不导入 | 不导入 | 不导入 | 不适用 | 不导入 | [SocialSignOnEndpoint.java](https://github.com/dromara/MaxKey/blob/main/maxkey-starter/maxkey-starter-social/src/main/java/org/dromara/maxkey/authn/support/socialsignon/SocialSignOnEndpoint.java) |
| Keycloak 社区扩展 | 未核实 | 未核实 | 未核实 | 受 Trust Email 控制 [推断] | 未核实 | 不适用 |
