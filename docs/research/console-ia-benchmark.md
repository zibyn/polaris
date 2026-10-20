# 主流认证平台管理端的信息架构与引导方式

- 调研日期：2026-10-07
- 问题（[#41](https://github.com/zibyn/polaris/issues/41)，属于地图 [#40](https://github.com/zibyn/polaris/issues/40)）：Logto、Auth0、Authing、Clerk、Zitadel 的管理端各自是怎么做的？具体看这几项：
  - 顶层导航怎么分组；Application、API、登录方式、通道、安全策略分别放在哪一层；
  - 创建 Application 时是否按类型分步引导；
  - 技术字段怎么命名、怎么解释；
  - 配置之间的依赖怎么提示；
  - 有没有快速开始清单和空状态引导；
  - 说明文字是什么语气、多长。
- 用途：为 #40 的信息架构、引导流程、风格指南和界面用语对照表提供对照材料。本项目现在的管理端分五组：概览 / 身份 / 接入 / 安全 / 审计（见 `web/src/routes/console.tsx`、[docs/spec/consoles.md](../spec/consoles.md)）。
- 说明：任务里提到的"命名调研 `docs/research/idp-naming.md`"在本仓库任何分支上都不存在，所以本文不涉及概念命名（领域术语以 `GLOSSARY.md` 为准），只讲界面层的组织方式和文案。

## 0. 怎么读这份文档

- **第 1 节是结论**，第 2–7 节按问题逐项对照，**附录是逐平台的原文摘录**。
- 文案一律照抄原文：中文版产品摘中文，没有中文版的摘英文。每条都附一手来源。凡是我自己的判断，都标了 **【推断】**；找不到一手来源的，标 **未验证**。
- 取证方式：
  - 五路并行调查。
  - 开源产品读源码里的界面字符串：
    - Logto 读 `packages/phrases/.../zh-cn` 和 `packages/console`，版本 [`c814034`](https://github.com/logto-io/logto/tree/c814034401b0e13a6f461e0b0835ad3bbb84c9c2)；
    - Zitadel 读 `console/src/assets/i18n/zh.json` 和 Angular 源码，版本 [`8a54a2a`](https://github.com/zitadel/zitadel/tree/8a54a2a0c611b244a282bab70060e6e9bc7cfce3)。
  - 闭源产品读官方文档：
    - Auth0 读 auth0.com/docs；
    - Clerk 读 clerk.com/docs、changelog，以及官方的 Dashboard 路由清单 [dashboard.clerk.com/llms.txt](https://dashboard.clerk.com/llms.txt)；
    - Authing 读 docs.authing.cn v2 使用指南（更新于 2026-03-25）。
  - 我自己用 `gh api` 抽查了 Logto 和 Zitadel 的若干关键字符串，与摘录一致：连接器缺失警告、`client_id` 说明、CORS 说明、侧栏分组名、Zitadel 入职清单标题、开发模式提示、"客户保密"误译。其余内容没有逐条复核。
- **局限**：
  - 闭源产品（Auth0、Clerk、Authing）看不到真实界面，空状态、弹窗原话、提示的视觉形态大多只能标 **未验证**。
  - 开源产品的结论只对应上述 commit，发布版可能有出入。

## 1. 结论速览

**已验证的事实**

1. **没有一家按"读者"分组，都是按"对象 / 职能"分组。**
   - 共性：都有 Application 和 API，都有用户，都有安全和日志；登录方式与通道几乎都分在两个地方。
   - Logto 的侧栏分六组：概览 / 身份验证 / 授权 / 用户 / 开发者 / 租户。
   - Auth0 新版导航（Early Access）也是按职能分组：Integration / Customization / Messaging / Automation & Extensibility / Security & Monitoring。
2. **Application 和 API 总是放在相邻位置，但不一定在同一组。**
   - Auth0 经典导航：Applications 下面有 Applications、APIs 两项。
   - Logto：应用在「身份验证」组，API 资源在「授权」组。
   - Zitadel：API 只是应用的一种类型，挂在"项目"下。
   - Authing：资源和权限挂在每个应用的「访问授权」标签页里。
   - Clerk：没有 API 这个对象。
3. **登录方式和通道（SMS / 邮件服务）一律分开放。**
   - Logto：「登录与账户」对「连接器」。
   - Auth0：Authentication > Passwordless 对 Branding > Phone / Email Provider。
   - Zitadel：「登录行为和安全」对「通知」组下的「SMTP 提供商 / 短信提供商」。
   - Authing：应用的「登录控制」对「设置 → 消息服务」。
   - Clerk：User & authentication 对 Emails / SMS。
   - 本项目把这两者都放在"安全"组里，在这五家里没有先例。
4. **签名密钥一律不是一级入口，都藏在租户或实例设置里。**
   - Logto：租户设置 → OIDC 配置。
   - Auth0：Settings → Signing Keys。
   - Zitadel：默认设置 → OIDC Web Keys。
   - Authing：设置 → 基础设置 → 密钥管理。
   - Clerk：只在 API keys 页给出 JWKS 公钥。
5. **创建 Application 有两种主流做法。**
   - 第一种是"名称 + 类型"一个弹窗创建，回调地址留到之后再填：Auth0、Authing，以及 Logto 的"跳过教程"路径。
   - 第二种是"先选框架或教程"，回调地址在教程的某一步里填：Logto 默认路径；Zitadel 快速开始只问名称和重定向地址，并默认开启开发模式。
   - **唯一在向导里逐步追问技术细节的是 Zitadel 的通用向导**：名称和类型 → 认证方式 → 重定向 → 概览。它还提供"我是专业人士。跳过此向导。"的开关。
   - 类型选项大体都是四类：原生 / 单页 / 传统 Web / 机器对机器。每个类型都配一句"是什么 + 举例"。
6. **技术字段保留英文原名，再用一句人话解释。** 几种写法：
   - Logto：「应用的唯一标识，通常由 Logto 生成。等价于 OpenID Connect 中的 client_id。」
   - Auth0："The unique identifier for your application. …"
   - Authing：先写中文名，括号里给英文，例如「应用 ID（App ID）」。
   - **"audience" 这个词在 Logto、Zitadel、Authing 的界面上都不出现**：Logto 叫「API 标识符」，Auth0 叫 "Identifier"，只有 Auth0 在租户设置的 Default Audience 处解释了它和 audience 的关系。
7. **配置之间的依赖，有界面级提示的只有 Logto。**
   - Logto 的做法是"内联警告 + 立即设置链接，不禁用"：「尚未设置 SMS 短信连接器。在完成该配置前，用户将无法通过此登录方式登录。立即设置连接器。」
   - Logto 在 MFA 上更严一层："警告 + 保存时拦截"。
   - Logto 对互斥项的做法是"禁用 + tooltip 说明原因"。
   - Zitadel 有现成的侧栏警告图标机制，但相关代码被注释掉了；SMTP 必填的警告文案存在，却没有被使用。
   - Auth0、Clerk、Authing 只在文档里写依赖关系。界面上是否有提示：**未验证**。
8. **快速开始清单方面，只有 Zitadel 做成了带进度的清单；Logto 和 Clerk 用的是另外的形式。**
   - Zitadel：顶栏有进度条，点开是浮层，可以隐藏；当前启用 3 项：创建项目 → 注册应用 → 登录应用。
   - Logto：「开始上手」页是一组卡片，不跟踪进度。
   - Clerk：首页列出生产上线还差哪几步，最后一步是 Deploy certificates。
   - Auth0 Home 页的内容：**未验证**。
9. **空状态有三种水平。**
   - Logto 最用心：没有任何应用时，不显示空表格，直接内嵌框架和教程库；Webhook 空状态有一句用途说明加一个创建按钮。
   - Zitadel 只有一句「尚未创建任何角色。」这类短句。
   - 其余三家：**未验证**。
10. **说明文字普遍是一到三句，用第二人称。** 常见结构是"是什么 → 默认行为或能否留空 → 后果或风险"，常附示例值或推荐值。两家开源产品的中文都有明显的机翻痕迹：
    - Zitadel 把 Client Secret 的说明译成「将您的客户保密在一个安全的地方」；
    - Logto 的 Webhook 停用确认被译成「重新激活」，意思正好相反。

**【推断】对 #40 的启示**

- 本项目的五组分法可以保留。但"通道"放在"安全"组里有两个问题：一是别家没有这么放的；二是读者（开发者 / 运维）想"开短信登录"时会先去找"登录方式"。较稳的做法是二选一：
  - 方案一：在"安全"组内把「登录方式」和「通道」拆成两个相邻页面，学 Logto 用内联警告互相链接；
  - 方案二：另设"登录"组，把登录方式、通道、Provider 放在一起，"安全"组只留策略和密钥。
- 签名密钥是低频操作。可以放到"安全"组的末尾，或者单独放进一个"设置"页，不要和高频配置并列。
- 创建 Application 采用"类型卡片（四选一，每张卡一句说明加举例）→ 只问名称 → 创建后进入分步配置"的做法：Auth0 和 Logto 跳过教程时就是这样，对本项目来说最轻。
  - 本项目不提供框架 SDK 教程，所以 Logto 那种"先选框架"的形态不适用。
  - 如果要在向导里收集回调地址，可以学 Zitadel，把每一步限定为一个问题。
- 依赖提示直接照搬 Logto 的三种模式就够用：
  1. 缺前置配置 → 内联警告 + 跳转链接，不禁用；
  2. 会导致不可用的组合 → 保存时拦截，并说明原因；
  3. 互斥 → 禁用 + 说明原因。
- 概览页的快速开始清单有先例（Zitadel），而且项数少，只有 3 项。本项目可以做成"配通道 → 建 Application → 建 API"这样的 3 步。全部完成后可以隐藏。做不做由 #40 决定。
- 风格指南可以借鉴的句式：
  - Logto「通常不需要对此字段进行操作」——说明可以留空；
  - Auth0 "Without X, Y will fail" 和 Logto「在完成该配置前，用户将无法…」——讲后果；
  - Authing「设置之后不能修改」——提示不可逆。
- 风格指南可以引以为戒的写法：
  - 机翻腔、你 / 您混用（Logto、Zitadel）；
  - 营销腔的长段引言（Authing 登录控制页）；
  - 俏皮话式警告，例如「我当然希望你知道你在做什么。」（Zitadel）。

## 2. 顶层导航对照表（映射到本项目五组）

表头是本项目的五组。单元格里写的是该平台对应内容所在的**一级入口**，用 `→` 表示下钻。

| 本项目分组 | Logto | Auth0（经典导航） | Authing | Clerk | Zitadel |
|---|---|---|---|---|---|
| **概览** | 概览组：「开始上手」「仪表盘」 | Activity（统计）；新导航有 Home "Dashboard landing for getting started" | 概览（应用数、用户数、登录与新增统计） | Overview（用户增长分析） | 首页「开始使用 Zitadel」+ 顶栏入职清单 |
| **身份**（用户） | 用户组：「用户管理」「组织」 | User Management → Users | 用户管理（用户、用户组、组织机构） | Users（顶部入口） | 「用户」顶部菜单；「角色分配」顶部菜单 |
| **接入 · Application** | 身份验证组 →「全部应用」（Tab：我的应用 / 第三方应用） | Applications → Applications | 应用 → 自建应用 | 无独立对象：Application 就是整个项目；Native applications、OAuth applications、M2M 各有一页 | 项目 → 应用 |
| **接入 · API / Permission / Role** | 授权组 →「API 资源」「角色」 | Applications → APIs；User Management → Roles | 应用详情 →「访问授权」；全局另有「权限管理」 | 无 API；Organizations 设置 → Roles & Permissions | 「API」是应用的一种类型；角色在项目页内 |
| **安全 · 登录方式** | 身份验证组 →「登录与账户」 | Authentication → Database / Social / Enterprise / Passwordless | 应用详情 →「登录控制」；身份源在「身份源管理」 | User & authentication、SSO connections | 设置 →「登录行为和安全」「身份提供者」 |
| **安全 · 通道** | 身份验证组 →「连接器」（Tab：短信和邮件连接器 / 社交连接器） | Branding → Email Provider / Phone Provider | 设置 → 消息服务（文档另有放在「品牌化」下的说法，**未验证**） | Emails、SMS（Clerk 自己负责投递） | 默认设置 → 通知组：「SMTP 提供商」「短信/电话提供商」 |
| **安全 · 策略** | 身份验证组 →「多因素认证」「安全」（Tab：验证码 / 密码策略 / 阻止列表 / 常规） | Security → Attack Protection / Multi-factor Auth | 安全设置（通用安全、密码安全、MFA）；应用级「安全管理」 | Protect → Rules；Blocklist；Access mode；Multi-factor | 「登录行为和安全」「密码复杂性」「密码过期」「安全锁策略」 |
| **安全 · 签名密钥** | 租户组 →「租户设置」→ Tab「OIDC 配置」→「签名密钥」卡片 | Settings → Signing Keys | 设置 → 基础设置 → 密钥管理 | API keys 页提供 JWKS Public Key | 默认设置 →「OIDC Web Keys」 |
| **接入 · Webhook** | 开发者组 →「Webhooks」 | Actions；Monitoring → Streams | 自动化 → Webhooks | Webhooks | 默认设置 → Actions / Targets |
| **审计** | 开发者组 →「审计日志」 | Monitoring → Logs / Streams | 审计日志（管理员日志 / 用户日志） | Logs、Email logs、SMS logs | 默认设置 → 贮存组「活动」「失败事件」 |

补充说明：

- **作用域层级**：
  - Zitadel 是 Instance → Organization → Project → Application；
  - Clerk 是 Workspace → Application → Instance（dev / prod）；
  - Logto、Auth0 是租户；
  - Authing 是用户池。
- 本项目是单实例、单用户池，不需要层级切换器。【推断】这样做的好处是导航可以比这五家都平。
- **Auth0 的新导航**（Early Access）分组原文见附录 B，其中把 "Messaging"（Emails / Phone）单列成了一组。
- **Clerk 的安全页** 从 "Restrictions / Attack protection" 改成了 **Protect › Rules**：每一行显示 Status（Enabled / Disabled）和 Enable / Manage 按钮，点开后弹窗配置。

## 3. 创建 Application 流程

| | 入口与第一步 | 类型选项（原文） | 创建时问什么 | 推迟到创建后的内容 |
|---|---|---|---|---|
| **Logto** | 「创建应用」→ 全屏「从 SDK 和指南开始」→ 选框架，或点「跳过教程直接创建应用」 | 跳过教程时出现「选择应用类型」，四张卡片：原生应用 / 单页应用 / 传统网页应用 / 机器对机器 | 「应用名称」（必填）、「应用描述」（选填）；仅原生应用多问一项「授权流程」 | 选了框架：跳到教程页，在 "Configure redirect URIs" 这一步填回调地址。跳过教程：直接进详情页。M2M：创建后立刻弹出角色分配，可跳过 |
| **Auth0** | "Create Application" → "Create it manually" / "Import from URL" | Native / Single-Page Web / Regular Web / Machine-to-Machine | 名称 + 类型；M2M 还要选 API 和 Permissions，然后点 "Authorize" | 进入 Quick Start（选技术栈看教程）；回调 URL 等在 Settings 标签页的 "Application URIs" 里填 |
| **Authing** | 应用 → 自建应用 →「创建自建应用」弹窗 | 标准 Web 应用 / 单页 Web 应用 / 客户端应用 / 后端应用 | 应用名称、认证地址（二级域名）、选择类型 | 「应用配置」里的登录回调 URL、登出回调 URL；协议默认是 OIDC 授权码；有「体验登录」按钮 |
| **Clerk** | Create application → "interactive authentication setup form" | 没有类型概念 | 应用名称 + 勾选登录方式（email / phone / username / social） | 生产实例要另建（可以 clone 开发配置，但 SSO、Integrations、Paths 不复制）；代码接入看 quickstart |
| **Zitadel** | (A) 首页里程碑 → 选项目 → 选框架 → integrate 页；(B) 通用向导（mat-stepper） | Web / Native / User Agent / API / SAML，各配一句说明 | (A) 名称 + 重定向地址，默认开启开发模式；(B) 名称和类型 → 认证方式（PKCE / Code / JWT / Basic…）→ 重定向 URIs → 概览确认 | Token 选项、其他来源、Back-Channel Logout、App Links 等，只在详情页出现；创建后提示「要配置角色、角色分配等设置，请导航至项目页面。」 |

**各家的类型卡片文案**（说明 + 举例）：

- Logto（[`ZH/applications.ts`](https://github.com/logto-io/logto/blob/c814034401b0e13a6f461e0b0835ad3bbb84c9c2/packages/phrases/src/locales/zh-cn/translation/admin-console/applications.ts)）：
  - 「原生应用」—「在原生环境中运行的应用程序」—「例如 iOS 应用程序、Android 应用程序、桌面应用程序、电视、CLI」
  - 「单页应用」—「在浏览器中运行并动态更新数据的应用程序」—「例如 React DOM 应用程序，Vue 应用程序」
  - 「传统网页应用」—「仅由 Web 服务器渲染和更新的应用程序」—「例如 Next.js, PHP」
  - 「机器对机器」—「直接与资源对话的应用程序（通常是服务）」—「例如后端服务」
- Auth0（[create-applications](https://auth0.com/docs/get-started/auth0-overview/create-applications)）：
  - "**Native Applications**: These applications include mobile, desktop, or hybrid apps"
  - "**Machine-to-Machine Applications**: These applications include non-interactive applications, such as command-line tools, daemons, IoT devices"
- Zitadel（`APP.*`，[zh.json](https://github.com/zitadel/zitadel/blob/8a54a2a0c611b244a282bab70060e6e9bc7cfce3/console/src/assets/i18n/zh.json)）：
  - Web：「常规 Web 应用程序，如：.net，PHP，Node.js，Java 等。」
  - Native：「移动端应用, 桌面应用, 智能终端设备等」
  - User Agent：「单页应用程序 (SPA) 以及通常在浏览器中执行的所有 JS 框架」
  - API：「通用的 APIs 服务」

【推断】本项目的 Application 类型（App、小程序、Web）与这四类并不一一对应。小程序是国内特有的类型，五家都没有，所以卡片文案需要自己写。不过"一句说明 + 例如…"的结构可以直接沿用。

## 4. 技术字段的命名与解释

| 概念 | Logto（zh） | Auth0 | Authing | Zitadel（zh） | Clerk |
|---|---|---|---|---|---|
| client_id | 列表列名「App ID」，详情页「应用 ID」：「应用的唯一标识，通常由 Logto 生成。等价于 OpenID Connect 中的 client_id。」 | Client ID："The unique identifier for your application. You will use this when configuring authentication with Auth0. Generated by the system … and cannot be modified." | 「应用 ID（App ID）：应用的唯一标志。」 | 「客户端 ID」 | Publishable Key："… prefixed with `pk_test_` … `pk_live_`" |
| 密钥 | 「应用密钥」（可以有多把，可设「到期」）；空状态「该应用没有任何密钥。」 | Client Secret："… While the Client ID is considered public information, the Client Secret **must be kept confidential**. …" | 「应用密钥（App Secret）：用于验证客户端请求的合法性。」 | 创建后只显示一次：「将您的客户保密在一个安全的地方，因为一旦对话框关闭，便无法再次查看。」（「客户保密」是误译） | Secret Key："**Do not expose this on the frontend with a public environment variable**." |
| 回调地址 | 「重定向 URIs」：「在用户登录完成（不论成功与否）后重定向的目标 URI。」 | Allowed Callback URLs："Set of URLs to which Auth0 is allowed to redirect users after they authenticate. … For production environments, verify that the URLs do not point to localhost." | 「登录回调 URL」：「…用户在此应用登录之后，浏览器将会跳转到这个地址，你可以在这里换取用户信息。示例：…」 | 「重定向 URLs」：「指定登录将重定向到的 URL。」，按类型给出规则 | Native applications 页的 "Allowlist for mobile SSO redirect" |
| 退出后跳转 | 「退出登录后重定向 URIs」：「…（可选）。在某些应用类型中可能无实质作用。」 | Allowed Logout URLs："… The URL that you use in `returnTo` must be listed here." | 「登出回调 URL」 | 「退出登录重定向 URLs」 | — |
| CORS | 「所有重定向 URI 的来源将默认被允许。通常不需要对此字段进行操作。」 | Allowed Web Origins / Allowed Origins (CORS) | 安全域（Allowed Origins） | 「其他来源」 | Domains → Allowed subdomains |
| API 标识 / audience | 「API 标识符」：「…它必须是一个绝对URI并没有 fragment(#) 组件。等价于 OAuth 2.0 中的资源参数。」 | Identifier："… Auth0 recommends using a URL. … Auth0 will not call your API. This value cannot be modified afterwards." | 无 audience 字段；资源只有「资源名称」「操作类型」 | 无 audience 字段（**未验证**）；用「项目ID」 | — |
| 默认 API | 「每个租户只能设置零个或一个默认 API。当指定默认 API 时，可以在认证请求中省略资源参数。…」 | Default Audience："… all access tokens issued by Auth0 will specify this API identifier as an audience."，并附 breaking change 警告 | — | — | — |
| 签名密钥 | 「签名密钥」卡片：「安全管理应用程序使用的签名密钥。」；状态「待切换 / 当前 / 旧密钥」 | Signing Keys："Currently used / Previously used / Next in queue"；"Always test signing key rotation on a development tenant …" | 「当前密钥」「下一个密钥」，按钮「轮换并撤销当前密钥」 | 「…Zitadel 默认使用 RSA2048 密钥和 SHA256 哈希算法。」+ JWKS 缓存 5 分钟的提醒 | "JWKS Public Key" |
| Webhook 签名 | 「签名密钥」：「将由 Logto 提供的密钥作为请求标头添加到您的端点中，以确保 Webhook 负载的真实性。」 | — | 「请求密钥」：「…Authing 将在每个请求中（HTTP Header：X-Authing-Token）附带此密钥…」 | — | "Signing Secret"（由 Svix 签发） |

可以看出的规律：

- 英文原名保留的方式：Logto 用"中文名 + 等价于 client_id"；Authing 用"中文名（英文名）"。
- 说明的第一句讲"它是什么"，第二句讲"由谁生成、能不能改"，或者"通常不需要动"。
- 只有 Auth0 会写生产环境的提醒，例如"不要用 localhost"。
- 只有 Logto 会写"可以留空"的提示，例如「通常不需要对此字段进行操作」。

## 5. 配置之间的依赖提示

| 平台 | 依赖关系 | 呈现方式 | 原文 |
|---|---|---|---|
| Logto | 登录方式依赖短信 / 邮件 / 社交连接器 | 内联警告（`InlineNotification`）+「立即设置」链接，**不禁用** | 「尚未设置 SMS 短信连接器。在完成该配置前，用户将无法通过此登录方式登录。立即设置连接器。」 |
| Logto | 短信 MFA 依赖短信连接器 | 内联提示 + **保存时用 toast 拦截** | 「无法在没有短信连接器的情况下启用短信验证码 MFA。请先配置短信连接器。」 |
| Logto | MFA 与主登录方式互斥 | 开关**禁用** + tooltip | 「邮件验证码已经是你的主要登录方式。为了确保安全性，不能再次用于 MFA。」 |
| Logto | 配了连接器但没在登录体验里启用（反向提示） | 页内提示 | 「你已经配置了社交连接器，记得在登录体验上添加使之生效。」 |
| Logto | 验证码依赖 provider | 开关禁用，没有原因说明 | 「选择一个验证码提供商并设置集成。」 |
| Zitadel | ID Token 角色依赖项目设置 | 只写在字段说明里（仅英文版有，且引用了旧名称） | "Ensure to enable the Project setting 'Assign user roles during authentication' …" |
| Zitadel | 通知依赖 SMTP | 侧栏 `showWarn` 警告图标机制存在，但**被注释掉**；`REQUIREDWARN` 文案存在，但未使用 | 「要从您的域发送通知，您必须输入您的 SMTP 数据。」 |
| Zitadel | 应用配置不合规 | 后端检查，详情页顶部红框「OIDC 兼容性」 | 「必须至少注册一个重定向 URL。」 |
| Auth0 | 应用需要启用 connection；SMS 需要 Phone Provider；M2M 需要授权 API | 只见于文档的 Next steps，界面形态**未验证** | "Without an enabled connection, users cannot authenticate." |
| Clerk | 付费功能；生产实例需要 DNS；生产环境的 SSO 需要自有凭证 | 首页列出剩余步骤；其余为文档 callout，界面形态**未验证** | "The homepage of the dashboard will show you what is still required to deploy your production instance." |
| Authing | 身份源要先创建，才能在应用里选；某些标签页要先在「高级配置」里打开开关 | 文档文字，界面形态**未验证** | 「你需要先创建待使用的社会化身份源，才可在 自建应用->登录控制 标签页选择已创建的身份源。」 |

【推断】本项目最典型的依赖是"启用短信登录 → 需要短信通道"，以及"启用邮件验证码 → 需要邮件通道"，正好对应 Logto 的第一种模式。Logto 在这里不禁用开关，理由是让管理员能先排好登录方式、再补通道。代价是可能出现"已启用但不可用"的状态，所以警告必须说出后果：「用户将无法…」。

## 6. 快速开始清单与空状态

- **Zitadel**（[`modules/onboarding`](https://github.com/zitadel/zitadel/tree/8a54a2a0c611b244a282bab70060e6e9bc7cfce3/console/src/app/modules/onboarding)、`utils/onboarding.ts`）：顶栏进度条，点开是卡片「让你的Zitadel运转起来」——「这份清单有助于设置你的实例，并指导你完成最重要的步骤」，可以「隐藏」。三个里程碑：
  1. 「创建你的第一个项目」——「添加项目并定义角色及角色分配。」
  2. 「注册你的应用程序」——「创建一个web、native、api或saml应用程序并设置你的认证流程。」
  3. 「登录你的应用程序」——「将你的应用程序与 Zitadel 集成以进行身份验证，并通过使用管理员用户登录来测试它。」
  - 另外「添加用户」「授予用户」「设置你的品牌」「SMTP设置」四项在代码中被注释掉了。
- **Logto**（[`ZH/get-started.ts`](https://github.com/logto-io/logto/blob/c814034401b0e13a6f461e0b0835ad3bbb84c9c2/packages/phrases/src/locales/zh-cn/translation/admin-console/get-started.ts)）：「开始上手」页由卡片组成，不跟踪完成状态。
  - 标题「成功开发身份方案，我们先来探索一番」。
  - 卡片「开发：花 5 分钟集成你的应用」「自定义：提供出色的登录体验」。
- **Clerk**：首页列出生产部署还差的步骤，完成后出现 **Deploy certificates** 按钮（[production](https://clerk.com/docs/guides/development/deployment/production)）。2025-05 起 Overview 改成了用户增长分析页（[changelog](https://clerk.com/changelog/2025-05-28-redesigned-dashboard-overview)）。
- **Auth0**：新导航的 Home 写的是 "Dashboard landing for getting started"，清单内容**未验证**。
- **Authing**：应用详情里有「快速开始」标签页，讲 SDK 用法。新用户注册后会被引导创建用户池。概览页有没有清单：**未验证**。

空状态：

- **Logto**：
  - 没有任何应用时，用「选择一个框架或教程」的内嵌教程库代替空表格。
  - Webhook 为空时：「创建一个Webhook以通过POST请求将实时更新发送到您的端点URL。了解并立即采取有关"创建账户"、"登录"和"重置密码"等事件的操作。」+ 按钮「创建 Webhook」。
  - 第三方应用为空时：用途说明 +「了解更多」+「创建第三方应用」。
  - 通用表格兜底：「没有数据」。
- **Zitadel**：只有一句短句，例如「尚未创建任何角色。」「没有可用的 SMTP 提供商」「没有条目」。
- **Authing**：只找到一条：「刚创建好的 Hook 请求事件都为空，这时你可以点击「调试」触发一个「测试事件」」。
- Auth0、Clerk 的空状态：**未验证**。

【推断】Zitadel 的清单只有 3 项，入口在顶栏，可以隐藏，和本项目"配通道 → 建 Application → 建 API"的设想最接近。以前不做清单的顾虑是它变成"配置健康清单"。可以这样规避：只列首次上手的 3 步，全部完成后自动消失，不做持续体检。空状态值得学 Logto：一句话说明这个列表里的东西有什么用，再放一个主按钮。

## 7. 说明文字的语气与长度

| 平台 | 长度 | 人称与语气 | 典型句 |
|---|---|---|---|
| Logto | 1 句，长的 2–3 句；末尾常带「了解更多」链接 | "你 / 您"混用；直接对照 OIDC 术语；有机翻痕迹 | 「在用户退出登录后重定向的目标 URI（可选）。在某些应用类型中可能无实质作用。」 |
| Auth0 | 1–3 句；涉及安全时再加 callout | "you"；参考页先下定义、再讲约束，quickstart 讲后果 | "Allowed Web Origins is critical for silent authentication. Without it, users will be logged out when they refresh the page or return to your app later." |
| Authing | 字段说明 1–2 句；引言段落偏长 | "你"为主；常带示例值和推荐值；风险用「注意」「请谨慎选择」 | 「**自定义过期时间**：可在右侧输入框指定过期时间，建议 1209600 秒（14 天），过期后用户需要重新登录。」 |
| Clerk | 1–2 句 | "you"；字段名加粗，与界面标签一致；默认值和最小值直接写出 | "The **Maximum attempt limit** setting controls the number of failed sign-in attempts before a user is locked out. … The minimum is 5." |
| Zitadel | 页面说明 1–4 句，字段说明 1 句 | 直接，偶尔口语化或俏皮；中文为直译 | 「配置您的OIDC令牌寿命。使用更短的寿命来增加用户的安全性，使用更长的寿命来增加用户的便利性。」 |

【推断】对照 #40 列出的四类问题：

1. "分号连接的规格式短句"：五家都没有这种写法，都是完整句子，常用"…，…"或两句话。
2. "直接暴露字段格式"：Zitadel 的做法是按类型写规则，例如「重定向 URI 必须以 https:// 开头。 http:// 仅对启用的开发模式有效。」——先说规则，再说例外。
3. "中英混排标题"：Logto 和 Zitadel 的中文界面里，标题都是中文，英文缩写（URI、ID、MFA）只在必要时出现。
4. "只说是什么、不说为什么"：Zitadel 的 OIDC 令牌寿命说明（在安全和便利之间取舍）、Clerk 的 SMS 国家白名单说明（"avoiding extraneous SMS fees"）是"为什么要配"的好例子。

## 附录 A：Logto 原文摘录

来源前缀：
- `ZH/` = [`packages/phrases/src/locales/zh-cn/translation/admin-console/`](https://github.com/logto-io/logto/tree/c814034401b0e13a6f461e0b0835ad3bbb84c9c2/packages/phrases/src/locales/zh-cn/translation/admin-console)
- `C/` = [`packages/console/src/`](https://github.com/logto-io/logto/tree/c814034401b0e13a6f461e0b0835ad3bbb84c9c2/packages/console/src)

- **侧栏**（`C/containers/ConsoleContent/Sidebar/hook.tsx`；`ZH/tab-sections.ts`、`ZH/tabs.ts`）：
  - 概览：开始上手、仪表盘
  - 身份验证：全部应用、登录与账户、多因素认证、连接器、企业SSO、安全
  - 授权：API 资源、角色、组织模板
  - 用户：组织、用户管理
  - 开发者：Actions（受功能开关控制）、自定义 JWT、Webhooks、审计日志
  - 租户：租户设置
- **创建应用**（`ZH/guide.ts`、`ZH/applications.ts`、`C/components/ApplicationCreation/CreateForm/index.tsx`）：
  - 教程库：「从 SDK 和指南开始」「使用我们提供的 SDK 和集成教程加速你的应用开发过程。」「如果你现在不需要教程，可以点击右侧按钮继续创建应用」→「跳过教程直接创建应用」
  - 弹窗副标题：「创建一个移动、单页、machine-to-machine 或传统 web 应用程序，并通过 Logto 进行身份验证」
  - 未选类型时的报错：「你还没有选择应用类型」
  - 原生应用的授权流程 tooltip：「选择应用的授权流程。一旦设置，将无法更改。」
  - 创建成功提示：「创建应用成功。」
  - 回调地址在教程的一步里填（`C/assets/docs/fragments/_redirect-uris-web.mdx`，仅英文）："Now, let's configure your redirect URI. E.g. http://localhost:3000/callback"
- **应用详情**（`ZH/application-details.ts`）：
  - 「端点和凭据」——「使用以下端点和凭据在应用程序中设置 OIDC 连接。」
  - 通配符警告：「通配符重定向 URI 不是标准 OIDC，可能会增加攻击面。请谨慎使用，尽可能使用精确的重定向 URI。」
  - 回调地址必填：「至少需要输入一个重定向 URI。」
  - 密钥到期选「永不」时：「该密钥永不过期。我们建议设置一个到期日期以增强安全性。」
  - 概念说明：「"应用"是注册的软件或服务，可以访问用户信息或代表用户执行操作。应用可以帮助 Logto 识别是谁在请求什么，并负责处理登录和授权。请填写认证所需的必填字段。」
- **签名密钥**（`ZH/signing-keys.ts`、`ZH/oidc-configs.ts`）：
  - 轮换说明：「此操作将创建一个新的私钥，轮换当前密钥，并删除之前的密钥。使用当前密钥签名的JWT令牌将在删除或另一轮轮换之前保持有效。」
  - 文档路径「控制台 > 租户设置 > OIDC 配置」（[docs](https://docs.logto.io/zh-CN/developers/signing-keys)）
- **Webhook**（`ZH/webhooks.ts`、`ZH/webhook-details.ts`）：
  - 「事件」字段：「选择触发事件，Logto 将发送 POST 请求。」
  - 「端点 URL」字段：「输入您的端点 URL，在事件发生时 Webhook 的数据将被发送到该 URL。」
  - 重新生成签名密钥的确认：「是否确定要修改签名密钥？重新生成后将立即生效。请在您的端点中同步修改签名密钥。」
  - 误译：`disable_reminder` 写的是「是否确定重新激活此 Webhook？重新激活后将不会向端点 URL 发送 HTTP 请求。」
- **依赖提示**：
  - 连接器缺失警告：`ZH/sign-in-exp/index.ts` 的 `setup_warning`，组件 `C/pages/SignInExperience/PageContent/SignUpAndSignIn/components/ConnectorSetupWarning/index.tsx`
  - MFA：`ZH/mfa.ts`、`C/pages/Mfa/MfaForm/index.tsx`
  - 反向提示：`ZH/connectors.ts` 的 `config_sie_notice`

## 附录 B：Auth0 原文摘录

- **经典导航**（[dashboard](https://auth0.com/docs/get-started/auth0-overview/dashboard)）：
  - 总述："It consists of several sections that you can navigate using the sidebar menu on your left."
  - Applications："Manage your applications, APIs, and single sign-on (SSO) integrations."
  - Security："Configure extra layers of security by enabling shields…"
  - Settings："…Manage other tenant settings related to your custom domains, signing keys, and other advanced settings."
- **新导航**，Early Access（[use-dashboard-navigation](https://auth0.com/docs/get-started/auth0-overview/dashboard/use-dashboard-navigation)）：
  - Primary：Home、Agents、Users、Organizations、Settings
  - Integration：Applications、APIs、Authentication、Connections、Enterprise SSO、Authorization
  - Customization：Branding、Pages、Portals、Domains
  - Messaging："Emails: Email templates and configuration"、"Phone: Phone messaging settings"
  - Automation & Extensibility：Actions、Events、Extensions、Rules、Hooks
  - Security & Monitoring：Attack Protection、Access Control、Security Dashboard、Logs、Analytics
- **各功能的路径**：
  - "Dashboard > Applications > APIs"（[set-up-apis](https://auth0.com/docs/get-started/auth0-overview/set-up-apis)）
  - "navigate to Branding > Phone Provider"（[sms-otp](https://auth0.com/docs/authenticate/passwordless/authentication-methods/sms-otp)）
  - "Dashboard > Settings > Signing Keys"（[rotate-signing-keys](https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys)）
- **创建应用之后**：
  - "When you click **Create** you will be navigated to the Quick Start view. Here you can pick the technology you plan on using to build your app and the relevant how-to quickstart will be displayed."（[part-2](https://auth0.com/docs/get-started/architecture-scenarios/sso-for-regular-web-apps/part-2)）
  - SPA 详情页的标签页：Quick Start / Settings / Credentials / Add-ons / Connections / Organizations / Login Experience（[single-page-web-apps](https://auth0.com/docs/get-started/auth0-overview/create-applications/single-page-web-apps)）
- **M2M**（[machine-to-machine-apps](https://auth0.com/docs/get-started/auth0-overview/create-applications/machine-to-machine-apps)）：
  - "Select the API you want to be able to call from your application."
  - "Select the **Permissions** that you want to be issued as part of your application's access token, and click **Authorize**."
- **字段说明**（[application-settings](https://auth0.com/docs/get-started/applications/application-settings)）：
  - 通配符和 localhost 的 callout："Do not use wildcard placeholders or localhost URLs in your application callbacks or allowed origins fields. Using redirect URLs with wildcard placeholders can make your application vulnerable to attacks."
- **API 字段**（[set-up-apis](https://auth0.com/docs/get-started/auth0-overview/set-up-apis)）：
  - Name："A friendly name for the API. Does not affect any functionality."
- **后果导向的写法**（[React quickstart](https://auth0.com/docs/quickstart/spa/react)）：
  - "Allowed Callback URLs are a critical security measure … Without a matching URL, the login process will fail."
- **连接的默认行为**（[update-application-connections](https://auth0.com/docs/get-started/applications/update-application-connections)）：
  - "When enabled, all current connections will be enabled for any new application that is created."
  - 建议关闭："Disable this setting so you can explicitly enable the connections appropriate for each application."

## 附录 C：Authing 原文摘录

- **导航**（[控制台概览](https://docs.authing.cn/v2/guides/basics/console/)）：
  - 原文写"以下会按照控制台左侧导航菜单 从上往下 介绍控制台每个模块"。
  - 模块依次为：概览、应用、身份源管理、用户管理、权限管理、安全设置、品牌化、自动化、审计日志、设置。
- **自建应用详情的标签页**：快速开始、应用配置、协议配置、登录控制、访问授权、品牌化、安全管理、高级配置、租户配置（例：[app-configuration](https://docs.authing.cn/v2/guides/app-new/create-app/app-configuration.html)）。
- **创建应用**（[create-app](https://docs.authing.cn/v2/guides/app-new/create-app/create-app.html)）：
  - 「点击页面右上角 **创建自建应用** 按钮。在弹出窗口填写如下信息：**应用名称**：指定应用名。**认证地址**：输入二级域名，必须为合法的域名格式（只允许包含英文、数字和 '-'，例如 my-awesome-app）。**选择类型**：按照你的业务应用的实际类型对应选择在 Authing 的应用类型。」
- **字段说明**：
  - 「登录回调 URL」：「此链接需要填写你的业务回调地址，用户在此应用登录之后，浏览器将会跳转到这个地址，你可以在这里换取用户信息。示例： https://myawesomeapp.com/login/callback 。」（app-configuration）
  - 「发起登录 URL」：「在 Authing 应用详情点击 **体验登录** 或在应用面板点击该应用图标时，会跳转到此 URL，默认为本应用的登录页。」（app-configuration）
  - 登出回调的后果：「你必须配置此回调链接，否则用户将无法退出，而会显示 misconfiguration 错误提示。」（[regular web app](https://docs.authing.cn/v2/guides/basics/platform-guide/integrate-with-regular-web-app.html)）
  - 「用户池密钥」：「**当前密钥**：是提供给客户线上使用请求的密钥。**下一个密钥**：是提供给客户准备更换密钥时提前自动创建的备用密钥。」（[basic-config](https://docs.authing.cn/v2/guides/userpool-config/basic-config.html)）
- **依赖与继承**：
  - 「打开本模块中的开关后，应用的相关配置首先将继承全局配置。在此基础上进行改动，不用担心给用户带来突兀的登录体验。」（[advanced-settings](https://docs.authing.cn/v2/guides/app-new/create-app/advanced-settings.html)）
  - 「应用中 安全管理 选项卡默认是关闭的…可以在 **高级配置->自定义配置** 中开启 **自定义本应用的安全规则** 开关」（security-management）
- **语气示例**（[social/github](https://docs.authing.cn/v2/guides/connections/social/github/)）：
  - 「**显示名称**：这个名称会显示在终端用户的登录界面的按钮上。」
  - 「**登录模式**：开启「仅登录模式」后，只能登录既有账号，不能创建新账号，请谨慎选择。」
  - 反例（营销腔，[login-control](https://docs.authing.cn/v2/guides/app-new/create-app/login-control.html)）：「登录体验是软件开发者需要考虑的最重要的用户体验之一，为用户提供一个无缝、便捷而又安全的认证体验不是一件很容易的事。」
- **未验证**：
  - 当前控制台的菜单名是否仍与 v2 文档一致，例如「身份源管理」和「认证配置」是哪个、「消息服务」放在哪里；
  - 是否有 M2M 类型；
  - 依赖提示在界面上的形态；
  - 概览页的清单。
  - 文档里的截图都没有 alt 文本，无法用来核对。

## 附录 D：Clerk 原文摘录

- **路由清单**（[llms.txt](https://dashboard.clerk.com/llms.txt)）：
  - `/~/` 的含义："Paths under /~/ resolve to the caller's last-active application and instance"
  - API keys 页："Access publishable and secret keys for Clerk SDK integration."
  - Sessions 页："Configure session lifetime, inactivity timeout, and single or multi-session mode."
  - Invitations 页："Only available when sign-ups are restricted."
- **顶栏**（[overview](https://clerk.com/docs/guides/dashboard/overview)）："The application dropdown: Allows you to choose which application you want to manage or create a new one. The instance dropdown: Allows you to switch between your development and production instances."
- **创建应用**（[setup-clerk](https://clerk.com/docs/getting-started/quickstart/setup-clerk)）：
  - "you will be asked to build your authentication flow … You can choose authentication options like email, phone, username, or social authentication providers."
  - 是否有实时预览：**未验证**。2022 年有 changelog 提到创建后可以预览组件（[2022-04-01](https://clerk.com/changelog/2022-04-01)）。
- **安全页**（[bot-protection](https://clerk.com/docs/guides/secure/bot-protection)）："navigate to the **Rules** page under **Protect**."
- **访问模式**（[restricting-access](https://clerk.com/docs/guides/secure/restricting-access)）：
  - 界面标签与 API 值的对应："`sign_up_mode` keeps the values `public`, `restricted`, and `waitlist`, which the Dashboard labels **Open**, **Invite-only**, and **Waitlist**."
  - 风险提示："Enabling the Allowlist without adding any identifier exceptions blocks _all_ sign-ups."
- **付费功能的统一提示句**："This feature requires a paid plan for production use, but all features are free to use in development mode so that you can try out what works for you."
- **SMS 国家白名单**：
  - 默认值："**By default, only the US and Canada are enabled.**"
  - 为什么要配："This can be useful for avoiding extraneous SMS fees from countries from which your app is not expected to attract traffic."（[sign-up-sign-in-options](https://clerk.com/docs/guides/configure/auth-strategies/sign-up-sign-in-options)）
- **邮件模板**（[email-sms-templates](https://clerk.com/docs/guides/customizing-clerk/email-sms-templates)）："**Delivered by Clerk**: Clerk will deliver your emails using its own email service provider (ESP). However, if you wish to handle delivery of emails on your own, then you can toggle this setting off."
- **未验证**：
  - 当前侧栏除 "Protect" 以外的分组名；
  - 空状态文案；
  - 依赖提示在界面上的形态。

## 附录 E：Zitadel 原文摘录

来源：[`console/src/assets/i18n/zh.json`](https://github.com/zitadel/zitadel/blob/8a54a2a0c611b244a282bab70060e6e9bc7cfce3/console/src/assets/i18n/zh.json)，以及 `console/src/app/` 下的组件。

- **层级说明**：
  - 组织（`DESCRIPTIONS.ORG.DESCRIPTION`）：「一个组织托管用户、带有应用的项目、身份提供者和设置，如公司品牌。」
  - 实例（`DESCRIPTIONS.SETTINGS.INSTANCE.DESCRIPTION`）：「所有组织的默认设置。有了正确的权限，其中一些权限在组织设置中是可以覆盖的。」
- **导航**：
  - 组织级顶部菜单（`modules/nav/nav.component.html`）：首页 / 组织 / 项目 / 用户 / 角色分配 / 认证流程 / 设置。
  - 实例默认设置的侧栏（`pages/instance/instance.component.ts`）分组：通用 / 通知 / 登录和访问 / 外观 / 贮存 / Actions / 其他。
- **通用向导**（`pages/projects/apps/app-create/`）：
  - 页头：「逐步输入您的应用详情」「将自动生成推荐的配置。」
  - 第一步：「先录入一个名字。」「您要创建什么类型的应用程序？」
  - 最后一步：「你现在完成了。检查您的配置。」
  - 跳过向导的开关："I'm a pro. Skip this wizard."（zh 的 key 放错了层级，推断 zh 界面在这里会回退成英文，**未验证**）
- **认证方式的说明**（`APP.AUTHMETHODS.*`）：
  - PKCE「使用随机哈希而不是静态客户端密码以提高安全性」
  - POST「发送 client_id 和 client_secret 作为表单的一部分」
  - Device Code「在计算机或智能手机上授权设备。」
- **快速开始**（`QUICKSTART.*`）：
  - 「默认情况下启用开发模式。您可以稍后更新生产值。」
  - 「我们为 {{value}} 应用程序创建了一个基本配置。创建后，您可以根据自己的需要调整该配置。」
- **字段说明**：
  - 开发模式：「注意：启用开发模式的重定向 URI 将不会被验证。」
  - 不安全的重定向地址：「我当然希望你知道你在做什么。」
  - Native 的重定向规则：「重定向 URI 必须以您自己的协议、http://127.0.0.1、http://[::1] 或 http://localhost 开头。」
  - 「其他来源」：「如果您想向您的应用程序添加不用作重定向的其他来源，您可以在此处执行此操作。」
  - 无密钥时：「使用您选择的身份验证流程，不需要任何秘密，因此不可用。」
- **页面说明**：
  - Web Keys：「管理您的 OIDC Web 密钥，以安全地签署和验证您的 Zitadel 实例的令牌。」
  - 事件：「此页面显示您实例中的所有状态更改，直到您实例的审计跟踪限制为止。…」
  - 失败事件：「此页面显示您实例中的所有失败事件。如果Zitadel的行为不符合您的预期，请始终首先检查此列表。」
- **语气示例**：
  - 安全设置：「启用可能会影响安全性的Zitadel功能。在更改这些设置之前，您确实需要知道自己在做什么。」
  - 允许本地身份验证：「允许您的用户使用其用户名和密码或通行密钥身份验证登录。如果停用此选项，您的用户只能使用外部身份提供商登录。」
- **译文问题**：
  - 「客户保密」：误译，应为「客户端密钥」；
  - "Secret Generator" 被译成「验证码外观」；
  - `APP.OIDC.WELLKNOWN` 的 zh 写成 `{url}}`，插值语法坏了；
  - `IDTOKENROLEASSERTION_DESCRIPTION` 的 zh 缺了依赖提示那一句。

## 未验证汇总

- Auth0：
  - Home / Getting Started 页的清单内容；
  - 新导航下 MFA、Signing Keys 的位置；
  - Rotate Key 确认弹窗的原话；
  - 空状态。
- Clerk：
  - 除 Protect 外的侧栏分组名；
  - 创建表单里是否有实时预览；
  - 空状态；
  - 付费和依赖提示的界面形态。
- Authing：
  - 当前菜单名是否仍与 v2 文档一致；
  - 「消息服务」的实际位置；
  - 是否有 M2M 类型；
  - 概览页的清单与空状态。
- Logto：
  - 「开始上手」页的「安全」「管理」两张卡片在 OSS 版是否渲染；
  - 审计日志、用户、角色等页面的空状态。
- Zitadel：
  - zh 缺 key 时回退成英文：由代码推断，没在运行实例里验证；
  - `REQUIREDWARN` 未被使用：依据 GitHub 代码搜索的索引，可能有滞后。
