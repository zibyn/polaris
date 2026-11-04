# 托管页的多语言与品牌定制：Auth0 / Logto / Keycloak / Zitadel / 国内同类对照

- 调研日期：2026-11-04
- 问题：托管页（`internal/login/pages.html`，服务端渲染的 Go `html/template`，目前只有中文、品牌固定）要加入**中英双语**与**品牌**（品牌名、Logo、主色），也可能支持「完整定制登录页」。主流平台的品牌配在哪一层、能改哪些项、「完整定制」分几档以及各档的安全措施和维护代价、语言怎么选、文案能否覆盖、邮件 / 短信要不要一起做多语言？
- 本项目现状：`GLOSSARY.md` 已定义 **品牌**（「托管页上代替 Polaris 标识的一组外观设置：品牌名、Logo、主色。实例设一套默认，Application 可逐项覆盖」）；Application 已能通过直连认证 API 完全自绘登录 UI（ADR 0002、0010）；托管页目前只发 `Content-Security-Policy: frame-ancestors 'none'`（`internal/login/login.go`）；OIDC 层已解析 `ui_locales` 但托管页未使用。

## 0. 怎么读这份文档

- **第 1 节是结论**，直接回答五个问题；第 2–6 节逐项展开；第 7 节是对 Polaris 的启示；附录列出全部来源。
- 事实一律附一手来源（官方文档或源码），读取日期均为 2026-11-04。**我自己的判断标【推断】；没取到一手来源的标「未验证」**，没有用记忆补。
- 取证方式：
  - **开源产品读源码**：Keycloak `keycloak/keycloak@main`（`DefaultLocaleSelectorProvider.java`、`keycloak.v2/login/template.ftl`、`theme.properties`、`docs/documentation/server_admin/...adoc`）；Zitadel `zitadel/zitadel@main`（`apps/login/src/i18n/request.ts`、`apps/login/src/lib/i18n.ts`）；Casdoor `casdoor/casdoor@master`（`object/application.go`、`object/organization.go`、`web-old/src/Setting.js`、`web-old/src/auth/LoginPage.js`，读取时 HEAD 为 `42e1808`）。其余未 pin commit SHA，读的都是默认分支，发布版可能有出入。
  - **闭源产品与开源产品的官方文档**：Auth0、Logto、Zitadel、Keycloak。
- **局限**：
  - 部分英文引文经抓取摘要工具转述，与原文可能有个别字词出入。
  - **Authing 文档站本次无法抓取**（多次连接被断开），Authing 部分只有搜索引擎摘要，全部标「未验证」。国内同类改用 **Casdoor 源码**作为可靠参照。
  - Logto 的 Bring your UI 文档描述的是 Logto Cloud；开源自托管版是否同样支持，本次未核实。

## 1. 结论速览

### Q1　品牌配在哪一层？

**都是「实例 / 租户一套默认，下层可以覆盖」，但能覆盖到 Application 这一层的只有一半。**

| 平台 | 默认层 | 可覆盖层 | 是否能按 Application 覆盖 |
|---|---|---|---|
| Auth0 | 租户（Branding → Universal Login 的主题） | Organization（Logo、主色、页面背景色） | **无配置项**；只能在 Liquid 页面模板里读 `application.logo_url` / `application.name` 自己写分支（需自定义域名） |
| Logto | 「Omni」登录体验（租户） | Application、Organization | **能**：Logo、favicon、明暗两套颜色、自定义 CSS；优先级 Organization → App → Omni |
| Keycloak | Realm（Realm settings → Themes） | Client 只能**换整套登录主题** | 间接能：每个 Client 可指定不同 login theme |
| Zitadel | 实例 | Organization | **不能**；Project 上的「private labeling」只决定**用哪个组织**的品牌 |
| Casdoor（国内开源） | Organization | Application | **能**：Application 有自己的 Logo、标题、favicon、`themeData`，启用时优先于组织 |
| Authing | 用户池全局登录框 | 应用 | 未验证：搜索摘要称应用「品牌化」默认关闭，开启后单独配置 |

### Q2　能定制哪些项？Logo 上传还是填 URL？

- **Logo**：Logto、Zitadel 是**上传**；Auth0、Casdoor 是**填 URL**（Casdoor 字段为 `varchar(200)` 的 URL）。Keycloak 没有 Logo 配置项，要写主题（或用实验性的 Quick Theme 生成主题 JAR）。
- **明暗两套**：Logto（Logo、favicon、品牌色都可单设深色版本，并跟随系统）、Zitadel（明暗各一套 Logo 与颜色）、Casdoor（`logoDark`、`themeType: dark`）。Auth0 主题编辑器文档未提深色模式。
- **主色**：Auth0 是一整套逐元素颜色（主按钮填充、链接、输入框、错误色……）；Logto、Casdoor 只有**一个品牌色**，色阶由组件库推导；Zitadel 是四色（背景、主色、警告、字体）；Keycloak Quick Theme 映射到 PatternFly 全局 CSS 变量。**没有一家文档说明从主色推导色阶的算法**。
- **favicon**：Logto、Casdoor 有；Zitadel 文档未提（API 有 icon 上传，未验证）；Auth0 主题编辑器文档未提。
- **背景**：Auth0（背景图 URL、页面背景色）、Zitadel（背景色）、Casdoor（`formBackgroundUrl`，另有移动端版本）。Logto 文档未提。
- **页面标题 / 品牌名**：Logto 明确**取消了自定义标题**，改用各流程固定的浏览器标题；Keycloak 用 realm 的 `displayName` / `displayNameHtml`；Casdoor 每个 Application 有 `title`；Auth0 模板里可读 `tenant.friendly_name`。
- **字体**：Auth0（WOFF URL）、Zitadel（上传 TTF）可换。

### Q3　「完整定制」有哪几档？

| 档位 | 谁提供 | 是否允许 JS | 安全措施 | 维护代价 |
|---|---|---|---|---|
| ① 自定义 CSS | Logto（三层都可设）、Casdoor、Authing（未验证） | Logto **只接受 CSS**；Casdoor 会剥掉 `<style>` 标签后插入 | 不执行脚本 | 类名带 hash，**会随版本变**；Logto 建议用 `$=` 选择器 |
| ② 包一层 HTML 模板，保留核心表单插槽 | Auth0 Liquid 页面模板（必含 `auth0:head`、`auth0:widget`）+ Prompt Partials 插入点 | **允许**（Partials 支持 HTML/CSS/JS/Liquid） | 文档要求转义输出、`ext-` 参数视为不可信、不得插进 `<script>`；需自定义域名；模板 ≤100KB | Auth0 明说 CSS 类名每次构建都变、HTML 结构可能变 |
| ③ 整页替换主题 | Keycloak FreeMarker 主题；Casdoor `signinHtml` / `formSideHtml`；Auth0 Classic「Customize Login Page」 | Keycloak 主题可带 `scripts=`；Casdoor **主动重建 `<script>` 让它执行**；Auth0 Classic 允许 | Keycloak：「恶意模板能以 Keycloak 进程身份执行代码」，只装可信主题、限制 `themes/` 写权限；Casdoor 无防护 | Keycloak：升级时「可能被迫更新自定义模板」；Auth0 Classic 已不再更新，开启即自行维护 |
| ④ 完全自建 UI | Auth0 ACUL（自托管静态资源 + SDK）；Logto Bring your UI（上传 zip 由 Logto 托管 + Experience API）；Zitadel Login V2（fork 开源 TypeScript 登录应用自部署） | 是，本来就是自己的应用 | Auth0：SRI 校验资源；Logto：施加 CSP，只追加管理员登记的 `script-src` / `connect-src`；Zitadel：登录应用持有 `IAM_LOGIN_CLIENT` 服务账号令牌 | 全部由客户自建自维护；Zitadel 还会因登录 UI 坏掉而锁死管理端 |

### Q4　多语言怎么选？

| 平台 | 选择顺序（先到先得） | 兜底 |
|---|---|---|
| Auth0 | 租户启用语言是约束；`ui_locales` 第一个须是启用语言；`Accept-Language` | 租户默认语言（启用列表第一个）；文档未说二者冲突时谁优先 |
| Logto | `ui_locales`（第一个支持的标签）→ 自动检测（`Accept-Language`）→ 租户默认 | 租户默认 |
| Keycloak | 用户在页面切换器选的 → 用户资料里的 locale → 客户端传的（如 `ui_locales`）→ cookie → `Accept-Language` → realm 默认 | **英语** |
| Zitadel Login V2 | 实例默认 → 被 `Accept-Language` 首项覆盖 → 被 `NEXT_LOCALE` cookie 覆盖（cookie 值不被允许时回到默认） | 默认语言，再不行 `en` |

- **页面切换器**：Keycloak 有（启用国际化且支持语言多于一种时）；Authing 有「切换语言入口」开关（未验证）；Auth0、Logto 文档未提。
- **单条文案覆盖**：四家都支持，且**都按语言分别覆盖**（Auth0 按 prompt / screen / key / language；Logto `PUT /api/custom-phrases/{languageTag}`；Keycloak Realm settings → Localization；Zitadel 按屏幕与语言，Login V2 也按组织加载托管翻译）。
- **品牌名 / Application 名随语言变**：只有 **Keycloak** 明确支持——Client 名填 `${myapp}` 这类占位符，按消息包翻译。其他平台名字是单值，Auth0 用 `${clientName}` 把应用名插进各语言文案。

### Q5　文案覆盖、邮件 / 短信模板的多语言是否一起做？

- **邮件和登录页共用语言判定**的：Logto（同一套 `ui_locales` → `Accept-Language` → 默认；邮件模板按 `languageTag` 分存）、Keycloak（邮件是主题的一种，同一套消息包）、Zitadel（restrictions 同时约束登录页和通知）。
- **Auth0 是分开的**：每种邮件只有一个模板，多语言靠 Liquid 条件自己写（可用 `request_language`、`user_metadata`）。
- **短信**：国内短信内容由运营商报备的模板决定（见 `cn-channel-qualifications.md`），每种语言要单独报备模板，不在 Polaris 文案层控制之内【推断】。

## 2. 品牌所在的层级（Q1 展开）

**Auth0**
- 主题编辑器在 Dashboard > Branding > Universal Login > Update branding theme，Management API 端点是 "Update the current theme"、"Create a new branding theme"。文档没写主题的作用范围；从「current theme」的单数形态看是租户级【推断】。[customize-themes](https://auth0.com/docs/customize/login-pages/universal-login/customize-themes)
- Organization 可覆盖三项：Organization Logo（API `ORG_LOGO`，URL）、Primary Color、Page Background Color。[create-organizations](https://auth0.com/docs/manage-users/organizations/configure-organizations/create-organizations)
- 没有按 Application 的品牌配置项。页面模板暴露了 `application.id`、`application.name`、`application.logo_url`、`application.metadata`，以及 `organization.branding.*`，要按应用换 Logo 得自己在模板里写条件。[customize-templates](https://auth0.com/docs/customize/login-pages/universal-login/customize-templates)；Auth0 支持中心文章给出了「按 application 名切换 Logo」的 Liquid 写法（非文档站）：[Displaying Per-Application Logos](https://support.auth0.com/center/s/article/displaying-per-application-logos-on-auth0-universal-login)

**Logto**
- 原文："The full precedence order is: Organization-level branding -> App-level branding -> Omni sign-in experience"。App 级在应用详情页开启「App-level sign-in experience」，可覆盖 Logo、favicon、明暗颜色和自定义 CSS；Organization 级要在登录请求里带 `organization_id`。[match-your-brand](https://docs.logto.io/customization/match-your-brand)

**Keycloak**
- 主题按 realm 选，"with the exception of clients being able to override the login theme"，可用 Theme Selector SPI 改这个逻辑。[themes](https://www.keycloak.org/ui-customization/themes)；[server_admin themes.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/realms/themes.adoc)

**Zitadel**
- "The settings on the instance level will set the default settings, which are triggered for all users if not overwritten on an organization specifically." 文档未提按应用覆盖，Project 上的 private labeling 设置决定用哪个组织的品牌。[branding](https://zitadel.com/docs/guides/manage/customize/branding)
- private labeling 取值：强制使用项目所属组织的品牌；或先显示项目组织的品牌，识别出用户后切换到用户所属组织的品牌。[projects](https://zitadel.com/docs/guides/manage/console/projects)

**Casdoor**
- `Organization` 与 `Application` 两个结构体都有 `Logo`、`LogoDark`、`Favicon`、`ThemeData`；Application 另有 `Title`。[organization.go](https://github.com/casdoor/casdoor/blob/master/object/organization.go)、[application.go](https://github.com/casdoor/casdoor/blob/master/object/application.go)
- 前端取主题：`application.themeData.isEnabled` 时用应用的，否则组织的，否则系统默认。[Setting.js `getThemeData`](https://github.com/casdoor/casdoor/blob/master/web-old/src/Setting.js)
- 注意：Casdoor 是**整块 ThemeData 覆盖**，不是逐项覆盖。

**Authing（未验证）**
- 搜索摘要：应用的「品牌化」选项卡默认关闭，此时由全局登录框控制，开启「自定义应用登录框」后单独设置。[customize-guard](https://docs.authing.cn/v2/guides/app-new/create-app/customize-guard.html)、[tenant-branding](https://docs.authing.cn/v2/tenant-console/tenant-branding.html)（两页本次均未能直接抓取）

## 3. 可定制项（Q2 展开）

**Auth0 主题编辑器的五类设置**：[customize-themes](https://auth0.com/docs/customize/login-pages/universal-login/customize-themes)
- Color：主按钮填充与文字、次按钮边框与文字、链接、焦点与悬停色、标题、正文、组件背景与边框、输入框各部分、图标、错误、成功。
- Fonts：WOFF 文件 URL 加各级字号。
- Borders：按钮与输入框的边框粗细、形状（直角 / 圆角 / 胶囊）、圆角半径、阴影。
- Widget：Logo 位置（左 / 右 / 中 / 隐藏）、**Logo URL**（"Enter the URL location of your custom logo"，推荐 SVG）、Logo 高度、标题对齐、社交按钮布局。
- Page backgrounds：背景图 URL、组件对齐方式。
- 文档未提 favicon、深色模式、Logo 上传。

**Logto**：[match-your-brand](https://docs.logto.io/customization/match-your-brand)
- Logo：上传，≤500KB，SVG / PNG / JPG / JPEG / ICO；"A dark mode version of the logo can also be uploaded."
- favicon：上传，可另传深色版本。原文说明各流程的**浏览器标题已改为固定值，不再支持自定义标题**。
- Brand color：按钮、链接等组件的主色；"For dark mode, a separate brand color can be specified."
- Dark mode：开启后跟随用户系统设置。
- Hide Logto branding：去掉 "Powered by Logto"。

**Keycloak**
- 没有 Logo / 颜色的管理端配置项，靠主题。`keycloak.v2` 登录主题的 `theme.properties` 写着 `darkMode=true`。[theme.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources/theme/keycloak.v2/login/theme.properties)
- 品牌名来自 realm 的 `displayNameHtml`，模板里用 `kcSanitize(...)` 消毒后输出。[template.ftl](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources/theme/keycloak.v2/login/template.ftl)
- Quick Theme：实验特性，`--features=quick-theme` 启用，改 Logo 和颜色（"The color options correspond to PatternFly global CSS variables"），产物是一个主题 JAR，仍要部署到 `providers/` 或 `themes/` 后再在 Realm settings → Themes 里选中。[quick-theme](https://www.keycloak.org/ui-customization/quick-theme)

**Zitadel**：[branding](https://zitadel.com/docs/guides/manage/customize/branding)
- 明 / 暗两套：上传 Logo；颜色有背景、主色（按钮 / 链接 / 高亮）、警告色、字体色；上传字体（推荐 TTF）。
- 高级：隐藏登录名后缀、隐藏 Zitadel 水印。
- 先在右侧预览，点 "Apply settings" 后登录页**和邮件**一起生效；"reset policy" 恢复系统默认。

**Casdoor**（源码字段）：[application.go](https://github.com/casdoor/casdoor/blob/master/object/application.go)
- `Logo` / `LogoDark` / `Favicon`（均为 URL 字符串）、`Title`、`ThemeData{ThemeType, ColorPrimary, …}`、`FormCss` / `FormCssMobile`、`FormBackgroundUrl` / `FormBackgroundUrlMobile`、`HeaderHtml` / `FooterHtml` / `SigninHtml` / `SignupHtml` / `FormSideHtml`。

## 4. 「完整定制」的档位（Q3 展开）

### ① 自定义 CSS

- **Logto**：三层都能设，优先级同品牌。"the code editor only supports the CSS code so far. Not HTML or Javascript." 类名来自 CSS Modules 带 hash，文档建议用 `$=` 选择器只匹配可读部分；CSS 插在 `<title>` 之后。[custom-css](https://docs.logto.io/customization/custom-css)
- **Casdoor**：`customCss` 被剥掉 `<style>` / `</style>` 后包进一个新的 `<style>` 用 `dangerouslySetInnerHTML` 插入。[LoginPage.js](https://github.com/casdoor/casdoor/blob/master/web-old/src/auth/LoginPage.js)
- **Authing（未验证）**：搜索摘要称文档提醒应使用固定类名而非带 hash 的类名；旧版文档称样式编辑器出于安全考虑不支持自定义 JavaScript。[custom-styles](https://docs.authing.cn/v2/guides/app/custom-styles.html)

### ② 包一层 HTML 模板（保留核心表单插槽）

- **Auth0 页面模板**：Liquid 写的模板包住所有登录流程页面，必须含 `auth0:head` 和 `auth0:widget`；"To use customized page templates, you must configure a Custom Domain for your tenant."；只能用 Management API 更新；上限 100KB。[customize-templates](https://auth0.com/docs/customize/login-pages/universal-login/customize-templates)
  - 安全：建议 "Use HTML-escaped outputs in templates"、"Do not interpolate `ext-` values in `<script>` blocks or event handler attributes"，`ext-` 参数视为攻击者可控。文档未提 CSP。
  - 维护："CSS class names change each time Auth0 builds the project"；"The HTML structure of Universal Login pages is subject to change."
- **Auth0 Prompt Partials**：在登录 / 注册表单的固定插入点（`form-content-start`、`form-content-end`、`form-footer-start`、`form-footer-end`、`secondary-actions-start/end`）塞片段。"Partials support HTML, CSS, JavaScript, and Liquid syntax."，每段 ≤10,000 字符；要求自定义域名和页面模板。文档提醒注册页易受 XSS、慎用第三方 JS、用 Liquid `escape` 转义收集到的数据。[customize-signup-and-login-prompts](https://auth0.com/docs/customize/login-pages/universal-login/customize-signup-and-login-prompts)

### ③ 整页替换主题

- **Keycloak**：FreeMarker 模板可整页覆盖，但 "Unless you plan to replace every single page you should extend another theme"；主题可通过 `scripts=` 带 JS。安全：恶意模板能以 Keycloak 进程身份执行代码，只装可信来源的主题，限制 `themes/` 与 `providers/` 的写权限。维护："During upgrades, you might be forced to update your custom templates to get the latest updates from newer versions."；不要直接改内置主题。[themes](https://www.keycloak.org/ui-customization/themes)
- **Casdoor**：Application 的 `signinHtml` 不为空时整块替换登录页；`RenderCustomHtml` 注释写明 "<script> tags inserted via dangerouslySetInnerHTML are not executed by the browser, so we need to re-create them manually to make embedded scripts run."——**故意执行管理员写的脚本**，无 CSP 或消毒。[Setting.js](https://github.com/casdoor/casdoor/blob/master/web-old/src/Setting.js)
- **Auth0 Classic「Customize Login Page」**：可整页编辑 HTML（Lock / Auth0.js 模板）。开启后自行维护、不再自动更新（包括 SDK 版本号）；Classic 已不再更新，官方推荐改用 ACUL。[customization-classic](https://auth0.com/docs/customize/login-pages/classic-login/customization-classic)、[customize-with-lock-sdk](https://auth0.com/docs/customize/login-pages/classic-login/customize-with-lock-sdk)

### ④ 完全自建 UI

- **Auth0 ACUL**：自己构建 JS/CSS 上传到自己的 CDN，Auth0 只出一个最小宿主页加载这些资源，"The ACUL SDKs act as the connection between your custom code and Universal Login."；需自定义域名；浏览器用 SRI 哈希校验资源。[advanced-customizations](https://auth0.com/docs/customize/login-pages/advanced-customizations)
- **Logto Bring your UI**：上传含根 `index.html` 的 zip（≤20MB、单文件 ≤10MB、≤200 个文件），由 Logto 托管；UI 调 Experience API。"Logto applies a Content Security Policy (CSP) header to custom UI pages."，需要第三方脚本或外连时由管理员登记 `script-src` / `connect-src` 源，且只在自定义 UI 生效时追加。上传即生效，删掉卡片即回到内置 UI。[bring-your-ui](https://docs.logto.io/customization/bring-your-ui)
- **Zitadel Login V2**：开源 TypeScript 登录应用，官方建议 fork 后直接改源码；自托管时需要一个带 `IAM_LOGIN_CLIENT` 角色的服务账号 PAT（`ZITADEL_SERVICE_USER_TOKEN`），会话放在签名的 httpOnly cookie 里。[login-client](https://zitadel.com/docs/self-hosting/manage/login-client)、[typescript-login 博客](https://zitadel.com/blog/typescript-login)
  - 博客称 "Custom Login Texts configurations are not used in the typescript login"，但当前源码已按组织加载托管翻译（`getHostedLoginTranslation`，见第 5 节），博客已过时。

## 5. 多语言（Q4 展开）

**Auth0**：[universal-login-internationalization](https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization)
- 租户设置里启用语言，"The default language is the first one in the list."
- `ui_locales`："The first locale on the list must match the enabled locale in your tenant to reflect in the UI."
- `Accept-Language`：在允许的语言内生效；"If not, the pages render in the default language."
- 文档没说 `ui_locales` 与 `Accept-Language` 同时出现时谁优先，也没提 cookie 或切换器。
- 文案覆盖：按 prompt → screen → key 组织，每条覆盖都绑定一个 `language`；Set 接口会**整体替换**该 prompt 的配置；文案可含 `${clientName}`、`${companyName}` 等变量。[customize-text-elements](https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements)

**Logto**：[localized-languages](https://docs.logto.io/customization/localized-languages)
- 顺序：`ui_locales`（第一个支持的标签）→ 自动检测（`Accept-Language`）→ 租户默认。默认语言 "used when the detected user language isn't covered in the current language library."
- 可新增自定义语言；改内置语言即覆盖默认文案，清空即回退。API：`PUT /api/custom-phrases/{languageTag}`。

**Keycloak**：[proc-configuring-internationalization.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/realms/proc-configuring-internationalization.adoc)、[DefaultLocaleSelectorProvider.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/locale/DefaultLocaleSelectorProvider.java)
- 顺序：用户在切换器选的 → 用户资料 locale → 客户端传的（"for example ui_locales"）→ cookie → `Accept-Language` → realm 默认 → 英语。realm 未开国际化时直接返回英语。
- 用户登录后更新持久 cookie；用户在登录页主动切过语言时也写回用户资料。
- 切换器：模板在 `realm.internationalizationEnabled && locale.supported?size gt 1` 时渲染。[template.ftl](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources/theme/keycloak.v2/login/template.ftl)
- 文案覆盖："All internationalized texts which are provided by the theme can be overwritten by realm-specific texts on the *Localization* tab."
- **名字可随语言变**：Client 的 Name "To localize the name, set up a replacement string value. For example, a string value such as ${myapp}."，Description 同样可本地化。[con-basic-settings.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/clients/oidc/con-basic-settings.adoc)

**Zitadel**
- 文档：支持 23 种语言，按请求的语言头选，不匹配时用实例默认；restrictions API 可限制允许的语言，登录 UI 与通知都只用允许的语言，OIDC discovery 的 `ui_locales_supported` 也只列允许的语言。[texts](https://zitadel.com/docs/guides/manage/customize/texts)
- Login V2 源码：先取实例默认，`Accept-Language` 首项（只取主语言部分）在允许列表内则覆盖，`NEXT_LOCALE` cookie 再覆盖；cookie 值不被允许时回到默认。文案合并顺序是 `en` 兜底 → 当前语言 → 按组织的托管自定义翻译。[request.ts](https://github.com/zitadel/zitadel/blob/main/apps/login/src/i18n/request.ts)
- 另有环境变量 `ZITADEL_UI_LOCALES_OVERRIDE_COOKIE` 控制 `ui_locales` 是否压过 cookie。[i18n.ts](https://github.com/zitadel/zitadel/blob/main/apps/login/src/lib/i18n.ts)

**Authing（未验证）**：搜索摘要称全局登录框样式里可设默认语言、开关「切换语言」入口。[tenant-branding](https://docs.authing.cn/v2/tenant-console/tenant-branding.html)

## 6. 邮件 / 短信与登录页是否一起做（Q5 展开）

- **Logto**：邮件模板按 `languageTag` + `templateType` 存（SMTP、SendGrid、Mailgun、AWS SES、阿里云邮件推送），找不到就用连接器里的默认模板；语言判定与登录页同一套。模板变量含 `application.name`，以及 Application / Organization 的品牌（`logoUrl`、`darkLogoUrl` 等）。[email-templates](https://docs.logto.io/connectors/email-connectors/email-templates)
- **Keycloak**：Email 是主题的一种，每封邮件三条消息（主题、纯文本、HTML），走同一套消息包。[themes](https://www.keycloak.org/ui-customization/themes)
- **Zitadel**：邮件 / 短信文案（message texts）与登录文案在同一个 texts 设置里按语言编辑；品牌应用后登录页和邮件一起生效。[texts](https://zitadel.com/docs/guides/manage/customize/texts)、[branding](https://zitadel.com/docs/guides/manage/customize/branding)
- **Auth0**："Each type of email has exactly one template."，多语言靠 Liquid 条件；可用变量 `request_language`、`user_metadata`。[email-templates](https://auth0.com/docs/customize/email/email-templates)、[use-liquid-syntax](https://auth0.com/docs/customize/email/email-templates/use-liquid-syntax-in-email-templates)
- **短信**：国内验证码短信的内容由报备的模板决定，阿里云号码认证的赠送模板「不支持自定义创建签名和模板」。见本目录 `cn-channel-qualifications.md`。

## 7. 对 Polaris 的启示

1. **层级照 `GLOSSARY.md` 现有定义走，逐项覆盖**：实例一套默认，Application 逐项覆盖品牌名 / Logo / 主色。这比 Casdoor 的整块覆盖更细，与 Logto 的 App 级覆盖相当；Polaris 没有 Organization 概念，不需要第三层。
2. **一期只做一个主色，不做逐元素调色板**：Logto、Casdoor 都只要一个品牌色。托管页的主色已经集中在 `:root` 的 `--primary`、`--primary-hover`、`--primary-soft`、`--primary-ink` 这组 CSS 变量里，服务端从一个 hex 算出这四个值写进 `<style>` 即可。校验只放行 `#rrggbb`，避免把任意字符串插进 CSS。深色模式先不做（托管页现在是 `color-scheme: light`）。
3. **Logo 先填 HTTPS URL，不做上传**：Auth0、Casdoor 都是 URL，省掉对象存储。要求 `https://`，用 `<img>` 输出（`html/template` 会转义属性）。代价是登录页会向第三方域名发请求；现在的 CSP 只有 `frame-ancestors`，以后收紧 CSP 时要给 `img-src` 留口子。上传可以等有需求再做。
4. **「完整定制」不做 ②③ 档**：Auth0 模板 + Partials、Keycloak 主题、Casdoor `signinHtml` 都带 JS 风险（Casdoor 甚至主动执行脚本），而且都明说升级会坏。Polaris 已有直连认证 API，等同于第 ④ 档（Application 完全自绘），能覆盖真正需要整页定制的场景。
   - 如果以后要给一个中间档，只开放**自定义 CSS**（Logto 做法：不接受 HTML / JS），同时加一个严格的 CSP（`script-src 'self'`，不允许 `unsafe-inline`），并且在文档里写明类名不保证稳定。
5. **语言判定**：中英两种，顺序取 Keycloak / Logto 的交集，`ui_locales` → 页面切换器写的 cookie → `Accept-Language` → 实例默认（建议 `zh-CN`），兜底中文。
   - 切换器只有两种语言，做成一个链接即可。
   - `ui_locales` 只在授权请求里出现，要随登录事务一起保存，后续表单提交时继续用。
   - 直连认证 API 本身不渲染页面，返回给 App 的 `error_description` 可以跟 `Accept-Language` 走，也可以保持现状，按 ADR 0010 App 应当读 `next` 而不是这段文字。
6. **文案**：先把 `pages.html` 里的中文抽成按语言分开的消息表（Go 内嵌，`html/template` 里用一个 `t` 函数取），**不做管理员覆盖单条文案**。四家都有覆盖功能，但都是在多语言稳定之后才加的；覆盖功能一旦做就必须按语言分别存（四家都是这样）。
7. **品牌名、Application 名先不随语言变**：只有 Keycloak 支持用 `${key}` 占位符，代价是管理员要懂消息包。双语场景下，管理员填一个中性名字（或中英混写）就够了。
8. **邮件和登录页共用一个语言判定**（Logto、Keycloak、Zitadel 都是这样），验证码邮件跟着这次登录事务的语言走；短信受运营商模板报备约束，一期只支持中文模板，不做多语言。

## 附录：来源

**Auth0**
- 主题：https://auth0.com/docs/customize/login-pages/universal-login/customize-themes
- 页面模板：https://auth0.com/docs/customize/login-pages/universal-login/customize-templates
- Prompt Partials：https://auth0.com/docs/customize/login-pages/universal-login/customize-signup-and-login-prompts
- Custom Text：https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements
- 国际化：https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization
- ACUL：https://auth0.com/docs/customize/login-pages/advanced-customizations
- Classic：https://auth0.com/docs/customize/login-pages/classic-login/customization-classic 、https://auth0.com/docs/customize/login-pages/classic-login/customize-with-lock-sdk
- Organization 品牌：https://auth0.com/docs/manage-users/organizations/configure-organizations/create-organizations
- 邮件：https://auth0.com/docs/customize/email/email-templates 、https://auth0.com/docs/customize/email/email-templates/use-liquid-syntax-in-email-templates
- 按应用换 Logo（支持中心）：https://support.auth0.com/center/s/article/displaying-per-application-logos-on-auth0-universal-login

**Logto**
- 品牌：https://docs.logto.io/customization/match-your-brand
- 自定义 CSS：https://docs.logto.io/customization/custom-css
- Bring your UI：https://docs.logto.io/customization/bring-your-ui
- 多语言：https://docs.logto.io/customization/localized-languages
- 邮件模板：https://docs.logto.io/connectors/email-connectors/email-templates

**Keycloak**（`keycloak/keycloak@main`）
- 主题指南：https://www.keycloak.org/ui-customization/themes ；Quick Theme：https://www.keycloak.org/ui-customization/quick-theme
- 国际化与 locale 选择：`docs/documentation/server_admin/topics/realms/proc-configuring-internationalization.adoc`
- 主题选择：`docs/documentation/server_admin/topics/realms/themes.adoc`
- Client 名本地化：`docs/documentation/server_admin/topics/clients/oidc/con-basic-settings.adoc`
- locale 选择实现：`services/src/main/java/org/keycloak/locale/DefaultLocaleSelectorProvider.java`
- 登录模板与主题属性：`themes/src/main/resources/theme/keycloak.v2/login/template.ftl`、`theme.properties`

**Zitadel**（`zitadel/zitadel@main`）
- 品牌：https://zitadel.com/docs/guides/manage/customize/branding
- 文案与语言：https://zitadel.com/docs/guides/manage/customize/texts
- Project private labeling：https://zitadel.com/docs/guides/manage/console/projects
- Login V2：https://zitadel.com/docs/self-hosting/manage/login-client 、https://zitadel.com/blog/typescript-login
- 源码：`apps/login/src/i18n/request.ts`、`apps/login/src/lib/i18n.ts`

**Casdoor**（`casdoor/casdoor@master`，HEAD `42e1808`）
- `object/application.go`、`object/organization.go`、`web-old/src/Setting.js`（`getThemeData`、`RenderCustomHtml`）、`web-old/src/auth/LoginPage.js`

**Authing**（均未能直接抓取，仅搜索摘要，未验证）
- https://docs.authing.cn/v2/guides/app-new/create-app/customize-guard.html
- https://docs.authing.cn/v2/tenant-console/tenant-branding.html
- https://docs.authing.cn/v2/guides/app/custom-styles.html
