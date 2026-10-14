# 管理端现有配置项盘点

调研 ticket:#42(地图 #40「管理端文案、用语与引导改版」)。依据为 `main`(7d83110)上的代码:前端 `web/src/routes/console*.tsx`,后端 `internal/`。下文的 `file:line` 都是该提交上的位置。

**这是写于实现之前的快照**:盘点的是 #40 改版动手前的界面。改版与二期功能落地后,下面不少条目已经过时;与现行实现不符时,以 [consoles.md](../spec/consoles.md) 为准。

## 读法

**文案问题分类**(#40 Notes 里风格指南要解决的四类):

- **A 分号短句**:用分号连接、读起来像规格的短句,如"留空用默认:浏览器 30 天,App 90 天"。
- **B 字段格式**:直接把字段或数据格式暴露给人,如"每行一个 Team ID.Bundle ID"。
- **C 中英混排**:标题或标签里中英文混排,如"User 详情"、"Session 闲置寿命(天)"。
- **D 缺"为什么"**:只说是什么,不说为什么要配、不配会怎样。
- 另记 **R 读者错位**:身份、审计页面向运营,却出现了协议词(sub、aud、client_id 等)。它不属于四类,但 #40 的"读者按分组区分"会碰到。

**谁来配**:开发者 = 接入方工程师(懂 OAuth);运营 = 运营 / 客服 / 实例负责人。

**未验证**:代码里找不到消费方,或者效果取决于运行环境、无法只靠读代码确认的项。

---

## 0. 外壳(`console.tsx`)

| 元素 | 当前文案 | 实际作用 | 需要的 Permission | 文案问题 |
|---|---|---|---|---|
| 顶部导航 | 概览 / 身份 / 接入 / 安全 / 审计 | 按 Permission 过滤,缺权限的分组不显示(console.tsx:21-27, 51-52) | 概览、身份需 `users:read`;接入需 `applications:read`;安全需 `config:read`;审计需 `audit:read` | — |
| 右上角 | 当前管理员的 `sub`(console.tsx:69) | 只显示 | — | R:只显示 sub,没有手机号或邮箱 |
| 错误页 | "你不是管理员,无法使用管理端" / "管理端加载失败:…" | `/me` 返回 403 或其他错误时显示 | — | — |

---

## 1. 概览(`console.index.tsx`)

只读,没有可配置项。

| 元素 | 当前文案 | 实际含义(后端) | 文案问题 / 备注 |
|---|---|---|---|
| 统计卡 | User | `count(*) FROM users`,含已禁用的 User(management.sql:242) | C |
| 统计卡 | 今日登录 | 今天 `auth_time` 落在当天的 Session 数(management.sql:243)。重新认证、同一浏览器再次登录(`RenewSession` / `Reauthenticate` 更新 auth_time)也会计入,所以它不是"登录次数",也不是"登录人数"。"当天"按数据库时区算(**未验证**部署时区) | 含义模糊 |
| 统计卡 | 活跃 Session | `live_sessions` 视图:未结束且未超过闲置寿命的 Session(00007_sessions.sql:19-20) | C;运营不懂 Session |
| 统计卡 | Application | `count(*) FROM applications`,**包含内置的管理端和账号中心**(management.sql:245) | C;数字比"我注册的"多 2 |
| 告警条 | "过去 24 小时已发送 {n} 条验证码,达到每日上限 {limit},已停发。可在「安全」中调整上限。" | `sendsLastDay >= dailySendLimit` 时出现(console.index.tsx:24)。计数来自 `sends` 表,测试码不计入(channels.go:68-90 不写 sends) | 写法不错:说了后果和去处。可以加跳转链接 |
| 最近事件 | 最近事件 / 全部 → | `audit?limit=10`,需 `audit:read`;表格复用审计页的 EventTable | 问题同审计页 |

---

## 2. 身份(`console.users.tsx`)

读者:运营 / 客服。

### 2.1 列表

| 元素 | 当前文案 | 实际作用(后端) | 依赖 / 备注 | 文案问题 |
|---|---|---|---|---|
| 卡片标题 | User | — | — | C |
| 搜索框 | 占位符"搜索 sub / 手机号 / 邮箱 / 用户名,回车确认" | sub 按大写子串匹配;Identifier 按小写子串匹配(management.sql:22-24) | — | R(sub);A(分隔符拼接) |
| 角色筛选 | "全部角色";选项为 Role 名 + 所属 API 名 | `?api=&role=`;不传 api 时后端默认按 Management API 筛(management.go:208-226) | 列出所有 API 的所有 Role | 混用:选项叫"角色",别处叫 Role |
| 列 | User | 显示 sub;被禁用时加"已禁用"徽标 | — | C、R:运营看到的是一串 ID |
| 列 | Identifier | 所有 Identifier 的值用"·"拼接 | — | C,而且是领域术语原词 |
| 列 | 角色 | 所有 API 上的 Role 名(management.sql:18-20) | 同名 Role 分属不同 API 时无法区分 | 与 Role 混用 |
| 列 | 创建于 | `created_at` | — | — |
| 空状态 | 没有匹配的 User | — | — | C |
| 按钮 | 加载更多 | 每页 50 条,offset 分页 | — | — |

### 2.2 User 详情(右侧抽屉)

| 元素 | 当前文案 | 实际作用(后端) | 谁 / 权限 | 依赖 / 前后关系 | 文案问题 |
|---|---|---|---|---|---|
| 抽屉标题 | User 详情 | — | — | — | C(#40 点名的例子) |
| 头部 | sub + "创建于 …" | — | — | — | R |
| 分区 | Identifier:手机号 / 邮箱 / 用户名,未绑定的显示"未绑定" | — | — | — | C |
| 操作 | 替换(浏览器 `prompt("新的手机号")`) | `PUT /users/{sub}/identifiers/{kind}`。手机号只收 +86;用户名须符合 `^[a-z0-9._-]{3,32}$`;值已被他人占用时返回 409(users.go:95-118, identity.go:178-188)。写审计 `identifier.replaced`,不记录值 | 运营;`users:write`,对管理员操作还需 `admin-roles:assign`(users.go:20-37) | **用户名只能配合密码登录**:密码登录为"关闭",或为"仅管理员"而对方不是管理员时,替换来的用户名登不了(identity.go:168-173)。界面没有提示 | D:没说替换后会怎样(旧值作废、不发通知、不需对方确认);原生 prompt 不显示格式要求 |
| 分区 | 安全 → 状态 | 正常 / 已禁用 · 时间 | — | — | — |
| 分区 | 安全 → 密码 | 已设置 / 未设置(只是 `hasPassword`) | — | 即使密码已设置,登录策略不允许时也用不了,界面看不出来 | D |
| 分区 | Session:每行"App · 应用名"或"浏览器 · 应用名",显示"活跃于 …"或"已结束 …" | `GET /users/{sub}/sessions` | — | 过期时间 = 最后活动 + 该 Application 的闲置寿命(sessions.sql) | C |
| 操作 | 下线 | `DELETE …/sessions/{id}`,结束该 Session;它下面的 refresh token 随之失效(grant 只在 Session 存活期间可用,oidc.sql:54-57);写审计 `session.ended` | `users:write` | — | D:没说下线后 App 要重新登录;无二次确认 |
| 空状态 | 没有 Session | — | — | — | C |
| 分区 | Role:按 API 分组的复选框,每组单独"保存" | `PUT /users/{sub}/roles`,对该 API **整组替换**;撤下最后一个所有者时返回 409(rbac.go:26-66);写审计 `roles.assigned` | 普通 API 需 `roles:assign`;Management API 需 `admin-roles:assign` | **Role 只在某个 Application 以它所属 API 为默认 API 时才会出现在 access token 里**(login.go:173-191)。见第 6 节 | C;D:没说勾上以后对用户有什么效果 |
| 操作 | 禁用 | `POST /disable`:User 不能再登录,所有 Session 立即结束(management.sql:185-197);不能禁用最后一个所有者(users.go:41-57) | 运营;`users:write` | — | 确认框写得好:"禁用后该 User 无法登录,所有 Session 立即下线" |
| 操作 | 恢复 | `POST /enable` | 同上 | 已结束的 Session 不会恢复 | — |
| 操作 | 删除 | `DELETE /users/{sub}`:连带删除该 User 的所有数据;**并向每个设了 webhook 的 Application 排队发送 user.deleted**(management.sql:200-214);写审计 `user.deleted` | 运营;`users:write` | 与各 Application 的 webhook 配置相关 | 确认框没提会通知接入方 |
| 规格有、界面无 | 重置 2FA、外部身份 | consoles.md 有写;代码里没有 2FA 和 Provider 的实现 | — | — | 规格与界面不一致 |

---

## 3. 接入(`console.apps.tsx`)

读者:开发者。

### 3.1 Application 列表

| 元素 | 当前文案 | 实际作用 | 文案问题 |
|---|---|---|---|
| 卡片标题 / 按钮 | Application / 注册 Application | — | C |
| 列 | 名称(内置的带"内置"徽标) | 内置的是管理端和账号中心,只读(applications.go:256-262) | D:没说"内置"为什么不能改 |
| 列 | client_id | — | 开发者可以接受,缺一句人话 |
| 列 | 类型 | 原样显示 `public` / `confidential` | 英文枚举直出 |
| 列 | 默认 API | 显示 API 标识符,不是名称;未设显示"—" | B |

### 3.2 Application 表单(抽屉)

| 字段 | 当前文案(标签 / 帮助 / 占位符) | 实际作用(后端) | 谁 | 默认值 | 依赖 / 前后关系 | 文案问题 |
|---|---|---|---|---|---|---|
| 头部 | `client_id: … · public` | — | 开发者 | — | — | C |
| client secret 提示 | "client secret(只显示这一次):…" | 创建 confidential 应用或重新生成时返回一次;库里只存哈希(applications.go:221-242, 355-366) | 开发者 | — | 只有 confidential 有 | 说清了"只显示一次",但没说该拿它做什么 |
| 类型(仅新建时显示) | `public(App、SPA,PKCE)` / `confidential(有后端,client secret)` | public:token 端点不认证客户端,只靠 PKCE;confidential:用 client_secret_basic(oidcstore.go:62-85)。**创建后不能改** | 开发者 | public | 决定后面是否有"重新生成 secret" | B(PKCE、client secret 直出);D:没说"创建后不能改",也没说怎么选 |
| 名称 | 名称 | 1-64 字;登录页显示它(goidc ClientMeta.Name) | 开发者 / 运营 | 必填 | — | D:没说最终用户会在登录页看到 |
| 回调地址 | 帮助"每行一个" | `redirect_uris`;必须是完整 URI 且不带 `#`(applications.go:279-283);授权请求只接受登记过的值 | 开发者 | 空 | 浏览器 / OIDC 登录必填;**只走直连认证 API 的 App 是否也需要,未验证** | B;D:没说填错会怎样、格式示例 |
| 退出后跳转地址 | 帮助"每行一个" | `post_logout_redirect_uris`,RP 发起退出后允许跳回的地址 | 开发者 | 空 | 不填就不能带 post_logout_redirect_uri 退出 | B、D |
| 默认 API | 帮助"access token 的 aud";选项"无"或某个 API 的名称+标识符 | 设了之后 access token 的 `aud` = 该 API 标识符,并带上 User 在这个 API 上的 `roles` / `entitlements`(login.go:173-191);不能选 Management API 或 Account API(applications.go:273-278);外键约束 API 必须存在(applications.go:334-335) | 开发者 | 无 | **必须先在下方"API"里登记 API 才能选**;删除 API 时,有 Application 以它为默认 API 就会被拒(rbac.go:183-184);**选"无"时,该 Application 拿到的 token 不带任何 Role** | B(aud);D:没说不选会怎样 |
| Session 闲置寿命(天) | 帮助"留空用默认:浏览器 30 天,App 90 天";1-365 | `session_idle_timeout`;新建 Session 时写入 `idle_timeout`(sessions.sql:1-10)。闲置超过这个时长,Session 失效,其下 refresh token 也失效;每次 refresh 都会续期(oidc.sql RotateRefreshToken 更新 last_seen_at);浏览器 cookie 的 Max-Age 也用它(login.go:500, 516, 535) | 开发者 | 空 → 浏览器 30 / App 90 | **只对修改之后新建的 Session 生效**(值在建 Session 时拷贝);对 App 而言,只有开了 refresh token 才有意义 | **A、C**(#40 点名的两条);D |
| 签发 refresh token | 开关"签发 refresh token" | 开:客户端获得 `refresh_token` 授权类型,每次签发,轮换使用,重放会结束整个 Session(oidcstore.go:79-81, login.go:115, oidc.sql EndReusedRefreshToken)。refresh token 本身不设有效期,跟着 Session 走(oidcstore.go:164-167) | 开发者 | 开 | 与闲置寿命构成 App 的实际登录时长;关掉后 access token 10 分钟到期(login.go:118-120)就得重新登录 | 英文协议词;D:没说关掉的后果 |
| webhook URL | 帮助"接收 user.deleted;留空不发送" | `webhook_url`,只接受 http(s)(applications.go:284-288)。User 被删除(管理员删除或本人注销,identity/account.go:103-122)时排队 POST,按 Standard Webhooks 签名,失败按指数退避重试,约一天后放弃(webhook.go:25-30, 95-97) | 开发者 | 空 | **第一次填 URL 必须同时填签名密钥**(DB 约束 `applications_webhook_check`,00009_applications.sql:10,报错"webhook 需要签名密钥",applications.go:336-337);清空 URL 会同时清掉密钥(management.sql:153-156) | **A**;B(user.deleted);C(小写 webhook);D:没说为什么要接(删除用户后同步删业务数据) |
| webhook 签名密钥 | 无帮助;已设置时占位符"已设置 · 更新于 …,留空不修改" | 用主密钥加密存储,只写不读(applications.go:313-319) | 开发者 | 空 | 依赖 URL,见上 | C;D:没说怎么验签、密钥由谁生成 |
| iOS App | 帮助"每行一个 Team ID.Bundle ID" | 校验格式 `^[A-Z0-9]{10}\.…`(applications.go:289-293)后存入 `apple_app_ids`。**代码里没有任何消费方**:规格要求的 `apple-app-site-association` 尚未实现(roadmap.md:29,在后期范围) | 开发者 | 空 | 规格里用于 Passkey / 通用链接 | **B**(#40 点名);D;**作用未验证(目前没有生效)** |
| Android App | 帮助"每行:包名 SHA-256 签名指纹(可多个,空格分隔)" | 校验包名和 `AB:CD:…` 格式指纹(applications.go:294-303)后存入 `android_apps`。同样**没有消费方**(`assetlinks.json` 尚未实现) | 开发者 | 空 | 同上 | **A、B**;**作用未验证(目前没有生效)** |
| 按钮 | 保存 / 注册 | PUT / POST | 开发者 | — | 内置 Application 整个表单禁用 | — |
| 按钮 | 重新生成 secret(仅 confidential) | 新 secret 立即生效,旧的立即失效(applications.go:355-366);确认框"生成新的 client secret 后,旧的立即失效。确定吗?" | 开发者 | — | 没有新旧并存期,要先停服换密钥 | C |
| 按钮 | 删除 | 确认框"删除 {名称}?它将无法再登录 User。" | 开发者 | — | 已签发的 token 和 Session 怎么处理,**未验证** | "无法再登录 User"的说法不通顺 |

### 3.3 API 卡片

| 元素 | 当前文案 | 实际作用 | 谁 | 依赖 / 前后关系 | 文案问题 |
|---|---|---|---|---|---|
| 卡片说明 | "每个 API 定义自己的 Permission 和 Role;access token 只带当前 aud 那个 API 的 roles 和 entitlements。" | 准确(login.go:173-191) | 开发者 | — | **A、B、C** 都有;D:没说为什么要建 API |
| 添加 API | 占位符"API 标识符(aud),如 https://api.example.com"、"名称";按钮"添加 API" | `PUT /apis/{identifier}`。标识符已存在时**静默改名**,不报冲突(rbac.go:162-172) | 开发者 | 必须先有 API,才能选默认 API、建 Permission 和 Role | B(aud);D:没说标识符创建后不能改(GLOSSARY) |
| API 头部 | 名称 + 标识符 + "内置";按钮"删除" | `DELETE ?force=true`,连同 Permission、Role 和所有 Role 分配一起删除;仍有 Application 以它为默认 API 时返回 409(rbac.go:174-191) | 开发者 | 依赖默认 API(先解绑再删) | 确认框只提了 Role 分配,没提默认 API 冲突 |
| Permission 区 | 小标题"Permission";徽标"key 显示名";"×"删除,确认"删除 {key}?它也会从所有 Role 中移除。" | `PUT/DELETE …/permissions/{key}`;删除时级联移除 | 开发者 | 先建 Permission,再把它勾进 Role | C |
| 添加 Permission | 占位符"key,如 track:write"、"显示名" | 同 key 已存在时改名 | 开发者 | — | B(key) |
| Role 区 | 小标题"Role";每行"名称 key [内置] · n 个 Permission · n 个 User";按钮"编辑 / 删除" | `PUT/DELETE …/roles/{key}`;仍有分配时须 force,确认框写明人数(rbac.go:242-264) | 开发者(定义)/ 运营(分配) | 只能勾选同一 API 的 Permission(rbac.go:223-240);Management API 上的 Role 需 `admin-roles:assign` | C |
| 添加 Role | 按钮"添加 Role";占位符"key,如 editor"、"显示名";Permission 复选框只显示 key | — | 开发者 | — | B(只显示 key,不显示显示名) |
| 规格有、界面无 | 默认 Role(consoles.md 接入分组);给 confidential Application 分配 Role(GLOSSARY Role) | 代码里都没有 | — | — | 规格与界面不一致 |

---

## 4. 安全(`console.security.tsx`)

读者:开发者(#40);但登录策略里有不少项其实是运营 / 负责人的决定。

### 4.1 登录策略(`PUT /settings`,需 `config:write`,写审计 `settings.updated`)

| 字段 | 当前文案 | 实际作用(后端) | 谁 | 默认值 | 依赖 / 前后关系 | 文案问题 |
|---|---|---|---|---|---|---|
| 密码登录 | 下拉"关闭 / 仅管理员 / 所有 User";帮助"关闭期间,已设的密码保留但不能用" | 登录时校验密码正确后再看策略:`off`,或 `admins` 而该 User 不持有 Management API 上的 Role,一律回"账号或密码错误"(identity.go:168-173)。账号中心据此决定能否设置密码(account.sql:12-13, account.go:338-339) | 运营 / 负责人 | `admins`(00003_identity.sql:51) | **用户名只能配合密码使用**,关闭密码就等于关闭用户名登录;与"必须绑定手机号"的关系见第 6 节 | C("所有 User");D:没说为什么默认只开给管理员 |
| 必须绑定手机号 | 开关"必须绑定手机号";无帮助 | 每次登录完成前检查(`NeedsPhone`,identity.sql:40-43):没有手机号的 User 先进入"绑定手机号"步骤,且**只接受手机号**(login.go:284, 315;challenge.go:146-152, 210);`prompt=none` 直接返回 `interaction_required`(login.go:218-221) | 运营 / 负责人 | 关(00006_code_login.sql:39) | **依赖短信通道**:没有手机号通道时发码失败,提示"暂不支持向这类手机号或邮箱发送验证码"(otp.go:26, 52-54),没有手机号的 User **全部登不进去**。也受每日发送上限约束 | **D**(最需要说明的一项:开了以后谁会被拦住、前提是什么) |
| 每日发送上限(条) | 帮助"全实例每天最多发送的验证码" | 过去 24 小时(滚动窗口,不是自然日)全实例发送数达到上限后拒发,提示"今日发送量已达上限";当天第一次触发时写审计 `send.daily_cap_reached`(otp.go:100-115, otp.sql:12)。0 = 一条都不发。测试码不计入 | 运营 | 1000(00006_code_login.sql:38) | 验证码登录、绑定手机号、注册邀请都受它约束;概览告警条读它 | D:没说达到上限后用户会怎样,也没说是防短信轰炸 / 控成本;"每天"其实是滚动 24 小时 |
| 审计保留期(天) | 无帮助;最小 1 | 每小时清理一次早于保留期的审计事件(audit.sql:8, main.go:144, 150) | 运营 / 负责人 | 180(00010_policy.sql:9) | 改短会在一小时内删掉旧事件,不可恢复 | C 无,D:没说改短不可恢复、合规上该填多少 |
| 《用户协议》URL | 无帮助 | 必须是 https(settings.go:41-45);登录页和 `GET /v1/auth/terms` 展示(challenge.go:247-253) | 运营 / 法务 | 空 | 填了协议版本时**必须同时填**两份 URL(settings.go:38-40) | D |
| 《隐私政策》URL | 无帮助 | 同上 | 运营 / 法务 | 空 | 同上 | D |
| 协议版本 | 帮助"登录时须勾选同意;改动后 User 下次登录须重新同意。留空则不要求同意";改动时确认"改动协议版本后,所有 User 下次登录时都须重新同意,确定吗?" | 非空时:登录表单要勾选同意(login.go:265-270);已登录的 User 在下次授权时补同意(`NeedsConsent`,login.go:384-396);直连认证 API 要求带 `terms_version`(challenge.go:85-92);同意记录写入 `consents` | 运营 / 法务 | 空 | **依赖上面两个 URL**;顺序应当是先填 URL,再填版本 | **A**(分号 + 句号连了三件事);D:没说版本号填什么(日期?) |
| 按钮 | 保存 | 整组提交 | — | — | 一个"保存"同时提交从密码到审计的 7 项,改一项也会写整组 | — |
| 规格有、界面无 | Passkey、2FA、管理员必须启用 2FA(consoles.md 安全分组) | `settings` 表和 Policy 里都没有 | — | — | — | 规格与界面不一致 |

### 4.2 通道(`/channels/{phone|email}`,需 `config:write`)

| 元素 | 当前文案 | 实际作用(后端) | 谁 | 默认 | 依赖 / 前后关系 | 文案问题 |
|---|---|---|---|---|---|---|
| 卡片说明 | 标题"通道";"把验证码送到手机号或邮箱;每类只启用一个。" | — | 开发者 | — | — | A(分号) |
| 分区头 | 短信 / 邮件 + "已启用 · 更新于 …" / "未启用" | — | — | 未启用 | — | — |
| 插件下拉 | 占位"选择 Channel";aria-label "短信 Channel" | 短信可选:阿里云短信认证、Webhook;邮件可选:SMTP、Webhook(aliyun.go:27-29, smtp.go:24-26, channel/webhook/webhook.go:28-30) | 开发者 | — | 换插件后,按钮变成"切换并保存",保存即替换旧通道 | **C**("选择 Channel",同一页标题又叫"通道") |
| 阿里云字段 | AccessKey ID;AccessKey Secret(密钥);签名(帮助"号码认证控制台赠送的签名;只能发往中国大陆 +86 号码");模板 Code(帮助"与签名配套的赠送模板,选登录/注册场景") | 存入 channel 配置,密钥字段加密(channel/store.go:95-115) | 开发者 | — | — | A(分号);B(字段名直出) |
| SMTP 字段 | 服务器(如 smtp.qq.com);端口(帮助"465 直接走 TLS;其他端口须支持 STARTTLS");用户名(选填);密码(选填、密钥);发件人(如 Stars Auth <noreply@example.com>) | 同上 | 开发者 | — | — | A |
| Webhook 字段 | URL(帮助 `收到 POST {"to", "code"},返回 2xx 即视为送达`);签名密钥(帮助 `X-Stars-Signature: t=<秒>,v1=<hex HMAC-SHA256(密钥, "<t>.<body>")>`) | 同上 | 开发者 | — | — | **B**(整段格式直出);D |
| 密钥占位符 | "已设置 · 更新于 …,留空不修改" | 留空保留原值 | — | — | — | 符合规格"只写不回显" |
| 选填标记 | 选填 | — | — | — | — | — |
| 按钮 | 保存 / 切换并保存 | `PUT` | 开发者 | — | — | — |
| 按钮 | 停用;确认"停用后将无法发送{短信/邮件}验证码,确定吗?" | `DELETE` | 开发者 | — | **停用短信通道且"必须绑定手机号"开着时**,没有手机号的 User 都登不进去;停用后,用户中只用这类 Identifier 的人也无法登录。确认框没提 | D(后果说得不够) |
| 测试 | 输入框占位 `+8613800001111` / `you@example.com`;按钮"发送测试码";结果"已发送 {code},请核对收到的验证码" | 手机号须为 E.164;不计入每日上限,不写 `sends`;审计记为 `test-channel`(channels.go:66-91) | 开发者 | — | 只有保存后才出现 | B(要求 E.164,但错误提示才说);占位符本身就是示例,还好 |

### 4.3 签名密钥

| 元素 | 当前文案 | 实际作用 | 谁 | 依赖 | 文案问题 |
|---|---|---|---|---|---|
| 卡片说明 | "当前密钥签发令牌;轮换后,上一个密钥只用来验证它签过的令牌。" | 最新的密钥签发;JWKS 发布全部保留的密钥(keys.go:61-80) | 开发者 | — | A(分号);D:没说什么时候该轮换 |
| 列表 | kid · 当前 / 已退役 · 创建于 … | 最新的在前 | — | — | B(kid) |
| 按钮 | 轮换;确认"轮换后,更早的密钥将被删除,它签发且未过期的令牌随即失效。确定吗?" | 新建一把并设为当前,只保留最新两把(keys.go:54-59, oidc.sql:106-109);需 `keys:rotate` | 开发者 | 连续轮换两次,当前签发、未过期的 token 立即失效(access token 10 分钟;ID token 同理) | 确认框说清了后果 |

### 4.4 规格有、界面无

Provider 的添加与启停:**已实现**(#87–#97),现落在独立的「认证源」分组(ADR 0012)。

---

## 5. 审计(`console.audit.tsx`)

读者:运营 / 客服。

| 元素 | 当前文案 | 实际作用(后端) | 依赖 / 备注 | 文案问题 |
|---|---|---|---|---|
| 卡片标题 | 审计日志 | — | — | — |
| 事件筛选 | "全部事件" + 26 个事件名(console.audit.tsx:38-64) | `?event=` 精确匹配 | **漏了账号中心写入的 `identifier.removed`、`password.changed`、`password.removed` 和投递失败的 `webhook.failed`**:不在下拉里,表格里也显示原始英文事件名 | 混用:"禁用 User"、"refresh token 重放"、"修改登录策略" |
| sub 筛选 | 占位符"User 或操作人的 sub,回车确认" | 同时匹配事件主体 `sub` 和 `detail.by`(management.sql:234) | 运营手上通常只有手机号,但这里只能按 sub 查 | **R**;C |
| 日期 | aria-label 起始日期 / 截止日期 | 本地日期;截止日包含当天 | — | — |
| 列 | 时间 | — | — | — |
| 列 | 事件 | 有映射就显示中文名,没有就显示原始名 | Management API 的写操作按 operationId 命名(audit.go:30-49),例如 `put-channel` | C(多数事件名里夹着英文) |
| 列 | User | 事件主体的 sub,没有时显示"—" | — | C、R |
| 列 | 详情 | "操作人 {sub}" + 其余字段按 `key: value` 用"·"拼接 | 字段名原样输出(如 `kind: phone`、`session: …`、`limit: 1000`、`force: true`) | **B**(最严重);R |
| 空状态 / 按钮 | 没有匹配的事件 / 加载更多 | 每页 50 条,按 id 翻页 | 受审计保留期影响,过期的查不到 | — |
| 规格有、界面无 | 导出 CSV | 规格写明二期 | — | — |

---

## 6. 配置之间的依赖

下表按"改 A 前要先有 B"或"A 开着时 B 才有意义"的关系整理,括号里是代码依据。目前**界面上一条都没有提示**,只有后端在保存时对其中三条报错(标 ⛔)。

1. **必须绑定手机号 → 短信通道**:开启前必须先启用短信通道,否则没有手机号的 User 全部登不进去(login.go:284, 315;otp.go:52-54)。停用短信通道时也要先检查这个开关。
2. **必须绑定手机号 ↔ 密码登录 / 邮箱登录**:用用户名+密码或邮箱验证码登录、但没有手机号的 User,会在登录后被拦到绑定手机号步骤(login.go:380-397)。开启前,运营应当知道这部分人有多少。
3. **验证码登录 → 对应 Identifier 的通道**:手机号或邮箱验证码登录各自依赖一个启用的通道;没有通道时,登录页报"暂不支持向这类手机号或邮箱发送验证码"(otp.go:26, 52-54)。
4. **每日发送上限 → 所有验证码场景**:登录、绑定手机号、账号中心换绑都受它约束;设为 0 等于关掉所有验证码(otp.go:100)。概览告警条就是读它。
5. **密码登录 → 用户名、账号中心设置密码**:用户名只能配合密码使用(GLOSSARY Identifier);策略不允许时,账号中心也不让设置密码(account.go:338-339)。在身份页替换用户名前,应先看策略。
6. ⛔ **协议版本 → 两个协议 URL**:填写版本时必须同时填写 https 的两个 URL(settings.go:38-45)。
7. **协议版本的改动 → 所有 User 下次登录**:改版本会让所有 User 重新同意;已经接直连认证 API 的 App 要带新的 `terms_version`(challenge.go:85-92)。
8. ⛔ **默认 API → 先登记 API**:只能选已登记的 API;不能选 Management API 或 Account API(applications.go:273-278, 334-335)。
9. ⛔ **删除 API ← 仍被用作默认 API**:要先把相关 Application 的默认 API 改掉(rbac.go:183-184)。
10. **Role 是否生效 → 默认 API**:Role 只出现在以它所属 API 为默认 API 的 Application 的 access token 里(login.go:173-191)。所以顺序是:登记 API → 定义 Permission → 定义 Role → 在 Application 上选默认 API → 给 User 分配 Role。如果没有任何 Application 以该 API 为默认 API,分配的 Role 不会出现在任何 token 里。
11. **Role → Permission(同一 API)**:Role 只能包含本 API 的 Permission;删除 Permission 会把它从所有 Role 里移除(rbac.go:203-240)。
12. ⛔ **webhook URL ↔ 签名密钥**:第一次填 URL 必须同时填密钥;清空 URL 时密钥一起清掉(00009_applications.sql:10;management.sql:153-156)。
13. **webhook → 删除 User**:管理员删除和本人注销都会向所有配了 webhook 的 Application 发送 `user.deleted`(management.sql:200-214;identity/account.go:103-122)。
14. **refresh token ↔ Session 闲置寿命**:refresh token 本身不设有效期,跟着 Session 走(oidcstore.go:164-167),每次刷新都给 Session 续期。所以 App 的"多久不用就要重新登录"= 闲置寿命,而且前提是开着 refresh token;关掉之后,access token 10 分钟一到就得重新登录,闲置寿命对 App 基本没有意义。
15. **Session 闲置寿命 → 只影响新 Session**:值在建 Session 时拷贝进去(sessions.sql:1-10),改了不影响已有 Session。
16. **类型 → client secret**:只有 confidential 有 secret、能重新生成;类型创建后不能改(applications.go:221-228, 355-366)。
17. **iOS App / Android App → Passkey、通用链接(尚未实现)**:目前只存不用,依赖的 `/.well-known/` 文件在 roadmap 后期(roadmap.md:29)。
18. **审计保留期 → 审计页能查到的范围**:每小时清理一次(audit.sql:8;main.go:144-150)。
19. **签名密钥轮换 → 已签发 token**:库里只保留两把,连续轮换两次就会让旧 token 立即失效(oidc.sql:106-109)。
20. **管理员身份 → 操作权限**:对持有 Management API Role 的 User 做任何写操作,都还需要 `admin-roles:assign`;禁用、删除、撤 Role 时,不能让最后一个所有者消失(users.go:20-57;rbac.go:26-66)。

## 7. 汇总

- **数量**:5 页加外壳。可编辑的配置字段 / 开关共 **29 个**:Application 表单 11 个、登录策略 7 个、通道插件字段 11 个(阿里云 4、SMTP 5、Webhook 2)。另有 API / Permission / Role 的新增或编辑表单 3 个,表格列 12 列(身份、接入、审计各 4 列),筛选器 6 个(身份 2 个、审计 4 个)。
- **点名最多的文案**(按严重程度):
  1. Application 表单的"Session 闲置寿命(天) / 留空用默认:浏览器 30 天,App 90 天"(A+C+D)。
  2. "iOS App:每行一个 Team ID.Bundle ID"、"Android App:每行:包名 SHA-256 签名指纹(可多个,空格分隔)"(B,而且**目前没有任何作用**)。
  3. API 卡片说明"…access token 只带当前 aud 那个 API 的 roles 和 entitlements"(A+B+C)。
  4. 审计页的"详情"列 `key: value` 直出和 sub 筛选(B+R)。
  5. 通道 Webhook 的签名密钥帮助(整段签名格式)(B)。
  6. 登录策略的"必须绑定手机号"没有任何说明,但它是最危险的开关(D,依赖 1)。
  7. 身份页处处混用 "User / Identifier / Session / Role" 和"角色"(C)。
- **规格与界面不一致**:consoles.md 写了、代码里还没有的有:Passkey、2FA、管理员必须启用 2FA、认证服务商、重置 2FA、外部身份、默认 Role、给 confidential Application 分配 Role、导出 CSV。改版规格应当以现有界面为准,或者明确标注为后期。
