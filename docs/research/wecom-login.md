# 企业微信登录作为 Provider 类型

调研日期：2026-11-04。范围：让 User 用企业微信账号登录 Polaris 时，企业微信那一侧的流程、身份标识、应用类型、限制和自测准备。不含通讯录同步、消息推送、客户联系。

**阅读须知**

- 一手来源只用企业微信开发者中心 `developer.work.weixin.qq.com`。链接紧跟结论。
- **本次环境打不开 qq.com**：沙箱代理在 TLS 握手阶段断开所有 `*.qq.com` 连接，WebFetch 也报 `Socket is closed`，浏览器工具连不上。所以下面的结论都来自**限定官方域名的搜索引擎对官方页面的摘录**，没有逐页打开原文。标记含义：
  - **[已验证]**：搜索摘录里有官方文档页面的原句，且多个页面说法一致。写进 ADR 前仍建议点开链接核一次。
  - **[未验证]**：只在开发者社区帖、或摘录没给原句、或官方页面之间说法不一。
  - **[推断]**：本文作者的判断。
- 企业微信同一主题常有好几个页面编号（自建 / 第三方 / 代开发各一份，新旧版各一份），下文尽量给自建应用那份。

## 1. 两种网页入口的流程

企业微信有两条网页登录路径，**最后都是拿 code 调同一个 `auth/getuserinfo`**，区别只在授权链接。

### 1.1 企业微信 Web 登录（外部浏览器，扫码 / 桌面端一键登录）

- **新版链接**：`https://login.work.weixin.qq.com/wwlogin/sso/login?login_type=CorpApp&appid=CORPID&agentid=AGENTID&redirect_uri=REDIRECT_URI&state=STATE`。[已验证] [Web登录组件 98152](https://developer.work.weixin.qq.com/document/path/98152)、[开始开发 98151](https://developer.work.weixin.qq.com/document/path/98151)
  - `login_type`：自建应用和代开发应用填 `CorpApp`，第三方应用（服务商登录）填 `ServiceApp`。[已验证] 同上；社区里有人把 CorpID 用在服务商场景报「appid 参数错误」，官方答复要改 `ServiceApp` + SuiteID。[未验证·社区] [问答](https://developer.work.weixin.qq.com/community/question/detail?content_id=16483814101506679499)
  - `appid`：`CorpApp` 时是企业 CorpID；`ServiceApp` 时是「登录授权」的 SuiteID。[已验证]
  - `agentid`：仅 `CorpApp` 时需要，是应用的 AgentID。[已验证]
  - `redirect_uri`：URL 编码；域名必须是应用配置的授权回调域。[已验证]
  - `state`：可选，官方建议带上防 CSRF。[已验证] 另有社区帖反映新版回调缺 `state`。[未验证·社区] [问答](https://developer.work.weixin.qq.com/community/question/detail?content_id=16466096421373280490)
  - `lang` 等：JS 组件 `ww.createWWLoginPanel`（`@wecom/jssdk` ≥ 2.3.2）另有 `redirect_type`（top / callback / self）、`panel_size`、`lang`。[已验证] [创建企业微信登录面板 98478](https://developer.work.weixin.qq.com/document/path/98478)。Polaris 走整页跳转，用不到组件。[推断]
- **回调**：用户同意后跳到 `redirect_uri?code=CODE&state=STATE`。[已验证] 98152
- **新旧版关系**：新版是旧版「扫码登录」的升级，除手机扫码外还支持企业微信桌面端快速登录；官方建议旧版接入方切到新版。[已验证] [98151](https://developer.work.weixin.qq.com/document/path/98151)、[98152](https://developer.work.weixin.qq.com/document/path/98152)
  - 旧版：`https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=CORPID&agentid=AGENTID&redirect_uri=...&state=...`，另有 `window.WwLogin({...})` 内嵌写法；「仅企业内可以使用此种授权方式，第三方服务商不支持使用」。[已验证] [扫码授权登录 10719](https://developer.work.weixin.qq.com/document/10719)
  - 结论：新接入只做新版。[推断]
- **成员不在应用可见范围**：扫码时提示无权限。[已验证] [98152](https://developer.work.weixin.qq.com/document/path/98152)、[设置授权应用可见范围 90583](https://developer.work.weixin.qq.com/document/path/90583)

### 1.2 网页授权登录（在企业微信客户端里打开网页）

- **链接**：`https://open.weixin.qq.com/connect/oauth2/authorize?appid=CORPID&redirect_uri=REDIRECT_URI&response_type=code&scope=snsapi_base&state=STATE&agentid=AGENTID#wechat_redirect`。[已验证] [构造网页授权链接 91022](https://developer.work.weixin.qq.com/document/path/91022)、[96441](https://developer.work.weixin.qq.com/document/path/96441)
  - `appid`：企业 CorpID。`response_type` 固定 `code`。必须以 `#wechat_redirect` 结尾。[已验证]
  - `scope`：`snsapi_base` 静默授权，只能拿 UserId；`snsapi_privateinfo` 手动授权，可拿头像、手机等敏感信息，要求成员在应用可见范围内。[已验证]
  - `agentid`：新版文档列为必填；旧版文档说只有 `snsapi_userinfo` / `snsapi_privateinfo` 时必填，不填则按 `snsapi_base` 处理。[未验证·两版说法不一] 一律带上即可。[推断]
  - `state`：可选，只能 `a-zA-Z0-9`，≤ 128 字节。[已验证] 91022。Polaris 的 state 需符合这个字符集。[推断]
- **回调**：跳到 `redirect_uri?code=CODE&state=STATE`。[已验证]
- 这条路径只在企业微信客户端（及微信内？）有意义，外部浏览器用 1.1。[推断]

### 1.3 code 换身份（两种入口通用）

1. 用 `corpid` + 应用 `corpsecret` 调 `GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET` 取应用 access_token。[已验证] [获取access_token 91039](https://developer.work.weixin.qq.com/document/path/91039)
2. `GET https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=ACCESS_TOKEN&code=CODE`。[已验证] [获取用户登录身份 98176](https://developer.work.weixin.qq.com/document/path/98176)、[获取访问用户身份 91023](https://developer.work.weixin.qq.com/document/path/91023)
   - 企业成员返回 `userid`；`scope=snsapi_privateinfo` 且在可见范围内时另返回 `user_ticket`（1800 秒，用来调 `auth/getuserdetail` 取敏感信息）。[已验证] [91023](https://developer.work.weixin.qq.com/document/path/91023)、[获取访问用户敏感信息 96443](https://developer.work.weixin.qq.com/document/path/96443)
   - 非企业成员返回 `openid`（及条件性的 `external_userid`），见 3.3。[已验证]
   - code 每次不同、只能消费一次、5 分钟未用自动过期。[已验证] [98179](https://developer.work.weixin.qq.com/document/path/98179)、[91023](https://developer.work.weixin.qq.com/document/path/91023)
   - 跳转域名须**完全匹配** access_token 所属应用的可信域名（含端口），否则返回 `50001`；code 无效 / 重复消费返回 `40029`。[已验证] [98176](https://developer.work.weixin.qq.com/document/path/98176)、[全局错误码 96213](https://developer.work.weixin.qq.com/document/path/96213)
   - 第三方应用改用 `service/auth/getuserinfo3rd`（用 suite_access_token）。[已验证] [98179](https://developer.work.weixin.qq.com/document/path/98179)、[91711](https://developer.work.weixin.qq.com/document/path/91711)

### 1.4 access_token 缓存与频率

- `expires_in` 通常 7200 秒；有效期内重复获取返回相同结果；企业微信可能因运营需要提前让它失效，代码要处理失效后重取。[已验证] [91039](https://developer.work.weixin.qq.com/document/path/91039)
- **必须缓存**，不能频繁调 `gettoken`，否则被频率拦截；按应用分别缓存，预留 ≥ 512 字节。[已验证] [91039](https://developer.work.weixin.qq.com/document/path/91039)、[开发前必读 90664](https://developer.work.weixin.qq.com/document/path/90664)
- 通用频率：每企业单个接口 ≤ 1 万次/分、15 万次/小时；按分钟超限屏蔽 60 秒，按小时超限屏蔽 60 分钟。[已验证] [访问频率限制 90312](https://developer.work.weixin.qq.com/document/path/90312)
- `gettoken` 一小时内失败次数过多（corpid/secret 填错）也会触发 `45009`。[未验证·社区官方人员回复] [问答](https://developer.work.weixin.qq.com/community/question/detail?content_id=16371609378110225058)。对 Polaris 的含义：管理员填错 secret 后不断重试会把整个企业的 `gettoken` 锁一小时。[推断]
- 过期错误码 `42001` 时重取再发。[未验证·社区]

### 1.5 PKCE / nonce / OIDC

- 两种链接的参数里都没有 `code_challenge`、`nonce`、`prompt`、`max_age`；`getuserinfo` 不返回 id_token，也没有 discovery 文档。搜索没有找到任何官方页面提到这些。[推断：不支持，依据是参数表里没有]
- code 只能由持有 corpsecret 的服务端兑换，且 code 与可信域名绑定，这代替了 PKCE 对 code 的保护。[推断]

## 2. 它不是标准 OAuth2，以及和 Redirect 接口的映射

**不是标准 OAuth2**，具体差在 [推断，依据 1.1–1.4]：

- 没有 token 端点用 code 换「用户的」access token；code 是拿**应用级**的 access_token（client credentials 性质）作为参数去 `getuserinfo` 换身份。
- 应用 access_token 用 GET + query 里的 secret 获取，不是 `client_secret_post` / Basic。
- 错误靠 HTTP 200 + `errcode` / `errmsg`，不是 OAuth2 的 `error`。
- 授权端点用的是 `appid`（企业 CorpID）而不是 `client_id`；`agentid` 才对应「哪个应用」。
- 网页授权链接必须带 `#wechat_redirect` 片段。

所以通用 OAuth2 类型（ADR 0013，固定 `client_secret_post` + userinfo 顶层字段）套不上，得是像 Apple 那样的独立类型包。

**映射到 `provider.Redirect`** [推断]：

| 接口 | 企业微信 |
|---|---|
| `AuthURL(redirectURI, state, nonce, verifier)` | 拼 1.1（或 1.2）的链接；`nonce`、`verifier` 忽略（无此参数）。`redirectURI` 即 `provider.CallbackURL(...)`，其域名要配到应用的授权回调域 |
| `Callback(params, ...)` | 取 `code` → 取缓存的应用 access_token（无则 `gettoken`）→ `auth/getuserinfo` → `Identity{Subject: userid}`；`errcode` 非 0 即失败；`40014`/`42001` 时作废缓存重取一次 |
| `Identity.AuthTime` | 零值（接口不返回登录时间） |
| `Identity.Token` | 空（没有可撤销的东西） |
| `NoReauthPrompt` | 实现（见 6） |

**服务端必须缓存应用 access_token**（见 1.4）。`Type.New` 规定不发网络请求，所以缓存在 upstream 结构体里惰性获取、带互斥锁，到期前留余量刷新。[推断] 多实例部署各自缓存问题不大：每实例每 2 小时 1 次，远低于 1 万次/分。[推断] Provider 配置被修改时 New 会重建 upstream，缓存自然丢弃。[推断]

## 3. 用户标识

### 3.1 userid（自建应用拿到的）

- 自建应用拿到的是**明文 userid**，即管理端的「账号」，企业内唯一，1–64 字节，唯一性校验忽略大小写。[已验证] [企业微信账号ID安全性全面升级 96516](https://developer.work.weixin.qq.com/document/path/96516)、[创建成员 90195](https://developer.work.weixin.qq.com/document/path/90195)
- **会变**：userid 由系统生成时，可以改一次（`更新成员` 接口的 `new_userid`），变更时推送 `change_contact` / `update_user` 事件带 `NewUserID`。[已验证] [更新成员 90197](https://developer.work.weixin.qq.com/document/path/90197)、[成员变更通知 90970](https://developer.work.weixin.qq.com/document/path/90970)、[成员UserId变更事件 93997](https://developer.work.weixin.qq.com/document/path/93997)
  - 管理后台界面能否改、是否也受「一次」限制：没查到官方说明。[未验证]
  - 管理员创建成员时自己填的 userid 能不能改：文档只说「系统生成时可改一次」，反推人工指定的不能改。[推断]
- 唯一范围：**单个企业**（corpid）。同一个人在两个企业是两个 userid。[已验证] 96516

### 3.2 open_userid / 密文 userid（第三方、代开发拿到的）

- 2022-06 的 ID 升级后，第三方应用和新授权的代开发应用拿到的 userid 是**服务商主体下的密文 userid，即 open_userid**；同一服务商下不同应用相同，不同服务商不同。自建应用不受影响，仍是明文。[已验证] [96516](https://developer.work.weixin.qq.com/document/path/96516)、[代开发应用安全性升级 96518](https://developer.work.weixin.qq.com/document/path/96518)。生效日期各页说法有 6 月 20 日 20 点、6 月 28 日 23:59 两种。[未验证]
- 有 `userid_to_openuserid` 等转换接口，用于服务商主体与企业主体 ID 之间互转。[已验证] [userid的转换 97062](https://developer.work.weixin.qq.com/document/path/97062)、[97106](https://developer.work.weixin.qq.com/document/path/97106)
- open_userid 会不会因管理员改 userid 而变：没查到。[未验证]

### 3.3 非企业成员扫码 / 打开

- `auth/getuserinfo` 对非企业成员返回 `openid`（**当前企业内唯一**），不返回 userid；若他是企业的客户且跟进人在应用可见范围内，另返回 `external_userid`。[已验证] [98176](https://developer.work.weixin.qq.com/document/path/98176)、[91707](https://developer.work.weixin.qq.com/document/path/91707)
- 第三方应用版（`getuserinfo3rd`）对非企业用户返回服务商范围内唯一的 `openid`。[已验证] [98179](https://developer.work.weixin.qq.com/document/path/98179)
- 但 Web 登录在成员不在可见范围时直接提示无权限（1.1），非成员能否走完 Web 登录流程拿到 openid，摘录没说清。[未验证]

### 3.4 锚点选择

- 自建应用下只有 userid 可用作锚点；它在企业内唯一，变化只发生在「系统生成的 userid 改一次」这种可预期场景。[推断]
- 锚点 = `(corpid, userid)`：corpid 定成 Immutable 字段，Subject 只存 userid。[推断]
- 非成员的 openid 与 userid 是不同命名空间，不应混作同一种 Subject。[推断]

## 4. 应用类型与资质

| | 企业自建应用 | 第三方应用（服务商） | 代开发应用（服务商替企业开发） |
|---|---|---|---|
| 谁建 | 企业管理员在自己管理后台 | 服务商在服务商后台，客户企业安装 | 服务商建模板，企业扫码授权后生成 |
| 谁能登录 | 本企业、在可见范围内的成员 | 所有安装了它的企业的成员 | 授权企业的成员 |
| Web 登录 `login_type` | `CorpApp` + CorpID | `ServiceApp` + 登录授权 SuiteID | `CorpApp` |
| 拿到的 ID | 明文 userid | open_userid（密文） | open_userid（新授权） |
| 取 token | `gettoken`(corpid, secret) | suite_ticket → suite_access_token → 永久授权码 | 拿到 secret 后与自建相同 |
| 费用 | 无接口许可费 [未验证] | 试用期后需购买接口调用许可（按成员账号） | 同第三方 |

来源：[自建/代开发/第三方区别（社区官方文章）](https://developer.work.weixin.qq.com/community/article/detail?content_id=16456783342741815588) [未验证·社区]；[与自建应用接口的差异 97165](https://developer.work.weixin.qq.com/document/path/97165) [已验证]；[自建应用代开发 31281](https://developer.work.weixin.qq.com/document/31281) [已验证]；接口许可收费见 [收费方案 99698](https://developer.work.weixin.qq.com/document/path/99698)（价格未取到）[未验证]。

- 服务商不得以自建应用方式给其他企业开发产品，历史自建应用要迁移成代开发。[已验证] [自建应用迁移成代开发应用 99617](https://developer.work.weixin.qq.com/document/path/99617)
- 发布应用必须完成企业微信账号认证。[已验证] [企业微信应用接入指引 90568](https://developer.work.weixin.qq.com/document/path/90568)

**2022 年后的新限制（自建应用）**

- **企业可信 IP**：2022-06-20 起，新创建的自建应用、新开启的通讯录同步须配置企业可信 IP，且不可配置第三方服务商的 IP；历史应用暂不需要。配置可信 IP 前须先设好可信域名。[已验证] [开始开发 91335](https://developer.work.weixin.qq.com/document/path/91335)；后半句来自社区。[未验证] 含义：**Polaris 服务器调 `qyapi.weixin.qq.com` 的出口 IP 必须在白名单里**，否则 `gettoken`/`getuserinfo` 失败。[推断]
- **可信域名**：须通过 ICP 备案验证；认证企业的自建应用要求域名备案主体与企业微信认证主体相同或有关联，否则「域名主体校验未通过」；未认证企业不受主体限制。[已验证：须备案，见 91022/91120] [未验证·社区：主体一致与未认证豁免] [社区解读](https://developer.work.weixin.qq.com/community/article/detail?content_id=16379433710071033989)、[ToB Dev 常见问题](https://developer.work.weixin.qq.com/community/article/detail?content_id=16526195469746891698)
- 可信域名须与访问链接域名**完全一致，含端口，不支持泛域名**。[已验证] [构造网页授权链接 91120](https://developer.work.weixin.qq.com/document/path/91120)。用于 OAuth 的可信域名只能配一个。[未验证·社区]。每企业每月最多改 20 次可信域名。[已验证] [90312](https://developer.work.weixin.qq.com/document/path/90312)
- **敏感信息**：新建自建应用和新授权代开发应用，成员手机、邮箱、头像、性别等敏感信息须成员在 OAuth2 登录时自主授权，经 `getuserdetail` 获取。[已验证] [获取访问用户敏感信息 95833](https://developer.work.weixin.qq.com/document/path/95833)。Polaris 只要 userid，不受影响。[推断]

## 5. 原生 App 登录

- iOS：SDK 为 `libWXWorkApi.a` + `WWKApi.h` + `WWKApiObject.h`；启动时注册，scheme 由企业 ID 和应用 ID 算出；发起 SSO 请求，在 `handleOpenURL` 收回调，得到一次性 code。[已验证] [iOS应用 91193](https://developer.work.weixin.qq.com/document/path/91193)
- Android：`lib_wwapi` aar；构造 `WWAuthMessage.Req`（appid、agentid、sch、state），`sendMessage` 发出，回调里按 errCode 判断成功 / 失败 / 取消，成功时取 code。[已验证] [Android应用 91194](https://developer.work.weixin.qq.com/document/path/91194)、[SDK下载 91074](https://developer.work.weixin.qq.com/document/path/91074)
- Harmony SDK 的 scopes 目前只支持 `snsapi_base`。[已验证] [Harmony应用 101021](https://developer.work.weixin.qq.com/document/path/101021)
- **服务端**：App 把 code 交给后端，后端用应用 access_token + code 换身份；文档写的接口路径是 `cgi-bin/user/getuserinfo`（旧名，与 `auth/getuserinfo` 的关系未确认），code 只能用一次、5 分钟过期。[已验证：路径；未验证：与新接口是否等价]
- 对 Polaris：这正是 `provider.ClientToken` 的形态（像 Apple 的 authorization_code），`ClientToken(code)` 复用 Callback 的兑换逻辑即可，无需额外配置字段。[推断] 原生 SDK 的回调是否也受可信域名校验（没有 redirect_uri）：未查到。[未验证]

## 6. 重新认证与撤销

- **没有找到强制重新登录参数**（无 `prompt=login` / `max_age` 等价物）。[推断：参数表无此项] Web 登录在桌面端已登录时可一键确认，网页授权 `snsapi_base` 是静默的，都不重新输入凭证。[推断]
- 企业微信另有「二次验证」能力，是企业层面对成员登录企业微信本身的验证，不是给第三方站点用的 reauth 参数。[未验证] [使用二次验证 99500](https://developer.work.weixin.qq.com/document/path/99500)
- **没有找到撤销授权 / 解绑接口**；`getuserinfo` 不给任何长期 token，本来就没东西可撤销。[推断]
- 结论：实现 `NoReauthPrompt`，不实现 `Unlinker`，与 ADR 0013 对 OAuth2 的取舍一致。[推断]

## 7. 自测准备清单

以下步骤来自 [开始开发 98151](https://developer.work.weixin.qq.com/document/path/98151)、[91335](https://developer.work.weixin.qq.com/document/path/91335)、[90568](https://developer.work.weixin.qq.com/document/path/90568) 的摘录和上文限制；界面菜单名以实际后台为准。

1. **注册企业**：在 work.weixin.qq.com 注册一个企业。未认证企业可以开发测试，但成员数有上限（具体数字未查到，超限报 `45024`），且不能「发布」应用。[未验证：未认证能否用 Web 登录，官方没明说] [全局错误码 90313](https://developer.work.weixin.qq.com/document/path/90313)
   - 未认证企业不受「域名主体一致」限制，自测时这点更省事。[未验证·社区]
2. **记下 CorpID**：管理后台「我的企业」→ 企业信息。
3. **创建自建应用**：「应用管理」→ 自建 → 创建应用；记下 **AgentId** 和 **Secret**（Secret 在企业微信客户端里查看）。
4. **设可见范围**：把自测账号（或其部门）加进应用可见范围，否则扫码提示无权限。
5. **准备一个已 ICP 备案的域名**，指向 Polaris 测试实例（HTTPS，端口要和回调 URL 完全一致，建议 443）。
6. **配置网页授权及 JS-SDK 可信域名**（应用详情页），可能要求在域名根目录放校验文件。
7. **开启「企业微信授权登录」→ Web 网页 → 设置授权回调域**，填与 `CallbackURL` 完全一致的域名。
8. **配置企业可信 IP**：填 Polaris 测试实例访问 `qyapi.weixin.qq.com` 的公网出口 IP（须先完成第 6 步）。
9. **在 Polaris 添加 Provider**：填 CorpID、AgentId、Secret。
10. **测试用例**：
    - 外部浏览器扫码（手机企业微信）和桌面端一键登录各一次 → 拿到 userid。
    - 企业微信客户端内打开登录页（若实现了 1.2）→ 静默拿到 userid。
    - 不在可见范围的成员、非本企业的人扫码 → 观察返回（无权限页 / openid）。
    - 同一 code 用两次 → `40029`；故意填错 Secret → `40001` 类错误，且确认不会无限重试导致 `45009`。
    - 回调域名填错 → `50001`；出口 IP 不在白名单 → 记录实际错误码（未查到，`60020` 待实测确认）。
    - 管理员改一次系统生成的 userid → 确认会被当成新 External Identity（锚点漂移的真实表现）。
11. **（可选）原生 App**：在应用详情里登记 iOS Bundle ID / Android 包名与签名，用官方 SDK Demo 拿 code，调 Polaris direct auth API。

## 对 Polaris 的建议

均为 [推断]。

- **形态**：新建独立类型包 `internal/provider/wecom`，照 `apple` 的写法：端点常量 + 可被测试覆盖的 `Endpoint` 变量，`init` 里 `provider.Register`。不复用 `oauth2` 包，理由见第 2 节。
- **只支持企业自建应用**（`login_type=CorpApp`）。第三方 / 代开发属于服务商业务（suite_ticket 回调、接口许可费），不是自建认证系统的 Operator 会走的路。自建应用代开发安装后用的也是 `CorpApp` 接口，顺带能用。
- **实现的接口**：`Redirect` + `ClientToken`（原生 App 交 code，复用兑换逻辑） + `NoReauthPrompt`。不实现 `Unlinker`。
- **锚点**：`Identity.Subject = userid`；External Identity 的命名空间由 Immutable 的 `corp_id` 决定。**拒绝非成员**（`getuserinfo` 只返回 openid 时报错）：企业微信登录的意义是「本企业成员」，openid 和 userid 命名空间不同，混进 Subject 会出错；以后真有需要再加前缀区分。在字段 Help 里写明「系统生成的账号被管理员修改后会变成另一个人」。
- **配置字段**：
  - `corp_id`（企业 ID，text，**Immutable**：锚点的命名空间，换企业就是另一批 User）
  - `agent_id`（AgentId，text，可改：userid 是企业级的，换应用不换人）
  - `secret`（应用 Secret，text，Secret: true，可改）
  - 不需要 scope 字段：固定 `snsapi_base`，只要 userid。
- **access_token 缓存**：upstream 内惰性获取 + 互斥锁 + 提前 5 分钟过期；`40014`/`42001` 作废重取一次；`gettoken` 失败不要在单次请求里重试，避免触发 `45009` 锁企业一小时。
- **两种入口都支持，同一个 Provider 内按环境选**：外部浏览器用新版 Web 登录（1.1），企业微信客户端内用网页授权（1.2，静默无感，是企业内部系统最常见的入口）。两者兑换逻辑完全相同，差别只在 AuthURL。难点是 `AuthURL` 签名里没有请求的 User-Agent：要么由登录页把「是否在企业微信内」放进 ctx，要么一期只做 1.1、二期再加 1.2。企业微信客户端的 UA 标识（常见是 `wxwork`）未在本次调研中验证。
- **部署文档要写清楚**：Polaris 的 issuer 域名须 ICP 备案（认证企业还要主体一致），出口 IP 须进企业可信 IP；这两条是自建应用接入失败最常见的原因，Operator 只能在企业微信后台解决。
- **state**：网页授权要求 state 只含 `a-zA-Z0-9` 且 ≤ 128 字节。`internal/provider/store.go` 用 `rand.Text()+rand.Text()`（base32 大写字母加数字，52 字符），已经满足，以后改 state 生成方式时别破坏这一点。

## 9. 浏览器复核（2026-11-04）

用浏览器直接打开原页核对：

- **Web 登录链接** [已验证] [98152](https://developer.work.weixin.qq.com/document/path/98152)：`https://login.work.weixin.qq.com/wwlogin/sso/login?login_type=CorpApp&appid=CORPID&agentid=AGENTID&redirect_uri=...&state=...`；`agentid` 在 `CorpApp` 时填写；`lang` 可选 zh/en；redirect_uri 域名须配置为「OAuth 可信域名或 Web 网页授权回调域名」。官方明示：在企业微信内置 Webview 里登录要改用 OAuth 授权登录（1.2 的链接）；用户不在 AgentID 应用可见范围时扫码提示无权限。旧版扫码登录建议切到此方式。
- **auth/getuserinfo** [已验证] [98176](https://developer.work.weixin.qq.com/document/path/98176)：`GET https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=&code=`，code ≤ 512 字节、一次性、5 分钟过期；跳转域名须完全匹配 access_token 所属应用的可信域名，否则 50001。企业成员**无论是否在可见范围内**都返回 `userid`；非企业成员返回 `openid`（对当前企业唯一）和条件性的 `external_userid`；失败 `{errcode:40029}`。→ 只接受带 `userid` 的响应，拿到 `openid` 一律拒绝。
- **userid 可变** [已验证] [更新成员 90197](https://developer.work.weixin.qq.com/document/path/90197)：「如果 userid 由系统自动生成，则仅允许修改一次。新值可由 new_userid 字段指定。」userid 不区分大小写，1–64 字节。改名后旧 userid 能否分配给另一个成员，文档没说 [未验证]；若能，旧 userid 的 External Identity 会被新成员继承。
