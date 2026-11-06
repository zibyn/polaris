# 飞书 / 企业微信 / 钉钉登录时能拿到的用户资料（邮箱、姓名、头像）

调研日期：2026-11-06。范围：飞书 / Lark、企业微信（企业自建应用）、钉钉（企业内部应用）三种 Provider 类型在登录时，除了 ID 之外还能不能拿到邮箱、显示名、头像、手机号；要什么权限、哪种 token；这些邮箱由谁设置、是否经过验证、会不会变。目的是决定 Polaris 要不要把 `email` / `name` / `picture` 传给下游 OIDC Client（Grafana、Langfuse、Sentry、LiteLLM）。

登录流程本身、ID 锚点、应用类型、自测清单不在这里重复，见：

- [feishu-login.md](feishu-login.md)：锚点 `union_id`，`/authen/v1/user_info`。
- [wecom-login.md](wecom-login.md)：锚点 `userid`，`auth/getuserinfo`，两种入口（Web 登录 / 客户端内网页授权）。
- [dingtalk-login.md](dingtalk-login.md)：锚点 `unionId`，`/v1.0/contact/users/me`。

**阅读须知**

- 一手来源：open.feishu.cn / open.larksuite.com（文档接口 `document_portal/v1/document/get_detail`）、飞书帮助中心 www.feishu.cn/hc；developer.work.weixin.qq.com 和企业微信帮助中心 open.work.weixin.qq.com/help2；open.dingtalk.com（正文取自文档站的内容文件 `icms-document.oss-cn-beijing.aliyuncs.com`，引用的是页面 URL）。
- 本次 `curl` / WebFetch 仍连不上 `*.qq.com` 和 `open.feishu.cn`，但**浏览器工具能打开**，所以企业微信和飞书的结论是在浏览器里读原文得到的。
- 标签：
  - **[已验证]**：读到了官方文档原文。
  - **[未验证：搜索摘要]**：只看到搜索引擎摘要或社区帖。
  - **[推断]**：本文作者的判断。

## 1. 飞书 / Lark

### 1.1 登录时那一次 `user_info` 就能拿到

`GET https://open.feishu.cn/open-apis/authen/v1/user_info`，`Authorization: Bearer <user_access_token>`，就是我们现在已经在调的那个接口。字段与权限 [已验证] [飞书：获取用户信息](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get)、[Lark：获取用户信息](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get)：

| 字段 | 含义 | 需要的权限 | 支持的应用类型 |
|---|---|---|---|
| `name` / `en_name` | 用户姓名 / 英文名 | 无 | 自建、商店 |
| `avatar_url`、`avatar_thumb`(72)、`avatar_middle`(240)、`avatar_big`(640) | 头像 | 无 | 自建、商店 |
| `email` | 用户邮箱（后台叫「工作邮箱」，见 1.2） | `contact:user.email:readonly` | **仅自建**（`support_app_types="custom"`） |
| `enterprise_email` | 企业邮箱，「请先确保已在管理后台启用飞书邮箱服务」 | `contact:user.employee:readonly` | 自建、商店（`custom,isv`） |
| `mobile` | 手机号 | `contact:user.phone:readonly` | 仅自建 |

- 全部只要 **user_access_token**，不需要 tenant_access_token，也不需要再调第二个接口。[已验证，同上]
- 飞书版页面对 `email` 和 `mobile` 有原话：「邮箱信息为管理员导入的用户联系方式，未经过用户本人实时验证，不建议开发者直接将其作为业务系统的登录凭证。如使用，务必自行认证。」Lark 版页面没有这句。[已验证，同上]
- 权限要先在开发者后台为应用开通。自建应用的权限分「免审」和「需审核」，需审核的要创建版本、由租户管理员审核通过才生效；商店应用的权限要过平台上架审核和租户安装审核。[已验证] [飞书：申请 API 权限](https://open.feishu.cn/document/ukTMukTMukTM/uQjN3QjL0YzN04CN2cDN)
- 授权页的 `scope` 参数是「用户需要增量授予应用的权限」；「当应用使用 user_access_token 调用某个 OpenAPI 时，必须确保该 user_access_token 具备目标 OpenAPI 所需的权限」；scope 里写了应用没开通的权限会报 20027。[已验证] [飞书：获取授权码](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
  - `user_info` 的字段权限是只看应用开通了没有，还是也要求写进 `scope`、由用户授予，文档没讲清。[推断] 稳妥起见把 `contact:user.employee:readonly` 写进 `scope`，实测时确认不写会不会也返回 `enterprise_email`。

### 1.2 三种邮箱，谁设置

飞书帮助中心把成员身上的邮箱分成三种 [已验证] [管理员修改成员信息 · 常见问题](https://www.feishu.cn/hc/zh-CN/articles/360043261194)：

- **飞书企业邮箱**（API 字段 `enterprise_email`）：「企业开通邮箱服务后，管理员为成员配置的飞书企业邮箱地址」。这是飞书托管的真实邮箱，域名要企业在管理后台申请、开通，没开通时用 API 设置会失败。[已验证] [Lark：用户接口相关问题](https://open.larksuite.com/document/ugTN1YjL4UTN24CO1UjN/uQzN1YjL0cTN24CN3UjN)
- **工作邮箱**（API 字段 `email`）：「如果企业未开通飞书企业邮箱服务，管理员可以自行为成员填写一个邮箱地址作为工作邮箱，用于沟通协作」。是管理员填写的任意地址。[已验证，同上]
- **登录邮箱**：成员用来登录飞书的凭证。账号未激活时，工作邮箱默认就是登录邮箱；「成员账号激活后，工作邮箱和登录邮箱将解除关联，管理员可以修改成员的工作邮箱，不会影响成员登录」。登录邮箱不通过开放平台返回。[已验证，同上]

### 1.3 能不能改

- **管理员**：可以在成员详情改头像、姓名、工作邮箱、企业邮箱、手机号等。[已验证] [管理员修改成员信息](https://www.feishu.cn/hc/zh-CN/articles/360043261194) 通讯录 API `PATCH /contact/v3/users/:user_id` 也能改 `name`、`email`、`enterprise_email`。[已验证] [Lark：修改用户部分信息](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/patch)
- **企业邮箱改地址**：「企业邮箱地址修改成功后，旧的企业邮箱地址会自动转为企业邮箱别名」；「如需将旧的企业邮箱地址分配给其他成员，需要先从别名中删除旧企业邮箱地址」。也就是说，**同一个 union_id 的 `enterprise_email` 会变，旧地址也可能被分配给另一个人**。[已验证] [管理员修改成员的企业邮箱地址](https://www.feishu.cn/hc/zh-CN/articles/360049067887)
- **成员自己**：管理员可以在「组织架构 > 字段配置 > 更多设置」里勾选允许成员自行修改的字段，包括头像、姓名、别名、联系手机号、**工作邮箱**；手机号和工作邮箱要去账号安全中心改。[已验证] [管理员允许成员自行修改信息](https://www.feishu.cn/hc/zh-CN/articles/360042994534) 账号安全中心里改邮箱是否要收验证码、改的是不是同一个「工作邮箱」字段，帮助页没写清。[未验证]
- 企业邮箱不在成员可自改的字段列表里。[已验证，同上] → 成员改不了 `enterprise_email`，只有管理员能改。[推断]
- 唯一性：`email` 在企业内不可重复。[已验证] [Lark：创建用户](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/create)

### 1.4 授权页

- 浏览器里的飞书授权页本来就有（见 [feishu-login.md](feishu-login.md) 1.2）；在飞书客户端里打开可以免确认直接回跳。[已验证] [飞书：获取授权码](https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code)
- 多要 `contact:user.employee:readonly` 之后授权页上会多列一项权限。[推断：授权页展示 scope 对应的权限] 权限是累积的，用户授过一次以后签发的 token 都带着。[已验证，同上]

## 2. 企业微信（企业自建应用）

### 2.1 2022-06-20 之后新建的自建应用

`读取成员`（`GET https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=&userid=`，用**应用 access_token**）原文 [已验证] [读取成员 90196](https://developer.work.weixin.qq.com/document/path/90196)：

> 从2022年6月20号20点开始，除通讯录同步以外的基础应用……以及新创建的自建应用与代开发应用，调用该接口时，不再返回以下字段：头像、性别、手机、邮箱、企业邮箱、员工个人二维码、地址，应用需要通过oauth2手工授权的方式获取管理员与员工本人授权的字段。

- **`name` 仍返回**：被收走的字段清单里没有姓名；`name` 的说明只限制了第三方和代开发应用（「代开发自建应用需要管理员授权才返回」），对自建应用没有限制。[已验证，同上]
- `user/get` 的前提：「应用只能获取可见范围内的成员信息」，「应用须拥有指定成员的查看权限」。[已验证，同上] 另外它和 `gettoken` 一样受企业可信 IP 限制（见 [wecom-login.md](wecom-login.md) 第 4 节）。[推断]
- `thumb_avatar`（头像缩略图）不在被收走的清单里，但说明里也没写自建应用一定返回。[未验证] 实测确认。
- 2022-06-20 之前建的老自建应用仍能从 `user/get` 拿到头像、邮箱、企业邮箱。[推断：变更只针对「新创建的」应用]

### 2.2 敏感字段：`snsapi_privateinfo` + `auth/getuserdetail`

1. **授权链接**（客户端内网页授权）用 `scope=snsapi_privateinfo`：「手动授权，可获取成员的详细信息，包含头像、二维码等敏感信息（此时要求成员必须在应用可见范围内）」；此时 `agentid` 必填，否则「系统会视为snsapi_base，不会返回敏感信息」。[已验证] [构造网页授权链接 91022](https://developer.work.weixin.qq.com/document/path/91022)
2. **`auth/getuserinfo`**（网页授权版）多返回 `user_ticket`：「最大为512字节，有效期为1800s。scope为snsapi_privateinfo，且用户在应用可见范围之内时返回此参数」。[已验证] [获取访问用户身份 91023](https://developer.work.weixin.qq.com/document/path/91023)
3. **`POST https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail?access_token=ACCESS_TOKEN`**，body `{"user_ticket": "..."}`，用应用 access_token。返回 `userid`、`gender`、`avatar`、`qr_code`、`mobile`、`email`、`biz_mail`、`address`；每个都是「仅在用户同意snsapi_privateinfo授权时返回」，`avatar` 不同意时返回默认头像。**不返回 `name`**。[已验证] [获取访问用户敏感信息 95833](https://developer.work.weixin.qq.com/document/path/95833)
   - 「对于自建应用与代开发应用，敏感字段需要管理员在应用详情里选择，且成员oauth2授权时确认后才返回。」[已验证，同上] → 两道门：管理员先在应用详情里勾字段，成员登录时再在授权页确认。

### 2.3 Web 登录（外部浏览器扫码 / 桌面端一键登录）拿不到 `user_ticket`

- Web 登录链接 `login.work.weixin.qq.com/wwlogin/sso/login` 的参数只有 `login_type`、`appid`、`agentid`、`redirect_uri`、`state`、`lang`，**没有 `scope`**；页面全文没有出现 scope、user_ticket、敏感信息。[已验证] [Web登录组件 98152](https://developer.work.weixin.qq.com/document/path/98152)
- Web 登录对应的 `getuserinfo` 文档页，成员返回值只有 `userid`（和灰度中的 `user_doc_ticket`），没有 `user_ticket`；网页授权那一页才有。两页请求地址相同。[已验证] [获取用户登录身份 98176](https://developer.work.weixin.qq.com/document/path/98176) 对比 [91023](https://developer.work.weixin.qq.com/document/path/91023)
- 98152 自己也说：在企业微信内置 Webview 里登录要改用 OAuth 授权登录。[已验证，同上]
- **结论** [推断]：新自建应用在外部浏览器登录时，只能拿到 `userid`，再用 `user/get` 拿到 `name`；**邮箱、企业邮箱、头像都拿不到**。只有在企业微信客户端里打开、走 `snsapi_privateinfo` 的那条路，才有机会拿到。

### 2.4 `email` 与 `biz_mail`，谁设置，能不能改

- `email`：「可填写企业已有的邮箱账号，方便同事获取成员的邮箱账号以发邮件……企业内必须唯一……境外成员可用此邮箱登录企业微信」。是管理员填的任意地址，文档没说会验证。[已验证] [创建成员 90195](https://developer.work.weixin.qq.com/document/path/90195)
- `biz_mail`：「如果企业已开通腾讯企业邮（企业微信邮箱），设置该值可创建企业邮箱账号……未填写则系统会为用户生成默认企业邮箱（由系统生成的邮箱可修改一次）」。是企业微信 / 腾讯企业邮托管的真实邮箱。[已验证，同上]
- 更新规则 [已验证] [更新成员 90197](https://developer.work.weixin.qq.com/document/path/90197)：
  - `email` 可以由管理员通过 API 改。
  - 「如果创建时『企业邮箱』为系统默认分配的，则仅允许修改一次，若创建时填入了合规的『企业邮箱』，则无法修改」。→ `biz_mail` 基本是稳定的，最多改一次。
  - 「若成员已激活企业微信」，`mobile` 要成员自己改。
- 成员自己改：头像要管理员在「我的企业 > 通讯录管理 > 成员可修改字段」里放开；别名、性别成员可以自己改。[已验证] [企业微信帮助：如何修改个人信息](https://open.work.weixin.qq.com/help2/pc/14946) 成员能不能自己改 `email`，帮助页没写；隐私指引的摘要说「若管理员设置为成员无法自行修改……请联系管理员」。[未验证：搜索摘要] [企业微信隐私保护指引](https://work.weixin.qq.com/nl/privacy_230802)
- 旧的 `biz_mail` 地址改掉后能不能分配给别人，没查到。[未验证]

### 2.5 授权页

- `snsapi_base` 是「静默授权」，`snsapi_privateinfo` 是「手动授权」。[已验证] [91022](https://developer.work.weixin.qq.com/document/path/91022) → 改用 `snsapi_privateinfo` 后，成员每次（或首次）在客户端里会看到一个确认页。[推断] 是不是每次都弹、能不能记住，文档没写。[未验证]

## 3. 钉钉（企业内部应用）

### 3.1 登录时那一次 `users/me` 就能拿到

`GET https://api.dingtalk.com/v1.0/contact/users/me`，`x-acs-dingtalk-access-token: <用户 accessToken>`，权限 `Contact.User.Read`，企业内部应用、第三方企业应用、第三方个人应用都支持。[已验证] [获取用户通讯录个人信息](https://open.dingtalk.com/document/development/dingtalk-retrieve-user-information)

| 字段 | 原文说明 |
|---|---|
| `nick` | 「用户的钉钉昵称」 |
| `avatarUrl` | 「头像URL」 |
| `mobile` | 「用户的手机号」；第三方企业应用拿到的是脱敏的；要申请「个人手机号信息」权限 |
| `email` | 「用户的个人邮箱」，说明里写「添加个人邮箱」并配了一张截图 |
| `openId` / `unionId` / `stateCode` | 见 [dingtalk-login.md](dingtalk-login.md) |

[已验证，同上]

- 这里的 `nick` 是钉钉账号的个人昵称，`email` 是**个人邮箱**，都是钉钉账号层面的、用户自己填的东西，不是组织通讯录里的姓名和企业邮箱。[推断：依据字段说明「钉钉昵称」「个人邮箱」]
- 个人邮箱在钉钉里怎么添加、要不要收验证码，没找到官方原文。帮助中心摘要提到钉钉账号有「辅助邮箱」，在安全中心里绑定。[未验证：搜索摘要] [钉钉帮助：如何添加验证钉钉辅助邮箱](https://m.dingtalk.com/qidian/help-keyword-97046) 二者是不是同一个，不知道。[未验证]
- 授权页展示哪些信息「以应用注册时配置的为准」，见 [dingtalk-login.md](dingtalk-login.md) 1.2。→ 多开通邮箱、手机号权限后，授权页会多列几项。[推断]

### 3.2 组织通讯录里的姓名和企业邮箱：要多两次调用、用应用 token

1. `unionId` → `userid`：`POST https://oapi.dingtalk.com/topapi/user/getbyunionid`，企业 access_token，权限 `qyapi_get_member`。[已验证，见 [dingtalk-login.md](dingtalk-login.md) 第 3 节]
2. `POST https://oapi.dingtalk.com/topapi/v2/user/get`，Query 带企业 `access_token`，body 带 `userid`；企业内部应用、第三方企业应用支持，第三方个人应用不支持；权限「成员信息读权限」。[已验证] [查询用户详情](https://open.dingtalk.com/document/orgapp/query-user-details)
   - `name`：「员工姓名」。
   - `avatar`：「员工使用默认头像，不返回该字段，手动设置头像会返回」。
   - `email`：「员工邮箱」；「企业内部应用，只有应用开通通讯录邮箱等个人信息权限，才会返回该字段。第三方企业应用，不返回该参数」。
   - `org_email`：「员工的企业邮箱。如果员工的企业邮箱没有开通，返回信息中不包含该数据……第三方企业应用不返回该参数」。说明里没给它额外的权限要求。
   - `mobile`：要「企业员工手机号信息」权限。
   - 邮箱、手机号权限的开法：「钉钉开发者后台 > 企业内部开发 > 应用 > 权限管理 > 通讯录管理页面，勾选企业员工手机号信息和邮箱等个人信息，单击申请权限」。
   [已验证，同上]
- 这两步都用**应用（企业）access_token**，不用用户 token；用户在登录时不会看到这两项授权。[推断]
- 任务里提到的 `orgEmail`（v1.0 驼峰写法）本次没有查到对应的新版接口；上面是 `topapi` 旧接口的 `org_email`。[未验证]

### 3.3 谁设置，能不能改

- `email`（员工邮箱）：管理员通过「更新用户信息」可改，「员工邮箱是唯一的，企业内不能重复」。[已验证] [更新用户信息](https://open.dingtalk.com/document/orgapp/user-information-update)
- `org_email`：同一接口可改，「需满足以下条件，此字段才生效：员工的企业邮箱已开通」。[已验证，同上] → 是钉钉托管的企业邮箱，由管理员分配，也可以被管理员改。[推断]
- 改了 `org_email` 之后旧地址能否给别人、改的次数有没有限制，没查到。[未验证]
- 文档里没有任何一处说 `email` / `org_email` 经过验证。[已验证：上面几页均无此说明]

## 4. 对比

| 平台 | 字段 | 登录时能拿到？ | 权限 | token | 谁控制 | 已验证？ |
|---|---|---|---|---|---|---|
| 飞书 | `name` | 能，`user_info` | 无 | 用户 | 管理员；可放开给成员 | — |
| 飞书 | `avatar_*` | 能，`user_info` | 无 | 用户 | 管理员；可放开给成员 | — |
| 飞书 | `email`（工作邮箱） | 能，仅自建 | `contact:user.email:readonly` | 用户 | 管理员填写；可放开给成员 | **否**，官方明说未验证 |
| 飞书 | `enterprise_email` | 能，自建和商店都行；租户要开通飞书邮箱 | `contact:user.employee:readonly` | 用户 | 仅管理员；改后旧地址可转给他人 | 托管邮箱，等于租户背书 [推断] |
| 企业微信 | `name` | 多一次 `user/get` | 成员在可见范围 + 可信 IP | 应用 | 管理员 | — |
| 企业微信 | 头像 | 外部浏览器 Web 登录**拿不到**；客户端内 `snsapi_privateinfo` 才行 | 管理员勾字段 + 成员确认 | 应用 + `user_ticket` | 管理员 / 成员（需管理员放开） | — |
| 企业微信 | `email` | 同上 | 同上 | 同上 | 管理员填写 | 否（文档未提） |
| 企业微信 | `biz_mail` | 同上 | 同上 | 同上 | 管理员；最多改一次或不可改 | 托管邮箱 [推断] |
| 钉钉 | `nick` / `avatarUrl` | 能，`users/me` | `Contact.User.Read` | 用户 | 用户本人（钉钉账号） | — |
| 钉钉 | `email`（个人） | 能，`users/me` | `Contact.User.Read`（另需邮箱权限？[未验证]） | 用户 | 用户本人 | 不明 |
| 钉钉 | `name` / `email`（员工） | 多两次调用 | `qyapi_get_member` + 成员信息读 + 邮箱等个人信息 | 应用 | 管理员 | 否（文档未提） |
| 钉钉 | `org_email` | 多两次调用；租户要开通企业邮箱 | 成员信息读 | 应用 | 管理员 | 托管邮箱 [推断] |

## 对 Polaris 的建议

均为 [推断]。

- **只认「租户托管的企业邮箱」当 verified email**：飞书 `enterprise_email`、钉钉 `org_email`、企业微信 `biz_mail`。这三个地址都是租户开通的邮件服务里真实存在的邮箱，由管理员分配，成员不能自己改。管理员填写的 `email`（飞书工作邮箱、企业微信 `email`、钉钉员工邮箱）和钉钉的个人邮箱都不要当 verified：飞书官方明说未验证；其他两家没说验证过。
- **各类型具体做法**：
  - **飞书 / Lark**：`scope` 加 `contact:user.employee:readonly`，从同一次 `user_info` 读 `enterprise_email`（`email_verified=true`）、`name`、`avatar_url`。代价很小：不多调接口，自建、商店都支持；只是多一个权限要租户管理员审核。租户没开飞书邮箱时 `enterprise_email` 为空，就不给 `email`，不要退回去读 `email`。
  - **钉钉**：`name` 和 `org_email` 都要先 `getbyunionid` 再 `topapi/v2/user/get`，用企业 token。比现在多两次请求，还要缓存企业 token（同企业微信）。值得做，因为 `users/me` 的 `nick` 是个人昵称、`email` 是个人邮箱，都不是组织里的身份。没有 `org_email` 就不给 `email`。
  - **企业微信**：外部浏览器登录是主路径，在这条路上新自建应用拿不到任何邮箱和头像，只能多调一次 `user/get` 拿 `name`。所以一期**只给 `name`，不给 `email`**。要拿 `biz_mail`，就得在客户端内走 `snsapi_privateinfo`：管理员要勾字段，成员要点确认，扫码登录的用户还是拿不到。这件事等 [wecom-login.md](wecom-login.md) 里的「客户端内入口」做了再说。
- **email 只当资料，不当身份**：三家都允许管理员改企业邮箱，飞书还明说旧地址可以转给别人。所以 email 每次登录都刷新，不能拿它关联账号、找 User；锚点仍是各自的 ID。下游 Client（Grafana 等）如果按 email 匹配用户，地址被转给别人时会认错人。这一点要写进 Operator 文档。
- **名字和头像**：飞书 `name` / `avatar_url`、钉钉 `topapi` 的 `name` / `avatar`、企业微信 `user/get` 的 `name`，都可以每次登录刷新，不涉及验证问题。头像 URL 是平台 CDN 地址，是否长期有效没有查。[未验证]
- **实测时确认**：飞书不把 `contact:user.employee:readonly` 写进 `scope` 还会不会返回 `enterprise_email`；企业微信新自建应用的 `user/get` 有没有 `thumb_avatar`；钉钉 `org_email` 是否另要权限，`users/me` 的 `email` 是否另要邮箱权限。
