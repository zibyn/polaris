# 钉钉登录作为 Provider 类型

调研日期：2026-11-04。范围：让 User 用钉钉账号登录 Polaris，需要知道的钉钉开放平台协议细节、用户标识、应用类型和自测准备。不含钉钉作为 Channel（工作通知、机器人）。

**阅读须知**

- 一手来源只用钉钉开放平台官方文档（open.dingtalk.com）。这些页面在浏览器端渲染，抓取工具拿不到正文；正文取自文档站自己加载的内容文件 `https://icms-document.oss-cn-beijing.aliyuncs.com/zh-CN/dingtalk/<仓库>/topics/<slug>.html`，它和页面 `https://open.dingtalk.com/document/<仓库>/<slug>` 是同一份内容。下面引用的都是页面 URL。
- 标签含义：**[已验证]** 表示一手页面上有原文；**[未验证]** 表示没有找到一手出处，不要当事实用；**[推断]** 是本文作者根据原文作的判断。
- 钉钉文档新旧版本并存，同一件事常有好几页，说法也不完全一致（例如回调参数叫 `code` 还是 `authCode`）。下面在冲突处都会注明。这些地方要在实际对接时测出来，第 7 节的清单里列了要测的项。

## 1. 网页登录流程（登录第三方网站）

### 1.1 新旧两套接口

| | 新版（官方当前推荐） | 旧版（sns，已移入历史文档） |
|---|---|---|
| 授权端点 | `https://login.dingtalk.com/oauth2/auth` | `https://oapi.dingtalk.com/connect/qrconnect`（扫码）、`/connect/oauth2/sns_authorize`（账密/钉钉内） |
| 换 token | `POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken` | 无 token：`POST https://oapi.dingtalk.com/sns/getuserinfo_bycode` 用临时码直接换用户信息，请求要带 appSecret 算出的签名 |
| 用户信息 | `GET https://api.dingtalk.com/v1.0/contact/users/me` | 同上一步返回 `unionid` / `openid` / `nick` |

- 旧版「扫码登录第三方网站」「使用钉钉账号登录第三方网站」两页都写着：功能已升级，请优先参考新文档；该页于 2021-12-21 移入历史文档，功能暂不下线，已在用的应用可继续调用。**[已验证]** [扫码登录第三方网站](https://open.dingtalk.com/document/orgapp-server/scan-qr-code-to-log-on-to-third-party-websites)、[使用钉钉账号登录第三方网站](https://open.dingtalk.com/document/orgapp/use-dingtalk-account-to-log-on-to-third-party-websites)
- 旧版 `sns/getuserinfo_bycode` 的权限表上，企业内部应用和第三方企业应用都标为「不支持调用」，只有第三方个人应用标为支持；但旧版教程又让企业内部应用调用它。两处自相矛盾。**[已验证]**（两处原文都看到了）[根据sns临时授权码获取用户信息](https://open.dingtalk.com/document/development/obtain-the-user-information-based-on-the-sns-temporary-authorization)
- 结论：按新版实现，下文只讲新版。**[推断]**

### 1.2 第一步：授权请求

`GET https://login.dingtalk.com/oauth2/auth?...`，参数放在 query string 里，参数名是 snake_case。**[已验证]** [网页方式登录应用（第三方网站）](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)、[获取登录用户的访问凭证](https://open.dingtalk.com/document/development/obtain-identity-credentials)

| 参数 | 必填 | 原文要点 |
|---|---|---|
| `redirect_uri` | 是 | 须 urlencode，须与开发者后台登记的地址一致 |
| `response_type` | 是 | 固定值 `code` |
| `client_id` | 是 | 企业内部应用填 AppKey（Client ID），第三方企业应用填 SuiteKey |
| `scope` | 是 | 「当前只支持两种输入」：`openid`，或 `openid corpid`（另外返回登录时用户选择的组织 corpId） |
| `prompt` | **是** | 「值为consent时，会进入授权确认页」 |
| `state` | 否 | 跟随 authCode 原样返回；FAQ 建议用它防 CSRF |
| `org_type` | 否 | `management`：只列出用户有管理权限的组织（仅在 scope 含 corpid 时有效） |
| `corpId` | 否 | 指定用户要选的组织（仅在 scope 含 corpid 时有效） |
| `exclusiveLogin` / `exclusiveCorpId` | 否 | 专属账号登录，展示组织代码输入页 / 直接进入该组织的登录页 |

- `prompt` 在网页文档里是必填，只写了 `consent` 一个值；移动端 SDK 文档里它是选填，同样只有 `consent`。**[已验证]** [接入流程（移动端）](https://open.dingtalk.com/document/dingstart/mini-app-procedures-for-authorized-logon-to-ios-applications)
- 授权页上展示哪些授权信息，「以应用注册时配置的为准」：scope 不决定能拿到哪些用户字段，开发者后台给应用开通的权限才决定。**[已验证]**（同上两页）
- 回调结果：
  - 「获取登录用户的访问凭证」页写：成功时跳转到 `https://www.aaaaa.com/a/b?authCode=xxxx&state=dddd`，失败时跳转到 `...?error=yyyyyy&state=dddd`。**[已验证]** [获取登录用户的访问凭证](https://open.dingtalk.com/document/development/obtain-identity-credentials)
  - 更新的教程页写：回调形如 `?code=f85c6...&authCode=f85c6...`，「code 和 authCode 一致，取任一即可」。**[已验证]** [网页方式登录应用（第三方网站）](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)
  - 所以要读回调参数时，先取 `authCode`，没有再取 `code`。**[推断]**
- authCode 一次性有效，用过即失效。**[已验证]**（教程 FAQ Q3）
- 另有内嵌二维码方式：页面引入 `https://g.alicdn.com/dingding/h5-dingtalk-login/0.21.0/ddlogin.js`，调用 `window.DTFrameLogin`，参数同上；嵌二维码的页面必须和 `redirect_uri` 同源。**[已验证]**（同一教程）Polaris 托管登录页用的是整页跳转，不需要这种方式。**[推断]**

### 1.3 第二步：换 token

`POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken`，`Content-Type: application/json`，**JSON body，字段名是 camelCase**。**[已验证]** [获取用户token](https://open.dingtalk.com/document/development/obtain-user-token)

```json
{ "clientId": "dingxxx", "clientSecret": "1234", "code": "abcd", "grantType": "authorization_code" }
```

- `clientId` / `clientSecret`：企业内部应用传 AppKey / AppSecret，第三方企业应用传 SuiteKey / SuiteSecret，第三方个人应用传 AppId / AppSecret。**[已验证]**
- `grantType`：`authorization_code` 时必须带 `code`；`refresh_token` 时必须带 `refreshToken`。**[已验证]**
- client 认证方式：client 凭据写在 JSON body 里，既不是标准的 `client_secret_post`（那是 form），也不是 `client_secret_basic`。**[已验证]**（请求示例只有这一种写法）
- **请求体里没有 `redirect_uri`，也没有 `code_verifier`。** **[已验证]**（参数表只有 clientId、clientSecret、code、refreshToken、grantType 五个字段）
- 响应（camelCase）：`accessToken`、`refreshToken`、`expireIn`（示例为 7200）、`corpId`（「所选企业corpId」）。accessToken 有效期 7200 秒，refreshToken 有效期 30 天。**[已验证]**
- 只有授权时 scope 带了 `corpid`，响应里才有 `corpId`。**[已验证]** [常见问题](https://open.dingtalk.com/document/orgapp/common-errors)
- 这个接口要求的权限是 `open_app_api_base`（「获取钉钉开放接口用户访问凭证的基础权限」）。**[已验证]**
- 「获取登录用户的访问凭证」页的 HTTP 示例里多了一个 `x-acs-dingtalk-access-token` 请求头，「获取用户token」接口页的 curl 示例里没有这个头。换 token 时还没有用户 token，这个头应该是示例写错了。**[推断]**

### 1.4 第三步：取用户信息

`GET https://api.dingtalk.com/v1.0/contact/users/{unionId}`，`{unionId}` 填 `me` 表示当前授权人。**token 放在自定义请求头 `x-acs-dingtalk-access-token` 里，不用 `Authorization: Bearer`。** **[已验证]** [获取用户通讯录个人信息](https://open.dingtalk.com/document/development/dingtalk-retrieve-user-information)

- 需要的权限：`Contact.User.Read`（通讯录个人信息读权限）。**[已验证]**
- 响应字段（顶层，camelCase）：`nick`、`avatarUrl`、`mobile`、`openId`、`unionId`、`email`、`stateCode`。**响应里没有 userId。** **[已验证]**
- 第三方企业应用拿到的手机号是脱敏的（如 `155****3240`）；要拿手机号得另外申请个人手机号信息权限。**[已验证]**（同上；教程 FAQ Q2）

### 1.5 PKCE、OIDC

- **PKCE**：所有登录相关页面都没有出现 `code_challenge` / `code_verifier`，token 接口的参数表里也没有 `code_verifier`。**[已验证：文档里没有]** 所以钉钉不支持 PKCE。**[推断]** 授权请求里多带 `code_challenge` 会被忽略还是会报错，没有出处。**[未验证]**
- **OIDC**：
  - 网页登录相关页面都没有 discovery、`id_token`、`nonce`。**[已验证：文档里没有]**
  - 实测 `https://login.dingtalk.com/.well-known/openid-configuration` 返回 302 跳到 `www.dingtalk.com`；`https://login.dingtalk.com/oauth2/.well-known/openid-configuration` 返回 200，但 body 是 `null`；`https://api.dingtalk.com/.well-known/openid-configuration` 返回 `{"errcode":404,...}`。（2026-11-04 用 curl 探测，不是文档）
  - 钉钉文档里唯一的「OIDC」是[企业账号OIDC集成](https://open.dingtalk.com/document/orgapp/enterprise-account-oidc-integration)。那是钉钉专属版的企业账号在钉钉侧登录时，跳到企业自己的 IdP 去认证：钉钉是 RP，方向和我们相反。**[已验证]**
  - 移动端 SDK 有一个 `nonce` 参数（「字段值任意填写，授权登录后原样返回」），但它只是原样回显，没有 id_token 来承载它。**[已验证]** [接入流程（移动端）](https://open.dingtalk.com/document/dingstart/mini-app-procedures-for-authorized-logon-to-ios-applications)
- 结论：钉钉是「非标准的 OAuth2，没有 OIDC」，和 ADR 0013 讲的上游属于同一类：身份只来自拿 token 调 userinfo，没有上游签名。**[推断]**

## 2. 能否用现有通用 OAuth2 类型的预设覆盖

不能。对照 `internal/provider/oauth2/oauth2.go`，有五处不兼容：

| # | 我们的通用 OAuth2 | 钉钉 | 后果 |
|---|---|---|---|
| 1 | token 请求是 form，`grant_type` / `client_id` / `client_secret` / `code` / `redirect_uri` / `code_verifier` | JSON body，`grantType` / `clientId` / `clientSecret` / `code` | 钉钉读不到参数（JSON 字段名大小写也不同）[推断] |
| 2 | 从响应里读 `access_token` | 返回 `accessToken` | 必然报「token endpoint: no access_token」[推断，依据 §1.3 的响应示例] |
| 3 | userinfo 请求带 `Authorization: Bearer <token>` | 请求头 `x-acs-dingtalk-access-token: <token>` | 鉴权失败 [推断] |
| 4 | 回调里读 `code` | 新文档有的写同时带 `code` 和 `authCode`，有的只写 `authCode` | 只读 `code` 有风险 [推断，依据 §1.2] |
| 5 | AuthURL 不带 `prompt`，带 `code_challenge` | `prompt=consent` 是必填参数；不支持 PKCE | 缺了 prompt 可能被拒；PKCE 不起作用 [推断] |

能直接沿用的部分：userinfo 是顶层 JSON，ID 字段（`unionId`）是字符串；scope 固定为 `openid`；`state` 原样回传；用户 ID 字段写死在预设里也没问题。**[推断]**

要让通用类型兼容钉钉，就得把 token 请求格式、响应字段名、token 放在哪个请求头、回调参数名都做成可配置项。ADR 0013 的取舍正是「差异只是三个 endpoint 加一个字段名」，钉钉不属于这种情况。**[推断]**

## 3. 用户标识

| 标识 | 唯一范围 | 会不会变 | 新版网页登录能否直接拿到 |
|---|---|---|---|
| `userId`（staffId） | 一个企业内唯一 | 「创建后不可修改」 | 不能。userinfo 不返回它；要用企业 access_token 调 unionid→userid 接口 |
| `unionId` | 一个**开发者企业账号**（钉钉开放平台账号）内唯一，覆盖该账号下的所有应用 | 「唯一且不变」，例外见下 | 能。userinfo 返回 `unionId` |
| `openId` | 一个**应用**内唯一 | 文档没有说 | 能。userinfo 返回 `openId` |

出处：

- userId：「企业内每个员工都有唯一的UserId，创建后不可修改」。**[已验证]** [基础概念](https://open.dingtalk.com/document/orgapp/basic-concepts-beta)
- unionId 的范围，几处原文：
  - 「unionid是员工在当前开发者企业账号范围内的唯一标识，由系统生成：同一个企业员工，在不同的开发者企业账号下，unionid是不相同的。在同一个开发者企业账号下，unionid是唯一且不变的，例如同一个服务商开发的多个应用，或者是扫码登录等场景的多个App账号」；同页参数说明里还有「系统生成，不会改变」。**[已验证]** [根据unionid获取用户userid](https://open.dingtalk.com/document/development/query-a-user-by-the-union-id)
  - 「用户在当前钉钉开放平台账号范围内的唯一标识，同一个钉钉开放平台账号可以包含多个开放应用」。**[已验证]** [基础概念](https://open.dingtalk.com/document/orgapp/basic-concepts-beta)
  - 「小钉同时在三个企业内，共用了同一个第三方企业应用……unionId是相同的」：unionId 不随用户所在的组织变。**[已验证]** [常见问题](https://open.dingtalk.com/document/orgapp/common-errors)
- openId：旧版接口对它的说明是「用户在当前开放应用内的唯一标识」，对 unionid 的说明是「用户在当前开放应用所属企业的唯一标识」。新版 userinfo 只列出了 `openId` 字段，没有说明范围。**[已验证]** [根据sns临时授权码获取用户信息](https://open.dingtalk.com/document/development/obtain-the-user-information-based-on-the-sns-temporary-authorization)；新版 openId 和旧版同义。**[推断]**
- **unionId 会变的例外**：钉钉提供「根据原unionId查询迁移后的unionId」和反向查询两个接口，用于「普通帐号迁移为专属帐号后」。也就是说，普通钉钉账号迁移成企业专属账号后，unionId 会变成另一个。这两个接口只支持企业内部应用和第三方企业应用，需要 `Contact.OrgAccountMigration.Read` 权限。**[已验证]** [根据原unionId查询迁移后的unionId](https://open.dingtalk.com/document/development/the-union-id-that-you-want-to-query-you-can)、[根据迁移后的unionId查询原unionId](https://open.dingtalk.com/document/development/query-the-original-union-id-based-on-the-union-id)

各自需要的权限：

- `unionId` 和 `openId`：调 `/contact/users/me` 需要 `Contact.User.Read`。**[已验证]**
- 新版教程的前置条件写的是申请 `Contact.User.mobile` 和 `Contact.User.Read` 两个权限点，其中 mobile 是为了取手机号。**[已验证]** [网页方式登录应用](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)
- 只取 unionId 时，`Contact.User.Read` 一个就够。**[推断]**
- `userId`：要用企业 access_token 调 `POST https://oapi.dingtalk.com/topapi/user/getbyunionid`，需要成员信息读权限 `qyapi_get_member`。**[已验证]** [根据unionid获取用户userid](https://open.dingtalk.com/document/development/query-a-user-by-the-union-id)

**适合做 External Identity 锚点的是 `unionId`。** **[推断]** 理由：

- 新版网页登录直接返回它，而且明文写了不变。
- 它的范围是开发者账号，不是单个应用：admin 在同一个钉钉组织里换一个应用（换 client_id），锚点不受影响。openId 是应用级的，一换应用就全部变成新人。
- userId 拿不到，而且只在一个组织内有意义。
- 代价是「普通账号迁移为专属账号」时 unionId 会变，这时会变成一个新的 External Identity。Polaris 不处理这种情况，用户重新绑定即可。

## 4. 应用类型

| 类型 | 谁能开发 | 谁能登录 | 门槛 |
|---|---|---|---|
| 企业内部应用 | 组织管理员给了开发者权限的成员 | **只有本组织成员** | 有一个钉钉组织即可；发布要管理员审批，选「仅我可见」时不需要 |
| 第三方企业应用 | 已完成产品方案商认证的组织的开发者 | 开通了这个应用的企业的成员 | 产品方案商入驻：钉钉指数 600、高级认证、20 人、保证金、15% 佣金等 |
| 第三方个人应用 | 产品方案商的开发者 | 钉钉个人用户 | 形态只有小程序 |

- **企业内部应用只允许本组织成员登录**，原文：「组织隔离：企业内部应用仅支持本组织员工登录，天然防止跨组织访问」；「内部应用不支持跨组织授权登录，仅限本组织内用户使用」；FAQ Q1 还写：如果要支持多企业用户，请用第三方企业应用。**[已验证]** [网页方式登录应用（第三方网站）](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)
- 应用类型表：企业内部应用的使用者是「安装了该应用的企业内部人员」；第三方企业应用的使用者是「购买开通该三方应用的企业内部人员」；第三方个人应用的使用者是「钉钉的个人用户」，支持的能力只有小程序。**[已验证]** [应用类型介绍](https://open.dingtalk.com/document/orgapp/application-types)
- 开发者身份：开发第三方企业应用，「你的企业组织必须完成产品方案商认证」。**[已验证]** [成为钉钉开发者](https://open.dingtalk.com/document/org/become-a-dingtalk-developer)
- 产品方案商入驻的门槛（钉钉指数 600 分、高级认证、通讯录 20 人、人工审核、保证金、约 15% 佣金）只来自搜索摘要，正文没有核对。**[未验证]** [入驻流程](https://open.dingtalk.com/document/operation-specification/joinPROCESS)、[保证金制度](https://open.dingtalk.com/document/isvapp/deposit-requirement)、[平台收费规则](https://open.dingtalk.com/document/isvapp/platform-charging-rules)
- 发布：「如果你不是企业管理员，发布应用时需要企业管理员审批，选择发布仅我可见则无需管理员审批」。**[已验证]** [网页方式登录应用](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)
- 不属于任何组织的个人钉钉用户，能否通过新版网页登录登进来：
  - 企业内部应用不行。**[已验证]**（见上）
  - 第三方个人应用的 AppId 能否用在 `login.dingtalk.com/oauth2/auth` 上：token 接口写了支持第三方个人应用的 AppId，但网页登录文档里 `client_id` 只列了 AppKey 和 SuiteKey。**[未验证]**
  - 旧版 sns 网页登录写着「此功能与应用类型无关」「如果扫码用户是外部用户需企业自行处理」，所以旧版大概可以让任何钉钉用户登录。**[推断]** 但旧版已经是历史文档。
- 企业内部应用是否收费：没有找到收费说明。**[未验证]** 创建钉钉组织是否免费：没有找到出处。**[未验证]**
- 对 Polaris 的含义：自建部署场景下，现实的选择是 Operator 在自己的组织里建一个企业内部应用，**钉钉登录只覆盖本组织员工**。要面向任意钉钉用户（ToC），需要产品方案商资质，或者走旧版接口。**[推断]**

## 5. 钉钉客户端内打开网页，以及原生 App

### 5.1 钉钉内 H5（网页应用，原 H5 微应用）免登

- 流程：
  1. 前端调用 `dd.requestAuthCode({corpId, clientId})` 拿到免登码，有效期 5 分钟，只能用一次。
  2. 服务端用**应用的** access_token（企业内部应用的 accessToken）调用 `POST https://oapi.dingtalk.com/topapi/v2/user/getuserinfo`，请求是 form，参数为 `access_token` 和 `code`。
  3. 返回 `userid`、`unionid`、`associated_unionid`、`sys`、`sys_level` 等。

  **[已验证]** [企业内部网页应用免登](https://open.dingtalk.com/document/development/enterprise-internal-application-logon-free)、[通过免登码获取用户信息](https://open.dingtalk.com/document/development/obtain-the-userid-of-a-user-by-using-the-log-free)、[requestAuthCode](https://open.dingtalk.com/document/development/jsapi-request-auth-code)
- requestAuthCode 只能在钉钉端内用：「免登操作需要在钉钉端内实现，端外无法正常调用免登组件」。第三方个人应用不能调用它。**[已验证]**（同上）
- 这和网页登录是**两条不同的路**：
  - 免登码不走 `userAccessToken`，而是用应用 token 调 topapi。
  - 这一步还需要 `qyapi_base` 权限，和应用凭证（client_id/secret 拿企业 token）。

  **[已验证]**
- 免登返回的 `unionid` 和网页登录 userinfo 里的 `unionId` 是不是同一个值：两边都叫 unionid，而且同一应用属于同一开发者账号，所以应该相同。**[推断]**
- 在钉钉内置浏览器里跳转到 `login.dingtalk.com/oauth2/auth` 走重定向流程，能不能用、会不会免确认：没有出处。**[未验证]**
- 旧版有「钉钉内免登第三方网站」：`sns_authorize?scope=snsapi_auth`，只支持移动端钉钉，属于历史文档。**[已验证]** [钉钉内免登第三方网站](https://open.dingtalk.com/document/orgapp/logon-free-third-party-websites)
- 对 Polaris 的含义：托管登录页是一个普通网页，一期在钉钉里打开也走同一个重定向流程，先实测（见第 7 节）。真要做端内无感免登，那是「App 直接提交 code」，形态像 ClientToken，但要拿的是应用 token，不是用户 token。可以先不做。**[推断]**

### 5.2 原生 App（iOS / Android / 鸿蒙）

- 钉钉登录 SDK 由钉钉 App 拉起授权，用户确认后回到开发者的 App，带回 `authCode`（Android 的 `DDAuthConstant.CALLBACK_EXTRA_AUTH_CODE`，iOS 新 SDK 的 `authResp.authCode`），由「业务方服务端」用 authCode 调 `userAccessToken` 换用户 token，再调用户信息接口。**[已验证]** [接入流程（移动端）](https://open.dingtalk.com/document/dingstart/mini-app-procedures-for-authorized-logon-to-ios-applications)
- 移动端钉钉登录「只提供原生的登录方式，需要用户安装钉钉客户端」。**[已验证]** [钉钉登录介绍](https://open.dingtalk.com/document/orgapp/webapp-mobile-application-access)
- SDK 参数：
  - `appId`：Client ID / AppKey。
  - `redirectUri`：「仅用于校验域名是否一致，不会跳转」。
  - `responseType=code`、`scope`（`openid` 或 `openid corpid`）、`nonce`、`state`、`prompt=consent`。

  **[已验证]**（同上）
- 旧版 iOS 文档（`DTAuthorizeResp.accessCode`）仍然让服务端调 `sns/getuserinfo_bycode`。**[已验证]** [iOS应用授权登录接入流程](https://open.dingtalk.com/document/mobile-app-guide/procedures-for-authorized-logon-to-ios-applications) 以新文档为准。**[推断]**
- 服务端要做的事：App 把 authCode 交给 Polaris，Polaris 做和网页回调完全一样的两步，换 token 后取 `unionId`。换 token 不带 `redirect_uri`，所以服务端不必知道 App 填的 redirectUri。**[推断，依据 §1.3 的参数表]** 这正好对得上 `provider.ClientToken`（「App 自己登录，把 Provider SDK 给它的东西交给 direct auth API」）。
- App 侧另外要在开发者后台登记 Bundle ID / 包名和签名，这些和服务端无关。**[已验证]**（同上）

## 6. 重新认证、撤销、解绑

- 强制重新登录：授权端点只有 `prompt=consent` 一个值，作用是「进入授权确认页」，没有 `prompt=login`、`max_age`；token 和 userinfo 响应里也没有 `auth_time`。**[已验证：文档里没有]** 钉钉记着登录状态时，`prompt=consent` 是否仍要扫码或输入密码：**[未验证]**，要实测。
- 所以钉钉和 ADR 0013 里的 OAuth2 上游一样，重新认证只能证明「此刻仍控制这个钉钉账号」，应当实现 `NoReauthPrompt`。**[推断]**
- 撤销 token、解绑：在登录、token、FAQ 相关页面里都没有找到撤销用户 accessToken / refreshToken 或解除用户授权的接口；搜索只找到与此无关的「撤销审批实例」「取消企业授权」等。**[未验证：没有找到]**
- 因此不实现 `Unlinker`，`Identity.Token` 也不必保存。**[推断]**

## 7. 自测准备清单

在动手对接前准备：

1. **一个钉钉组织**，自己是主管理员，或者有开发者权限的子管理员。只有这两类人能进开发者后台。[基础概念](https://open.dingtalk.com/document/orgapp/basic-concepts-beta)、[成为钉钉开发者](https://open.dingtalk.com/document/org/become-a-dingtalk-developer)
2. **另一个钉钉账号**，用来测非本组织成员会被拒；最好还有一个已加入本组织的第二个账号。
3. 开发者后台 → 应用开发 → 企业内部应用 → 钉钉应用 → **创建应用**，填名称和描述；在「基础信息 > 凭证与基础信息」里记下 **Client ID（AppKey）** 和 **Client Secret（AppSecret）**。[网页方式登录应用](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)
4. 「开发配置 > 安全设置 > **重定向URL（回调域名）**」：填 Polaris 的 `CallbackURL`，即 `<issuer>/login/providers/<id>/callback`。
   - 本地可以用 `http://localhost:<port>`，生产环境必须是 HTTPS。
   - 多个地址用逗号分隔。
   - 不要带 `#`。

   [同上](https://open.dingtalk.com/document/development/tutorial-obtaining-user-personal-information)、[接入流程（移动端）](https://open.dingtalk.com/document/dingstart/mini-app-procedures-for-authorized-logon-to-ios-applications)
   - 文档对「回调域名」和「回调地址」用词混用，到底按域名匹配还是按完整 URL 匹配，要实测（见第 9 步）。
5. 「权限管理」里开通：
   - **`Contact.User.Read`（通讯录个人信息读权限）**：必须。
   - `open_app_api_base`：换用户 token 的基础权限，确认默认已开。
   - 不要开 `Contact.User.mobile`，我们不需要手机号。
6. 「应用发布 > 版本管理与发布」：创建版本 → 可见范围 → 发布；可见范围可以选「仅我可见」，这样不用管理员审批。可见范围会不会挡住其他成员登录，要实测。
7. 手工走一遍：
   1. 浏览器打开 `https://login.dingtalk.com/oauth2/auth?redirect_uri=<urlencode>&response_type=code&client_id=<AppKey>&scope=openid&state=<随机>&prompt=consent`。
   2. 从回调地址拿到 code。
   3. `curl -X POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken -H 'Content-Type: application/json' -d '{"clientId":"..","clientSecret":"..","code":"..","grantType":"authorization_code"}'`。
   4. `curl https://api.dingtalk.com/v1.0/contact/users/me -H 'x-acs-dingtalk-access-token: <accessToken>'`。
8. 实测项（文档没写清的地方），每项记下结果：
   - [ ] 回调 query 里是 `code`、`authCode` 还是两个都有；用户拒绝授权时 `error` 的取值。
   - [ ] 授权请求多带 `code_challenge` / `code_challenge_method` 时会不会报错；不带 `prompt` 会不会报错。
   - [ ] token 接口出错时的 HTTP 状态码和 body 形状（是不是 `{"code":..,"message":..}`）。
   - [ ] 非本组织账号登录时在哪一步被拒、提示什么。
   - [ ] 同一账号连续登录两次：第二次 `prompt=consent` 是否还要扫码或确认（关系到重新认证能证明什么）。
   - [ ] 在钉钉 App 内置浏览器里打开 Polaris 登录页，走重定向流程能否完成。
   - [ ] 同一组织另建第二个应用，用同一账号登录，对比 `unionId` 是否相同、`openId` 是否不同，以验证第 3 节的范围。
9. redirect_uri 匹配规则：用登记域名下的另一个路径试一次，看是否被拒。

## 8. 对 Polaris 的建议

**做成独立类型包 `internal/provider/dingtalk`，不要做成通用 OAuth2 的预设。** **[推断]**

- 不做成预设的理由：差异有五处（JSON token 请求、camelCase 响应、自定义 token 请求头、回调参数名、必填 prompt、不支持 PKCE），见第 2 节。为了钉钉给通用类型加四五个开关，会违背 ADR 0013「差异只是 endpoint 加字段名」的前提。
- 独立包的写法：照 `github` 包的写法，把 endpoint 放成包级变量（`Login = "https://login.dingtalk.com"`、`API = "https://api.dingtalk.com"`），方便测试指向 fake；代码量大约是 oauth2 包里 `AuthURL` / `exchange` / `subject` 三个函数各改几行。
- `fetch`（保留数字原样、限长、非 200 报错）可以从 oauth2 包导出后复用，免得再抄一份。
- 实现的接口：
  - `Redirect`：
    - `AuthURL` 带 `response_type=code`、`client_id`、`redirect_uri`、`state`、`scope=openid`、`prompt=consent`；不带 PKCE 和 nonce，理由同 oauth2 包：没有 id_token，靠 state 加一次性 code。
    - `Callback` 先读 `authCode`，没有再读 `code`；有 `error` 时报错。
  - `NoReauthPrompt`：钉钉没有强制重新登录的参数。
  - 先不做 `ClientToken`。等真有原生 App 要接钉钉 SDK 时再加：它和 `Callback` 共用「authCode → token → unionId」，代码几乎没有增量。
  - 不做 `Unlinker`：没有撤销接口。
- **锚点：`unionId`。** 写死在类型里，不让 admin 选，理由同 GitHub 写死 `id`。不要用 `openId`：换一个应用就全部变成新人。也不要用 userId：拿不到。
- **配置字段：**
  - `client_id`（Label「Client ID（AppKey）」）。
  - `client_secret`（Secret）。
  - 都不必 Immutable：unionId 的范围是开发者组织，同一组织内换应用不影响锚点。
  - 换到**另一个钉钉组织**的应用，unionId 会全部变。可以在 `client_id` 的 Help 里写一句「换成其他组织的应用会让已有的钉钉绑定全部失效」，不必为此加 Immutable 字段。**[推断]**
  - 不加 `scope`、`corp_id`、`prompt` 这类可配置项：企业内部应用由钉钉自己限制只有本组织成员能登录，Polaris 不用再校验 corpId。**[推断，依据 §4 的原文]**
- 管理台说明里要写明：钉钉 Provider 只能让「建应用的那个组织」的成员登录；要面向所有钉钉用户，需要钉钉的产品方案商资质，一期不支持。
- 写 ADR 时值得记下的取舍：钉钉和 OAuth2 上游一样没有签名背书，重新认证打了折扣；锚点 unionId 在「普通账号迁移为专属账号」时会变，Polaris 不处理这种情况。
