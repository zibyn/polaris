# Node SDK 管 Web 登录和校验 access token,Go SDK 只管校验

除了 KMP,Polaris 再出两个服务端 SDK,范围不同:

- **Node SDK**:
  - Web Application 登录:confidential client 走 OIDC 授权码流程,在集成方站点上挂 login、callback、logout、session 四个路由,登录状态存在 SDK 的会话 cookie 里;
  - API 后端:校验 access token,按 Entitlement 拦截请求。
- **Go SDK**:只做 API 后端校验 access token,外加校验 logout token。Go 写的 Web 应用登录用 `x/oauth2` + `go-oidc`,文档给示例。

两个 SDK 都不包 Management API,集成方继续用 OpenAPI 自己生成 client(#179);也不包直连认证 API,那是原生 App 用的,归 KMP SDK。Node SDK 不实现 Back-Channel Logout:Polaris 的 Session 一终止,挂在它下面的 refresh token 也跟着失效,SDK 发现 access token 过期去刷新时就会失败,于是清掉会话 cookie。因此退出最多滞后一个 access token 的寿命(10 分钟)。

## Considered Options

- **照 better-auth 做进程内认证库**:用户表、登录方式插件、自绘登录表单都放在集成方。可用户池在 Polaris(ADR 0032),登录也必须经 Polaris 完成,ADR 0034 还排除了嵌入式组件。better-auth 只借鉴接入体验:几行配置、挂一个 handler、调一次 `getSession()`。
- **Node SDK 实现 Back-Channel Logout**:退出能即时生效,但 cookie 签出去就收不回来,集成方得给 SDK 配一个存储,记录被踢掉的 `sid`,SDK 就不再零依赖。滞后 10 分钟对 First-party Application 够用,以后需要再加,做成可选存储即可。
- **SDK 顺带包 Management API**:等于把 #179 否决过的「手写 SDK」又带回来,还要逐个语言跟着 API 演进。
- **Go SDK 也做 Web 登录**:Go 里 `x/oauth2` + `go-oidc` 已经是事实标准,集成方的 Go 服务多是给 App、小程序用的 API 后端,再封一层增加的价值很小。

## Consequences

- Application 要用 Node SDK 登录,必须开启 refresh token;回调时拿不到 refresh token,SDK 直接报配置错误。
- Node SDK 的 logout 会跳到 RP-Initiated Logout,终止 Polaris 的浏览器 Session,同一浏览器里的其他 Application 也会在 10 分钟内退出。
- 权限按规范只看 `entitlements`,不看 `roles`;SDK 的 `Require` 要求列出的 Entitlement 全部持有。
- 「SDK 的会话 cookie」是 SDK 的实现细节,不是领域里的 Session,不写进 GLOSSARY。
