# 不做可嵌入组件,账号中心只靠普通链接进入

Polaris 不提供嵌进集成方页面的登录或资料组件(前端组件库或 iframe),也不新增第三种集成模式;托管页继续 `frame-ancestors 'none'`。Application 把 User 送进账号中心就是一个普通链接 `{issuer}/account?client_id=<id>`:User 本就经 Polaris 登录,有会话即免登录进入,会话过期就照常再登录一次。带 `client_id` 时账号中心套用该 Application 的品牌,并在它填了「首页地址」时显示「返回 <Application 名>」。

## Considered Options

- **可嵌入组件**(Clerk `<UserProfile/>`、Descope User Widgets、WorkOS Widgets):要长期维护一套前端 SDK,放开 `frame-ancestors`,处理跨站 cookie 或短期 token,在别人页面里继承样式;换来的只是省一次跳转,托管账号中心已能完成同样的事。有组件的都是商业 SaaS,开源平台基本没有。
- **后端生成一次性链接**(Kinde self-serve portal):解决的是「User 在认证服务那里没有会话」,而 Polaris 下 User 总是经 Polaris 登录;它还要一个能代 User 登录的凭据,多出一个冒充面。
- **返回地址用 `redirect_uris` 或 `post_logout_redirect_uris`**:前者是 OIDC 回调,不带 code 打开会报错;后者语义是「退出后去哪」。故新增可选的首页地址字段(相当于 OIDC 注册里的 `client_uri`)。
- **收任意 return URL 参数**:是开放重定向;返回地址只取 Application 登记的首页地址。

## Consequences

- Application 新增可选「首页地址」,校验同 redirect URI(https,localhost 例外);不填则账号中心不显示返回入口。
- 未知或不存在的 `client_id` 按没带处理:用实例品牌、无返回入口,不报错。
- 集成指南为托管集成模式加一节:账号中心链接、退出链接与 Back-Channel Logout 的配法。
