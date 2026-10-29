# Polaris

为自有应用提供统一认证的中心化身份服务:一个用户池,所有应用共用,应用自身不再处理认证复杂度。

## Language

**Polaris**:
独立部署的中心化身份服务,所有 Application 的 User 身份都由它持有和验证。
_Avoid_: 认证库, 认证框架, SSO 平台

**管理员**(Admin):
在 Management API 上持有任一 Role 的 User,负责配置登录方式、通道与 Application;部署实例的人即首个所有者。旧称 Operator。
_Avoid_: Operator, 站长, 租户

**User**:
一个自然人在 Polaris 中的唯一账号,跨所有 Application 是同一个。
_Avoid_: 账户, 会员, 成员

**待激活**:
管理员创建、尚未接受邀请或首次登录改密的 User 状态。能登录,但拿不到任何令牌,只能改密码或注销。
_Avoid_: 未激活, 待验证, 待确认

**邀请**(也写作**注册邀请**):
管理员为某个 User 生成的一次性链接,让本人设置密码并激活账号;7 天内有效,只发往邮箱。
_Avoid_: 邀请码, 激活邮件, 注册链接

**开放注册**:
实例是否允许池外的人通过登录自动成为 User;关闭后,新 User 只能由管理员创建或邀请。
_Avoid_: 自助注册, 注册开关, 仅邀请

**Application**:
在 Polaris 注册的一个接入方:委托 Polaris 认证 User(App、小程序或 Web 端),或以自己的身份调用 API(M2M Application)。
_Avoid_: Client, 租户, 项目

**First-party Application**:
由该实例的运营方自己开发和运营的 Application;当前所有 Application 都属于此类。
_Avoid_: 内部应用, 自有客户端

**M2M Application**:
不代表任何 User、以自己的身份调用 API 的 Application(如业务后端、定时任务),没有登录界面;只调用它的默认 API,也只在这个 API 上持有 Role(Management API 上不能持有「所有者」)。要调多个 API 就建多个 M2M Application。
_Avoid_: 服务账号, 机器账号, 客户端凭证应用

**API**:
管理员登记的一个受保护业务后端,以 API 标识符区分;Polaris 签发给 Application 的 access token 指明它供哪个 API 使用,多个 Application 可共用同一个 API。
_Avoid_: Resource Server, 资源, 后端服务

**API 标识符**:
区分 API 的字符串(如 `https://api.example.com`),即 access token 的 `aud` 值,创建后不可改。
_Avoid_: 标识, Identifier, audience

**默认 API**:
每个 Application 各自设定的一个 API,它拿到的 access token 都以其 API 标识符为 `aud`;对应 RFC 9068 §3 的 default resource indicator。一期不支持 RFC 8707 `resource` 参数,所以它也是该 Application 唯一的 API。不同于 Logto、Auth0 的同名设置,它不是整个实例共用一个。
_Avoid_: Default Audience, 目标 API, 资源

**Session**:
一个 User 在一台设备或一个浏览器上的一次登录;App 中由 refresh token 承载,浏览器中由 cookie 承载,终止它即让该设备下线。
_Avoid_: 登录态, 会话令牌, 设备

**闲置时长**:
Session 多久没有活动就失效;每次活动重新计时。
_Avoid_: idle timeout, 空闲超时

**寿命上限**:
Session 距 User 上次证明身份(登录或重新认证)最多多久必须重新登录,不因活动而延长;偷到 refresh token 的人无法重新认证,所以续不了期。
_Avoid_: absolute lifetime, max lifetime, SSO Session Max, 绝对寿命

**Identifier**:
User 用来登录的手机号、邮箱或用户名,在用户池内唯一;手机号和邮箱必须已验证、能接收验证码,用户名不验证、只能配合密码使用。
_Avoid_: 账号, 用户名, 联系方式

**用户资料**(Profile):
User 对外展示的昵称和头像,跨所有 Application 是同一份;不唯一、不验证、不能用来登录。昵称不是用户名:用户名是 Identifier。
_Avoid_: 个人信息, 身份, 用户名

**External Identity**:
某个 Provider 认定的一个用户(Provider + 其侧用户 ID,如微信 openid、Apple `sub`),绑定在某个 User 上。
_Avoid_: 社交账号, 第三方账号, Identity

**Credential**:
User 持有、用于证明身份的秘密,如密码、Passkey、TOTP、恢复码;本身不能定位 User,须配合 Identifier 或由设备提供。
_Avoid_: 密钥, 因子

**Passkey**:
User 保存在设备或密码管理器里的一把 Credential,只对 Polaris 的域名有效;登录时由设备提供,不用先输 Identifier,设备每次都要求生物识别或 PIN,所以本身就满足两步验证。只能由已登录的 User 添加,不能用来注册;一个 User 可以有多把。
_Avoid_: 通行密钥, 安全密钥, WebAuthn 凭证, FIDO 凭证

**登录途径**:
User 能用来登录的一条路径:手机号、邮箱、用户名(须配合密码),或已启用 Provider 的 External Identity。Passkey 是 Credential,保存在设备或密码管理器里、可能随之丢失,不算登录途径。
_Avoid_: 认证途径, 登录手段, 账号方式

**两步验证**(2FA):
User 自愿开启的状态:开启后,除 Passkey 外,任何第一因素登录都还要输入 TOTP 或一个恢复码。
_Avoid_: MFA, 二次验证, 双因素认证(界面和文档里);协议值 `amr` 的 `mfa` 和审计事件名 `mfa.*` 是标识符,保留不改

**恢复码**:
开启两步验证时生成的一组一次性 Credential,每个可代替一次 TOTP,供丢失验证器时使用。
_Avoid_: 备用码, 救援码, 备份码

**Channel**:
把验证码送达 Identifier 的外部投递服务(短信或邮件),由管理员选择并配置;每种 Identifier 同时只启用一个。
_Avoid_: 网关, 短信服务商, 发送器

**Provider**:
管理员添加的一个外部认证服务(如"Google"、"Apple"、"公司 Keycloak"),替 Polaris 证明"这是谁",认证结果是一个已验证的 Identifier 或一个 External Identity;各 Provider 的 External Identity 互不相通。
_Avoid_: Provider 实例, 社交登录, IdP, 第三方登录, 认证服务商

**Provider 类型**:
一种 Provider 的实现(如通用 OIDC、Apple、微信),决定它要哪些配置、支持哪种交互形态;同一类型可添加多个 Provider。
_Avoid_: 连接器, 驱动

**Permission**:
某个 API 定义的一项可授予的能力,以字符串表示(如 `track:write`)。
_Avoid_: 权限点, scope, 授权

**Role**:
某个 API 上一组 Permission 的命名集合,分配给 User 或 M2M Application;同一 API 上可持有多个 Role。
_Avoid_: 用户组, 身份, 职位

**Management API**:
Polaris 自带的内置 API,管理 User、Application、Role 与配置;管理端界面和业务后端都通过它操作,权限由其上的内置 Role(所有者、管理员、只读)或自定义 Role 决定。
_Avoid_: 管理端 API, Admin API, 后台接口
