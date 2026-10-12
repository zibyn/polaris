# 分期路线

一期以首个接入方为锚:个人主体运营的 KMP 户外导航 App(iOS / Android),外加它的 Web 管理后台。微信系、一键登录等具体服务商不进任何一期;有资质的运营方需要时,按插件渐进接入。

## 一期(0.x):导航 App 能上线

| 领域 | 范围 |
|---|---|
| 服务端基础 | PG 与迁移、环境变量配置、主密钥加密、签名密钥生成与手动轮换、setup token 引导、清理任务 |
| 身份 | 手机号 / 邮箱 / 用户名三种 Identifier、登录即注册、不变式、换绑与解绑、注销、管理员对 User 的操作 |
| 认证 | 短信验证码(阿里云短信认证 Channel + Webhook Channel)、邮箱验证码(SMTP Channel + Webhook Channel)、密码登录开关 |
| 协议 | 裁剪后的 go-oidc:authorization code + PKCE、refresh 轮换与重用检测、JWKS、userinfo、revocation、RP-Initiated Logout;直连 challenge 端点(`/v1`);Session 模型;`amr` |
| RBAC | API / Role / Permission、`roles` / `entitlements` 进入 access token、Management API 及其内置 Role 与实时鉴权 |
| 安全与合规 | 发送限流与每日上限、ALTCHA PoW、失败锁定、审计日志、协议同意、数据留存、个人信息导出 |
| 界面 | 管理端(七组导航,见 [consoles.md](consoles.md#导航))、账号中心(单页)、托管登录页(`one-time-code` 标注) |
| 集成 | `user.deleted` webhook、KMP SDK、OpenAPI 文档与 SDK 行为说明 |
| 发布 | GHCR 镜像与二进制、compose 样例、部署文档、CI 中跑 conformance 回归 |

**完成标准**:
- 导航 App 的 iOS 和 Android 版经 KMP SDK,用短信或邮箱验证码登录成功;
- 导航管理后台经 OIDC 登录;业务后端用 JWKS 本地验签,并能读到 `roles`;
- conformance 三个计划在 CI 中全部通过;
- 用 compose 样例从零部署,到首次引导完成,不超过 15 分钟。

## 二期(0.x):安全增强与外部登录

- Passkey(托管页 conditional UI、直连 API 的 WebAuthn challenge、账号中心)**已实现**(#103–#111),含实例开关;KMP SDK 调用系统凭证 API **已实现**(#112,iOS 真机验证待做)。
- TOTP 2FA 与恢复码;"管理员必须启用 2FA 或 Passkey"开关(**已实现**,#79、#86;Passkey 落地后这个开关同时也认 Passkey,#108)。
- 动态生成 `/.well-known/` 文件(**已实现**,#105、#113):`apple-app-site-association`、`assetlinks.json`、`passkey-endpoints`、`change-password`。
- Provider 框架落地:通用 OIDC、通用 OAuth2、Apple(含注销回调),以及 Google、Microsoft、GitHub 三个具名供应商;管理端把它们收进独立的「认证源」分组(**已实现**,#87、#98、#99、#100)。
- `client_credentials` 与 M2M Application、默认 Role、Management API 对外文档 **已实现**(#115–#119)。
- 审计导出 CSV;主密钥轮换命令。

**完成标准**:
- 同一个 User 在 iOS 上添加 Passkey 后,能用 Passkey 登录;
- 开启 TOTP 后,验证码登录也要求输入 TOTP;
- 用 Google、Microsoft、GitHub 各登录成功一次;Microsoft 在 `common` 租户下的 issuer 校验也验证过。

## 三期(1.0):认证与发布

- 申请开源费用减免,以 1.0 版本在 www.certification.openid.net 提交 Basic OP、Config OP 与 RP-Initiated Logout 认证。
- 推送阿里云 ACR 镜像;补齐部署文档。

**完成标准**:拿到 OpenID 认证,发布 1.0。

## 以后再说

- 跨原生 App 共享 Session(倾向 Token Exchange):等出现第二个原生 App 时再定。
- Kotlin、Swift、TS SDK:按接入需求再做。
- 管理 CLI:单独设计。
- 微信系、一键登录、二次号检测、商业行为验证码:按插件接入。
