# Polaris 设计规格

Polaris 是开源、自托管的中心化身份服务:一个实例、一个用户池,服务部署它的运营方自己开发的全部 Application。它负责认证 User,并按 API 下发角色与权限;Application 不再各自处理认证。

本目录是可交付开发的规格,只写"是什么"。"为什么"见 `docs/adr/`,完整的决策过程见 [Polaris 设计规格](https://github.com/zibyn/polaris/issues/1) 地图下的各个 ticket。术语以仓库根目录 `GLOSSARY.md` 为准。

## 阅读顺序

| 文件 | 内容 |
|---|---|
| [architecture.md](architecture.md) | 部署形态、存储、插件、配置与密钥 |
| [identity.md](identity.md) | User、Identifier、External Identity、Credential 与账号生命周期 |
| [authentication.md](authentication.md) | 各种登录方式与第二因素 |
| [protocol.md](protocol.md) | OIDC 面、直连认证 API、令牌、Session |
| [rbac.md](rbac.md) | API、Role、Permission、Management API |
| [consoles.md](consoles.md) | 管理端与账号中心 |
| [security-compliance.md](security-compliance.md) | 限流、防刷、锁定、审计、协议同意、数据留存 |
| [clients.md](clients.md) | 客户端 SDK 与各端接入 |
| [operations.md](operations.md) | 部署、升级、发版、OpenID 认证 |
| [roadmap.md](roadmap.md) | 分期范围与完成标准 |

## 总体约束

- 单租户、单一用户池;同一个人跨 Application 是同一个 User。
- 中国大陆优先:一期为 +86 手机号验证码和邮箱验证码。其余认证服务商按插件渐进接入,本规格不逐个设计。
- 双面:原生 App 走直连认证 API(原生界面);Web 与需要标准协议的场景走 OIDC。两面共用同一个 `/token` 端点和同一套令牌。
- OIDC 协议层为自有代码(并入并裁剪 `luikyv/go-oidc`),必须通过 OpenID 认证(Basic OP + Config OP,RP-Initiated Logout)。
- 维护能力按一人业余计:凡认证要求以外的事项,一律取范围窄、依赖少的方案。

## 明确不做

组与组织架构、策略引擎;多租户 SaaS 与对外开放平台;嵌入式库形态;存量用户迁移;零表单入口与游客身份;设备授权流程(RFC 8628);逐个认证服务商的设计;风控与登录通知;身份证实名核验、未成年人保护、数据出境与等保测评;管理 CLI。各项理由见地图的 Out of scope 一节。
