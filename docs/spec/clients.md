# 客户端与接入

各端之间共享的契约是 HTTP API,不是代码。权威约定只有两份:OpenAPI 文档,以及一份 **[SDK 行为说明](../sdk-behavior.md)**(single-flight 刷新、refresh token 重用后的处理、登出)。

## SDK 清单

| SDK | 分期 | 形态 | 分发 |
|---|---|---|---|
| **KMP** | 一期 | 覆盖 iOS / Android | Maven Central |
| Kotlin | 后期 | 与 KMP 同源,单独发布 Android 产物 | Maven Central |
| Swift | 后期 | 纯原生手写(URLSession + Keychain) | 仓库根 `Package.swift`,以 git tag 分发 |
| TS 核心 | 后期 | React Native 与小程序共用,存储层可替换 | npm |

- **代码位置**:全部在主仓库 `sdk/` 下。
- **版本**:各 SDK 独立 semver,兼容关系用一条规则表达:"SDK x.y 支持服务端 API v1"。
- **Web 与业务后端**:不做官方 SDK。
  - Web 推荐使用已认证的 RP 库(如 `oidc-client-ts`);
  - 业务后端使用各语言主流的 JWT / JWKS 库;文档给出校验签名、`aud`、`typ` 和读取 `entitlements` 的示例。

## SDK 职责

SDK 只管协议,不带任何界面。原生登录界面由 App 自己实现。具体职责:

- 调用 challenge 端点:发码、验证码、密码;二期起还有 WebAuthn、TOTP、Provider 客户端令牌;
- 计算 ALTCHA PoW;
- 透传所同意的协议版本号;
- 兑换 code、刷新、登出、注销账号;
- **single-flight 刷新**:同一时间只有一个刷新请求,其余请求等待它的结果。服务端没有宽限窗口,不用 SDK 的集成方必须自己做到这一点;
- **令牌存储**:默认自己存(iOS Keychain、Android Keystore 加密存储),对外暴露存储接口,可以替换;
- **Passkey**(二期):调用系统凭证 API;在大陆 Android 上先探测能力,不可用时由 App 隐藏入口;要求 App 已声明关联(iOS 的 `webcredentials:`、Android 的 `assetlinks.json`,由管理端登记生成);
- **Provider 客户端令牌**:只转交令牌,不内置任何服务商的 SDK;Apple 转交的是 `authorization_code`(ADR 0011)。

## 接入要点

- **原生 App**:
  - 在管理端登记 Team ID + Bundle ID、包名 + 签名指纹,用于关联文件;
  - 验证码输入框标注 `.oneTimeCode`(iOS)或 `SMS_OTP`(Android);
  - 提供 App 内注销入口,调用直连 API 的注销接口。
- **Web 管理后台类 Application**:用 confidential 或 public + PKCE 的 OIDC 客户端,跳转到托管登录页。
- **业务后端**:
  - 在管理端登记为 API,定义 Permission 与 Role;
  - 本地验签 access token;
  - 可选配置 `user.deleted` webhook,用于删除业务数据。
