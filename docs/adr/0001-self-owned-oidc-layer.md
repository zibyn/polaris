# 业务层与 OIDC 协议层均自研、自有

没有开源系统同时具备"不跳转的直连登录换标准令牌 + 微信全端与 unionid 归并 + 进程内插件",而 Go 的 OIDC 基础库都不健康(fosite 已并入 hydra、`zitadel/oidc` 无自定义 grant、`luikyv/go-oidc` 为单作者 v0.x)。因此 Polaris 的业务层与 OIDC 协议层都是自有代码:协议层从一份已认证实现起步并在仓库内自行维护,不在运行时依赖第三方 OIDC 库;JOSE / JWT 与密码学原语仍依赖成熟库,绝不手写。尽管按一人业余维护,协议层仍须通过 OpenID 认证(Basic OP + Config OP),首版起即在 CI 跑 conformance suite。

## Considered Options

- **Fork / 二次开发 Casdoor**:国内通道最全,但无"手机号 + 验证码 → 令牌"API、无插件模型,核心认证路径反复出现严重安全公告。
- **Ory Kratos + Hydra**:Kratos session 换不出 Hydra 令牌,两者均不支持微信。
- **Zitadel**:session 不能直接换 OIDC 令牌,不支持微信,且为 AGPL。
- **站在 Go OIDC 基础库上**:受上游停滞与扩展点缺失限制。

## Consequences

- 可复用 Apache-2.0 / MIT 代码(保留版权声明);排除 AGPL 代码,以免约束本项目许可证。
- Better Auth 只借鉴插件机制与数据模型;其 `oauth-provider` 未获认证,不作协议层参考。
