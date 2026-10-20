# Operator 是带标记的 User,管理端经 OIDC 登录

> 部分被 [ADR 0007](0007-rbac-on-api.md) 取代:"只做 operator 标记、不做角色"一节已改为 Management API 上的 Role。

Operator 不另建账号体系:每个 Operator 都是用户池中带 operator 标记的 User。管理端是内置的 First-party Application,经 Polaris 自己的 OIDC 登录,只允许带标记的 User 进入。为了让 Operator 不配置任何 Channel 也能登录,用户名成为第三种 Identifier(不验证、不能接收验证码、只能配合密码使用);密码登录开关从开 / 关改为三档,依次为关闭、仅 Operator(默认)、所有 User。首次启动时日志打印一次性 setup token,凭它在引导页设置第一个 Operator 的用户名和密码。"Operator 必须启用 2FA 或 Passkey"是开关,默认关闭。

## Considered Options

- **Operator 账号独立于用户池**(用户名 + 密码,管理端不经过 OIDC):不需要改身份模型,但要另写一套登录、会话和 2FA,管理端也享受不到经 conformance 测试的那条代码路径。
- **用未验证的邮箱当用户名**:会和日后通过验证码注册的同一邮箱冲突,破坏 Identifier 的唯一性。
- **用命令行创建首个 Operator**:Operator 不愿意部署后还要额外执行命令。

## Consequences

- 只有用户名的 User 丢了密码就无法找回。当前不提供后门,所有 Operator 都进不去时,只能直接改数据库;管理 CLI 以后另行设计。
- 引导页在第一个 Operator 创建后永久关闭,setup token 同时失效。
