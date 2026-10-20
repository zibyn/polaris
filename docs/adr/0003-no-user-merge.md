# 不合并 User,外部身份不按邮箱自动关联

Polaris 永不合并两个 User。User 绑定一个已属于另一 User 的 Identifier 或 External Identity 时直接拒绝,要么先在另一个 User 上解绑 / 注销,要么改用那个 User。认证服务商返回的已验证邮箱或手机号也不会自动把新的 External Identity 关联到已有 User,只有已登录的 User 主动绑定才会关联。

## Considered Options

- **真正合并两个 User**:`sub` 是所有 Application 的主键,合并意味着每个 Application 都要处理"两个 `sub` 变一个"及其数据迁移;调研显示现有系统都不替业务方做这件事。
- **把标识从旧 User 移到新 User**(PlayFab ForceLink):不动数据,但旧 User 可能因此失去最后一个登录途径,而且移动本身也需要证明对两边的控制。
- **按已验证邮箱自动关联**:体验更顺,但各服务商"已验证"的标准不一,存在账号接管风险。

## Consequences

- 同一个人可能在池里留下两个 User,只能由他自己清理(注销其一)。
- 以后若要支持合并,必须设计 `sub` 变更通知,所有 Application 都要配合。
