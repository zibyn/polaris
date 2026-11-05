# Management API 的 Role 是实例级信任,不按 Application 收窄

在 Management API 上持有 Role 的 M2M Application(集成方后台)看到、操作的是整个用户池,不能限定到「与某个 Application 相关的 User」。Management API 不加按 Application 划分的授权层,也不提供 `?application=X` 这样的筛选。集成方需要「只看自己的 User」时,在自己的 API 上建 Role,再用 list-users 的 `api` + `role` 过滤去查;需要真正隔离时,另起一个 Polaris 实例。

## Considered Options

- **按 Application 限定可见范围**:前提是有一个持久的「User 属于 Application」关系,而 Polaris 没有这个关系,现有的几种口径都有漏洞。「登录过」靠的是 Session 记录,User 登录一次之后就永远可见;「持有该 Application 的 API 上的 Role」只对要求持 Role 才能登录的 Application 有意义;「由它创建」覆盖不到自助注册的 User。调研过的十几家 SaaS 和开源平台(`docs/research/integration-modes-saas.md`、`docs/research/integration-modes-oss.md`)都没做这一层,最细只隔离到 organization、tenant 或 realm。
- **只做筛选,不做授权**(`GET /users?application=X`):还是得选一种「相关」口径对外承诺,上面的漏洞会变成 API 契约的一部分;而按 Role 过滤已经能覆盖这个需求。

## Consequences

- 给集成方的 M2M Application 授予 Management API Role,等同于把整个用户池托付给它。文档要讲明这一点,并鼓励只授予最小的 Permission(例如只给 `users:read`)。
- 后续的写操作、委派管理员等决定,都以「Management API 作用于整个用户池」为前提。
- 多租户仍然不在范围内,见地图「两种集成模式缺口规格」的 Out of scope。
