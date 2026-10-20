# 角色挂在 API 上,并写入 access token

Polaris 除了认证,还负责基于角色的权限下发。每个 API 定义自己的 Permission(字符串)和 Role(Permission 的命名集合,支持自定义),User 在同一 API 上可以持有多个 Role,权限取并集。access token 按 RFC 9068 §2.2.3.1 携带 `roles` 和 `entitlements`(展开后的 Permission),只包含当前 `aud` 那个 API 下的;ID token 不携带。Polaris 的管理端本身就是一个内置 API,内置所有者、管理员、只读三个 Role,也允许自定义。因此管理员不再是一个标记,而是"在 Management API 上持有任一 Role 的 User"。组和组织架构不做;访问控制判断仍由业务后端自己完成。

本 ADR 取代 ADR 0006 中"只做 operator 标记、不做角色"的部分;0006 的其余内容(管理员是 User、经 OIDC 登录、用户名 Identifier、setup token 引导)仍然有效。

## Considered Options

- **只认证,授权全交给 Application**(原定范围):每个业务后端都要自建角色表和分配界面,同一个人的权限散落在各处。
- **角色挂在 Application 上**:但 access token 是发给 API 的,多个 Application 共用一个 API 时,角色会重复定义。
- **全实例一套角色**:不同 API 的权限会混在一起,令牌里会带上无关的权限。
- **固定内置角色,不能自定义**:实现简单,但满足不了业务 API 的需要。

## Consequences

- 权限变更要等 access token 过期才生效(最长 10 分钟)。
- 管理端权限和业务权限共用同一套机制,不需要两套实现。
- 需要角色与权限的管理界面,也可能需要供业务后端调用的 Management API(另立 ticket)。
