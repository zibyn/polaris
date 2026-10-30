# identity 的公开面不暴露 sqlc 类型

identity 的导出方法不再出现 sqlc 生成类型:调用方只认识 identity 的参数和返回值。但 identity 不接管全部 User 读写——management 保留自己的控制台读模型(用户列表/详情、角色、2FA、邀请),以及 applications、roles、settings、audit、sessions 等非 User 查询。

边界按不变式划,不按表划:identity 拥有执行身份不变式的写操作(Identifier、Credential、External Identity、登录途径、最后一个所有者);其他模块拥有各自的读模型与领域查询。

## Considered Options

- **最小:只改 `management.replaceIdentifier`**:diff 最小,但 identity 的公开面继续暴露两个 sqlc 类型。
- **User 聚合:identity 接管全部 User 读写**:seam 最彻底,但会和「User 状态收进 identity」「所有者守卫吸收 mutation」两项改动重叠;而且 management 的读模型是控制台专用的(角色、2FA、邀请),搬进 identity 会让 identity 认识控制台。
- **字面禁止 sqlc:management 不再 import sqlc**:需要把 applications、roles、settings、audit、sessions 全部拆成独立模块,远超本次目的。

## Consequences

- `OtherLoginPath` 变成 `(*Store).OtherLoginPath(ctx, sub)`,原来的纯函数不再导出;management 的 `putSettings` 不再接触 `sqlc.LoginPathsRow`。
- `RemoveExternalIdentity` 返回 `(subject string, sealedToken []byte, err error)`,不再返回 `sqlc.RemoveExternalIdentityRow`。
- `management.replaceIdentifier` 改调 `identity.Store.ReplaceIdentifier`,删掉第二条写同一张表的调用。
- `ReplaceIdentifier`、`LockOwners`、`CountOwners` 从 `management.sql` 搬到 `identity.sql`:改完之后它们只有 identity 调用。
- **公开面泄漏已堵上**(#167):原先的 `GuardOwners(ctx, func(*sqlc.Queries) error)` 改为不导出,disable / delete / set-roles 收进 identity 的 `SetDisabled`、`Delete`、`SetRoles`,内部执行所有者守卫;identity 导出方法不再含 sqlc 类型。
- **`provider.Unbind` 仍自建 `identity.New`**:它是无状态构造(pool + keyring),没有行为代价;等组合根(composition root)落地时统一注入。
- management 仍直接查 users 表:那是它的控制台读模型,不是绕过 identity 的写路径。
- 新增值类型会带来少量映射代码;换来的是调用方不需要 import sqlc 类型。
