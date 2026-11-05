# Polaris 不存 Application 的业务数据

集成方要给 User 挂的业务字段(会员等级、工号等)不存进 Polaris:没有 `app_metadata` 式的自定义数据,也没有把任意值写进 token 的 claim 模板或脚本。集成方以 `sub` 为键在自己的库里存;其中「分级或资格」类字段(如会员等级)在集成方自建的 API 上建成 Role,由此进入发给该 API 的 access token 的 `roles`,可用 list-users 的 `api` + `role` 过滤查人,变更也走现有 Webhook。

## Considered Options

- **全局一份 metadata**(Auth0 `app_metadata`、Logto `customData` 等主流做法):按 ADR 0031,持 Management API Role 的集成方看得到整个用户池,A 写的业务数据 B 也读得到;靠 key 前缀分应用只是约定。这会把「互相可见」从身份扩大到业务数据,也和 ADR 0022 薄事件 Webhook 的用意相反。
- **按 Application / API 各存一份**:需要新的作用域层;调研过的平台没有一家做到(Zitadel #6535 搁置),见 `docs/research/integration-modes-saas.md`、`docs/research/integration-modes-oss.md`。

## Consequences

- 工号这类自由文本进不了 token,集成方后端拿 `sub` 自查。
- 集成方原有系统的用户 ID 如何关联(`external_id` 一类)不在此决定,归「已有用户的导入与关联」。
- 文档要把「用自建 API 的 Role 表达业务分级」写成推荐做法。
