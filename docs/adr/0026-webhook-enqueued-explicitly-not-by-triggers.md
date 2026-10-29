# Webhook 入队由写操作显式进行,不用表触发器

改 User 的查询自己在 CTE 里 `INSERT INTO webhook_deliveries ... FROM user_event(...)`,并自己判断「值是否真的变了」(ADR 0022 的薄事件)。不在 `identifiers`、`users`、`user_roles` 上挂触发器比较 OLD/NEW 来自动入队。防漏和防误发靠一个表驱动测试:每个改 User 的查询都测「改了」和「值没变」两种情况,断言恰好一条或零条。

## Considered Options

- **行级 / 语句级触发器比较 OLD 与 NEW**:新写操作自动覆盖,但会误发:
  - `CreateUser` 在同一语句里写默认 Role,`AddIdentifier`(注册,不发)和 `BindIdentifier`(发)写同一张表,触发器分不出新 User 和已有 User;
  - `SetUserRoles` 一条语句里先 DELETE 后 INSERT `user_roles`,语句级触发器会发两次;
  - `identifiers`、`user_roles` 随 `users` 级联删除,会给已删除的 User 发 `user.updated`。
- **行级触发器记下改动,提交时由延迟约束触发器按 User 合并、去重**:三个问题都能绕过,但要靠「本事务新建的 User」「本事务删掉的 User」这类事务时间上的判断,规则藏在触发器里,比现在 10 处显式调用难懂、难测。

## Consequences

- 新增改 User 的查询要自己调 `user_event()` 并写变更判断;忘了由上面的表驱动测试拦住。
- 与 ADR 0025(审计在写操作自己的事务里显式写)同一取向:副作用跟着写操作走,不由旁路补。
