# Management API 的写操作在自己的事务里写审计

Management API 的每个写操作都在改数据的那个事务里写审计:一条查询能做完的,在 SQL 的 CTE 里带 `@by` 插入;要多条查询的,在 handler 的事务里调 `q.Audit`;不改库的(`test-channel`)在动作成功后写。不再有响应之后统一补写的中间件,也不再有记录「哪些操作已自己审计」的名单。事件名一律是 `名词.动词` 过去式(如 `application.updated`、`role.saved`),不用 operation ID;PUT 是 upsert,记为 `.saved`。detail 的键由各处显式写出,`byType` 仍由 `audit_log` 上的触发器补。

## Considered Options

- **保留中间件,按 operation ID 补写其余写操作**:原来的做法。审计在响应之后写,PG 出错就丢;要靠手工同步的 `selfAudited` 名单避免重复,漏加会记两次,错加会一条不记;事件名也分成两种风格。
- **保留中间件,把「已自己审计」改成 `op()` 注册时的标记**:名单和路由放到了一起,但丢审计和两套写法都还在。

## Consequences

- 迁移把历史记录里的 operation ID 事件名改成新名字,前端只留一套映射。
- 防漏靠测试:遍历 OpenAPI 里所有非 GET 操作,每个都必须在测试表里有一行,并断言恰好写一条预期事件。新增写操作不登记,测试就失败。
- 新增写操作的人要自己写审计;忘了不会静默,上面的测试会拦住。
