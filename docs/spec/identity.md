# 身份模型

## 概念

```
User (sub: 不透明、稳定、永不复用)
├── 状态                待激活 / active(与 disabled 相互独立)
├── Identifier          手机号 ≤1 · 邮箱 ≤1 · 用户名 ≤1   池内唯一
├── External Identity   每个 Provider ≤1                 池内唯一
├── Credential          密码 ≤1 · Passkey 多把 · TOTP ≤1 · 恢复码
├── Session             不限数量
├── Role 分配            按 API,见 rbac.md
└── 同意记录             见 security-compliance.md
```

- **Identifier**:
  - 手机号以 E.164 格式存储(一期只接受 +86);邮箱整体转小写后比较;两者都必须已验证,并且能接收验证码。
  - 用户名不需要验证,不能接收验证码,只能配合密码使用;3–32 位字母、数字或 `. _ -`,不区分大小写(不含 `@`、`+`,不会与邮箱或手机号混淆)。
- **External Identity**:由 Provider 和其侧的用户 ID 组成,不对 Application 暴露。
- **Credential**:见 [authentication.md](authentication.md)。
- **状态**:`待激活` 表示管理员创建、本人尚未设置自己密码的 User;`active` 是其余 User。它与禁用相互独立,**禁用永远优先**:被禁用的 User 根本登录不了,所以不算待激活。管理员创建 User 时给一个初始密码,账号即进入待激活(ADR 0016)。

## 不变式

1. **至少一个可登录途径**:User 至少要有以下之一:手机号、邮箱、用户名 + 密码、已启用 Provider 的 External Identity(停用的 Provider 登录不了,不算)。最后一个途径不允许解绑。
2. **登录即注册**:用池内不存在的手机号或邮箱完成验证,或用没有绑定过的 External Identity 登录时,自动创建 User。不提供"关闭注册"开关。
3. **永不合并**:要绑定的 Identifier 或 External Identity 已属于其他 User 时,直接拒绝;User 需先在那边解绑或注销。(ADR 0003)
4. **不自动关联**:Provider 返回的邮箱或手机号不会把新的 External Identity 关联到已有 User;只能由已登录的 User 主动绑定。
5. **设密码的前提**:至少要有一个 Identifier。只有 External Identity 的 User 不能设密码。
6. **"必须绑定手机号"开关**:实例级,默认关闭。打开后,没有手机号的 User 登录时须先补绑。
7. **待激活拿不到令牌**:待激活的 User 有凭据(初始密码),但凭据不能用到底——他登录得了,却拿不到 authorization code、拿不到任何令牌,直到本人设置自己的密码。所以 Application 侧看不到这个状态:不加 claim、不加 scope、ID token 不变。这一条与不变式 1「至少一个可登录途径」并不冲突:他确实有途径,只是必须先激活。

## 对 Application 暴露

- `sub`:User ID,public 类型,不用手机号。
- `phone` scope:`phone_number`,`phone_number_verified` 恒为 true。
- `email` scope:`email`,`email_verified` 恒为 true。
- External Identity 和用户名不暴露。

## 账号生命周期

### 待激活与激活

- **产生**:管理员创建 User 时给一个标识符与一个初始密码,账号即进入待激活。管理员代填的标识符**直接算已验证**,不发验证邮件、不消耗验证码条数,所以能走验证码登录。
- **期间能做和不能做**:只能**改密码**与**注销**;绑手机号、开启两步验证一律要求先激活。强制改密排在两步验证之前,托管页与直连认证 API 的顺序一致。
- **激活**:本人设置自己的密码即激活。
- **改密通路独立**:强制改密不复用账号中心的改密接口——那条要求近期重新认证,而重新认证对开了两步验证的 User 一律拒绝密码和验证码,2FA 用户会卡死。它只对**待激活的会话**开放,激活后自动失效。
- **Provider 登录**:待激活的 User 用 Provider 登录时不给令牌,只告知要设置密码。
- **Role**:待激活的 User 照常持有 Role,包括 Management API 的 Role——他调不了任何接口,风险为零,而「先建号、配好角色、再通知本人」是合理工作流。
- **禁用**:`SetUserDisabled` 只在待激活与 active 之间不动状态。

### 换绑与解绑

- 都要求**近期重新认证**:这个 Session 10 分钟内认证过,只看认证时间。没开两步验证的 User 用自己已绑定的手机号或邮箱收验证码,或者用密码重新认证;有 Passkey 的也可以用它重新认证(断言选项只列自己的凭证)。也可以用自己已绑定的 Provider 重新认证:通用 OIDC 带 `prompt=login` 和 `max_age=0`,并校验 `auth_time`。通用 OAuth2(如 GitHub)两者都不支持,上游记着登录状态时不必再输密码,所以用它重新认证只证明"此刻仍控制这个外部账号",不证明刚刚认证过(ADR 0013)。Google 与 Microsoft 也拿不到 `auth_time`(Google 要用 `claims` 请求参数专门要,Microsoft 的 v2 id_token 里没有这个 claim),两者同样按 OAuth2 的口径:`max_age` 两家文档都没写,`prompt=login` 只有 Microsoft 的文档写了(会要求输密码),Google 的文档没写。
- 开了两步验证的 User 用 TOTP、恢复码或 Passkey 重新认证,验证码和密码一律拒绝,这样拿到手机号或密码的人做不了敏感操作。TOTP 或恢复码成功后这个 Session 的 `amr` 记为 `["otp", "mfa"]`;Passkey 与 Passkey 登录一样,记为 `["hwk", "mfa"]` 或 `["swk", "mfa"]`(见 authentication.md),`auth_time` 同登录一样更新。同一个时间步的码只能用一次,恢复码用过即作废(记审计 `recovery_code.used`);输错计入单个 IP 的失败计数。
- 新的手机号或邮箱要用验证码验证;旧的不要求。
- 解绑规则相同,受不变式 1 约束。
- **绑定 External Identity**:只在账号中心,用重定向型 Provider 完成;直连 API 不提供绑定。解绑时触发该 Provider 的解绑回调(如 Apple 吊销令牌)。
- 换绑后不踢其他 Session。

### 找回

User 无法自助找回丢失的唯一途径。由持有 `users:write` 的管理员线下核实身份后,在管理端替换 Identifier 或重置 2FA,并写入审计日志。只有用户名的 User 丢了密码,同样只能由其他管理员处理。

### 运营商二次放号

不专门处理,作为已知风险写进部署文档。开了 2FA 或 Passkey 的 User 不受影响。

### 注销

- **发起**:账号中心,或直连 API(供 App 内注销,满足 App Store 要求)。
- **前提**:近期重新认证,并二次确认。
- **生效**:立即生效,没有冷静期。
- **删除范围**:物理删除 User、Identifier、External Identity、Credential、Session、Role 分配、同意记录,并吊销所有 refresh token。审计日志只保留 `sub` 和事件。
- **释放与复用**:`sub` 永不复用;Identifier 立即释放,同一个手机号可以马上注册为新 User。
- **外部吊销**:触发 Provider 的注销回调(如 Apple 吊销令牌)。
- **通知 Application**:向配置了 webhook 的每个 Application 发送 `user.deleted` 事件,见 [protocol.md](protocol.md#webhook)。

### 管理员对 User 的操作

- **创建**:给一个标识符与一个初始密码,账号进入待激活。需要 `users:write`,密码登录关闭时返回 422。建出的 User 照常获得业务 API 的默认 Role。
- **禁用**:禁止登录,并终止全部 Session;可以恢复。
- **删除**:效果等同注销。
- **替换 Identifier**、**解绑 External Identity**、**重置 2FA**、**下线 Session**。
- **保护规则**:最后一个「所有者」不能被删除、禁用或降级。
