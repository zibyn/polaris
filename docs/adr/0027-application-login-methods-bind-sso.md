# 按 Application 指定登录方式,单点登录的 Session 也受其约束

每个 Application 的登录方式有两种状态:「跟随实例」(默认)和「指定一组」;生效的是实例开关与指定的那组取交集。浏览器里已有的 Session 进入一个 Application 时,只有它当初用的登录方式在这个 Application 可用,才算已登录;否则按 `prompt=login` 处理,让 User 用允许的方式重新登录。为此 Session 要记下具体用了哪种登录方式,Provider 登录还要记是哪个 Provider(`amr` 的 `fed` 区分不出)。不这样做的话,员工后台「只要公司 IdP」的限制,会被一个在公众 App 用短信登录的 Session 绕过去。Auth0 的 connections 也是这么做的。(#153)

## Considered Options

- **排除列表**(勾掉不要的,新的自动出现):每加一个公共 Provider,它就会悄悄出现在「只要公司 IdP」的员工后台上。
- **限制只作用于登录页,单点登录照常放行**:实现最简单,但限制形同虚设。
- **Session 累积它期间证明过的所有登录方式**:能免去两个互不相交的 Application 之间来回重登,但与「`amr` 表示这一次认证」的语义冲突,还要另加字段。

## Consequences

- 重新登录沿用现有的原地续用:同一个 User 时,原 Session 改记这次的登录方式;换成别的 User 时,结束旧 Session。所以在两个只允许互不相交登录方式的 Application 之间切换,每次都要重新登录。
- 管理端和账号中心永远跟随实例,不会因为 Application 设置把管理员锁在外面(ADR 0017 的自锁问题)。
- 实例关掉某种登录方式时不受 Application 设置牵制。交集变空的 Application 由登录页和 challenge 端点报错,管理端在它上面显示警告。
