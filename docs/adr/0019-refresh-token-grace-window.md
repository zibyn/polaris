# refresh token 轮换留 60 秒宽限窗口

刷新时轮换 refresh token,被换下的旧 token 记为已用。以前已用的 token 一旦再来就终止整个 Session;现在给**最近一次被换下**的那一个留 60 秒宽限:60 秒内它再来,服务端基于当前 grant 再轮换一次,签发全新的一组令牌,不判为重用,并记一条 `refresh_token.grace` 审计事件。更早换下的 token,或超过 60 秒才回来的 token,仍按泄露处理。理由是:SDK 的 single-flight 只能防并发,防不住"服务端已轮换、响应在弱网下丢了,或 App 被杀掉"——客户端下次只能拿旧 token 来刷,User 会被误判为泄露而强制下线(#141)。

## Considered Options

- **不留窗口(原状)**:最严格,但弱网场景下误伤正常 User,而户外导航 App 正是弱网最多的场景。
- **窗口内返回同一组新令牌**:客户端拿到的就是丢失的那组,但要把新令牌明文封存起来,access token 还会被重复下发,存下的秘密更多。
- **按 Application 配置窗口长度**(Auth0 Reuse Interval、Okta grace period 的做法):目前没有不同 App 需要不同值,要加列和管理界面,不值得。

## Consequences

- 泄露检测最多滞后一个刷新周期:攻击者在窗口内用旧 token 能拿到一组新令牌,合法客户端手里的 token 由此变成"最近换下"的;它约 10 分钟后才刷新,那时窗口早已过去,于是判为重用,Session 照样终止。
- 并发刷新的输家也走宽限(基于最新的 grant 再轮换一次),不再终止 Session。返回 `invalid_grant` 不能作为替代,因为 SDK 收到它就会登出。
- 用已用 token 调 `/revoke` 不受影响:登出本来就要结束 Session。
- `protocol.md` 令牌表中"一旦重用,终止整个 Session"和 `sdk-behavior.md`"服务端没有宽限窗口"两处表述要同步修改。
