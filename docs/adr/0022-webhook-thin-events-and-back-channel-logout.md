# 通知分两路:Webhook 发薄事件,Session 终止走 Back-Channel Logout

Application 需要知道 User 被禁用、Identifier 或用户资料变了、Role 变了,也需要知道 Session 被终止了(#147)。这两类通知分开走:User 层面的变更走 Webhook(`user.disabled`、`user.enabled`、`user.updated`);Session 终止走 OIDC Back-Channel Logout,Webhook 里不出现 `session.ended`。Webhook 只发**薄事件**:payload 里只有 `sub`,`user.updated` 再加一个 `changed` 列出变了哪几项,不带新值。Application 要拿新值,就用自己的 M2M Application 调 Management API。Webhook 发给所有配置了它的 Application,不保证顺序;接收方要按 `timestamp` 丢弃过时事件,或者去取当前状态,还必须忽略不认识的 `type`。

## Considered Options

- **只扩充 Webhook**:Session 终止也用 Webhook 发(`session.ended` 带 `sid`)。这是自有协议,自己维护 cookie 会话的 Web 后端得自己处理;Back-Channel Logout 是 RP 库原生支持的标准做法。
- **只做 Back-Channel Logout**:它只能说「这个 Session 终止了」,说不了「手机号换了」「Role 变了」。
- **事件带新值**:Webhook 会发给每一个配置了它的 Application,不看 User 用没用过。带上新值等于把全池 User 的手机号和邮箱推给每个 Application,远超它们通过 scope 能拿到的范围。
- **保证每个 User 的事件按顺序投递**:投递队列得按 User 排队,一条投递一直失败,这个 User 后面的事件就全被卡住。薄事件本来就是「来取最新状态」的信号,用不着保证顺序。

## Consequences

- 想同步数据的 Application 需要一个 M2M Application,并且它在 Management API 上要有读 User 的 Role。
- 只改 Role 的 Permission 不发事件:这是 API 配置的变更,不是 User 的变更。Application 在令牌刷新后自然会拿到新的 `entitlements`。
- Session 要记下它给哪些 Application 签发过令牌。不然只走 code flow、不拿 refresh token 的 Application 收不到 logout token。
