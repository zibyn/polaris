# Passkey 可作为两步验证的第二因素

两步验证原来只认 TOTP 和恢复码:密码、验证码或 Provider 登录之后,只能输验证器里的 6 位码或一个恢复码。已经有 Passkey 的 User 想挡住拿到密码或手机号的人,还得再装一个验证器。改为第二因素可以是 TOTP、Passkey 或恢复码之一,三者效果相同。参照 Logto 等平台:Passkey 登录直接满足 MFA,同一把 Passkey 也是一种 WebAuthn MFA 因素。Passkey 本来就要求设备验证 User(生物识别或 PIN),当第二因素比 TOTP 更强,也不怕钓鱼。

- 第二步只在 User 有 Passkey 时提供,断言选项只列这个 User 自己的凭证(`allowCredentials`),要求 UV;别人的 Passkey 不通过。失败处理与 Passkey 登录一致,计数器回退照样写 `passkey.counter_regressed` 并拒绝。
- 第二步用 Passkey 时 `amr` 为 `[第一因素, "hwk"/"swk", "mfa"]`,不加 `otp`:没有输入任何一次性码。
- Passkey 断言失败不计入 `2fa:<sub>`(ADR 0036),也不占每次登录 5 次的机会:断言猜不出来,计数挡的是猜码。TOTP 被锁定期间 Passkey 第二步仍可用。
- 第二步遵守实例的 Passkey 登录开关:关着时不提供 Passkey,只剩 TOTP 和恢复码。Application 允许的登录方式只约束第一因素,不影响第二步提供 Passkey。
- Passkey 登录本身仍直接满足两步验证,不变。
- 直连 API:只有 Passkey 时 `next: "passkey"`,TOTP 和 Passkey 都有时 `next: "two_factor"` 加 `methods: ["totp", "passkey"]`;只有 TOTP 或 Passkey 登录关着时仍是 `next: "totp"`,原样不变。Passkey 第二步的断言不通过只作废那次 challenge,`auth_session` 留着,重新 `begin` 即可:与 Passkey 登录不同,第一因素已经过了,作废它只会逼 User 重来一遍,而断言本来就猜不出来。
- 两步验证开着却没有 TOTP 的 User 提交 `totp`,按输错处理,不再当作「两步验证已关闭」放行。

## Considered Options

- **维持只认 TOTP 和恢复码**:只有 Passkey 的 User 要么装验证器,要么放弃两步验证;而 Passkey 比 TOTP 更难被钓走,拒绝它没有安全上的理由。
- **Passkey 第二步也计入 `2fa:<sub>`**:断言由设备签名,不能靠猜;计入只会让故意输错 TOTP 的攻击者连带锁掉 User 的 Passkey,扩大 ADR 0036 已经接受的那点代价。
- **第二步不受 Passkey 登录开关约束**:管理员关掉 Passkey 登录,意思是这个实例不用 Passkey 做认证,第二步也一样;关着时仍有 TOTP 和恢复码。

## Consequences

- 两步验证页可以出现「使用 Passkey」,直连 API 需要新的 `next` 取值来表示同样的选择(只增不改,ADR 0010)。
- 实例关掉 Passkey 登录时,靠 Passkey 做第二步的 User 只剩 TOTP 和恢复码;Passkey 登录关着时,也不能只用 Passkey 开启两步验证。
- 两步验证可以只靠 Passkey 开着(没有 TOTP)。这时最后一把 Passkey 不能删(本人和管理员都返回 409),要解除就关闭或重置两步验证;TOTP 开着之后可以单独加、减,不重新生成恢复码。删 Passkey 与只用 Passkey 开启、移除 TOTP 都在 SERIALIZABLE 事务里检查,并发时不会同时放行而留下没有因素的两步验证。
- 有只靠 Passkey 开着两步验证的 User 时,实例仍可关掉 Passkey 登录,不加拦截:他们还有恢复码,托管页直接给恢复码输入框,用完可以重新生成;拦下来反而让管理员关不掉一个实例级功能。管理员本人属于这种情况时,"管理员必须启用两步验证或 Passkey"看的是两步验证开着,也不受影响。
