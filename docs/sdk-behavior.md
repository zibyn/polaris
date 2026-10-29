# SDK 行为说明

所有官方 SDK 都按这份说明实现;不用 SDK、自己调 HTTP API 的接入方也必须做到其中标 **必须** 的几条。端点细节见 `/v1/auth/openapi.json`。

## 登录

- **PKCE**:每次登录生成新的 `code_verifier`(43 个 base64url 字符,至少 240 位随机),第一步带上 `code_challenge`(S256);同一个 `auth_session` 内沿用,兑换 code 时带上 `code_verifier`,不带 `redirect_uri`。
- **协议版本**:每个 challenge 请求都带 User 勾选同意的 `terms_version`(`GET /v1/auth/terms` 的 `version`)。实例尚未配置协议(`version` 为空)时任意版本都行,空串也可以。
- **PoW**:发码和密码登录前,从 `GET /altcha/challenge` 取题目,按 ALTCHA v2(PBKDF2/SHA-256,计数器为 4 字节大端)求解,把题目原样连同解答 base64 后作为 `altcha` 发送。一个解答只能用一次。
- **多步**:`403 insufficient_authorization` 带回 `auth_session`,下一步带上它。**必须**按 `next` 决定下一步,不要解析 `error_description`:`code` 表示"输入验证码"(给绑定的手机号发码后也是 `code`);`phone` 表示"需要绑定手机号",在同一 `auth_session` 内给手机号发码再验证;`totp` 表示"User 开了两步验证",在同一 `auth_session` 内提交 `totp`(验证器上的 6 位码)或 `recovery_code`(恢复码),先于 `phone`。`totp` 输错返回 `invalid_request` 并带回 `auth_session`,可以重输;第 5 次输错后返回 `invalid_session`。`next` 以后只新增取值;遇到不认识的取值**必须**按失败处理(KMP SDK 抛 `PolarisException`,`error` 为 `unsupported_step`),提示 User 升级 App。
- **外部登录**(Apple):App 用系统的 Sign in with Apple 拿到 `authorization_code`,原样作为 `authorization_code`、连同 Provider ID 作为 `provider` 提交(KMP:`signInWithProvider`),不提交 identity token,也不需要 nonce(ADR 0011)。code 只能用一次,`400 invalid_grant` 表示 Apple 没认这个 code,让 User 重新用 Apple 登录。之后照常按 `next` 走。
- **用户错误**:`400 invalid_request` 的 `error_description` 可直接展示;返回了 `auth_session` 时它仍然可用(比如重输验证码)。`invalid_session` 表示从头再来。

## Passkey

- **系统界面**:断言和注册都由系统凭证 API 完成(Android Credential Manager、iOS ASAuthorization),SDK 不带界面,也不自己实现 WebAuthn。服务的 options 是 `publicKey` 包一层的 `PublicKeyCredentialCreationOptionsJSON` / `PublicKeyCredentialRequestOptionsJSON`;Credential Manager 要的是里面那层,SDK 拆开再给。
- **登录(两次往返)**:第一步在 challenge 上带 `passkey=begin`,得到 `200 {auth_session, options}`(**不发 PoW**:begin 不验证任何凭证,由按 IP 的预算兜底);把 `options.publicKey` 交给系统界面,拿到断言后在同一 `auth_session` 上带 `passkey=<AuthenticationResponseJSON>` 提交,得到授权码,或 `403 insufficient_authorization` 带 `next`(照常按 `next` 走)。断言被拒(含 challenge 重放)时服务端作废这个 `auth_session`,要重新 begin。
- **添加**:走账号中心(`POST /v1/account/passkeys/options` → 系统界面 → `POST /v1/account/passkeys`),令牌的 `aud` 必须是 `urn:polaris:account-api`,只有内置的 `polaris-account` 能签发,所以 SDK 内置一份账号中心的会话(内存里,不落存储)。两个接口都要求 10 分钟内登录过:服务端返回 `403`,SDK 报"需要重新认证"(`insufficient_user_authentication`),App 重新登录账号中心后再调一次。凭证重复是 `409`。
- **能力探测**:大陆 Android 机型可能没有 Google Play 服务,Passkey 一定失败。App 先问一声再决定是否展示入口:Android 看 GMS 是否安装且系统 ≥ 9;iOS 直接可用。
- **User 取消**:关掉系统界面不是失败,是可区分的结果(KMP:`PolarisException.PASSKEY_CANCELLED`),界面保持原样。系统给不出凭证的其它原因(iOS 没声明关联域等)照常按失败抛出,不要当成取消。
- **关联文件**:系统只在 RP ID 与 App 声明过关联时才弹界面——iOS 的 Associated Domains `webcredentials:`、Android 的 `/.well-known/assetlinks.json`。两者都按管理端登记的 Team ID + Bundle ID、包名 + 签名指纹生成,`/.well-known/` 始终返回这两个文件,不受 Passkey 开关影响。

## 刷新

- **single-flight(必须)**:同一时间只有一个刷新请求,其余调用方等它的结果。服务端的宽限窗口(见下)只兜住丢失的响应,不能代替 single-flight。
- **时机**:access token 剩余不足 30 秒时刷新;刷新后旧 refresh token 立刻作废,新令牌原子地写入存储。
- **网络失败、5xx**:保留现有令牌,下次再试。若服务端已完成轮换而响应丢失,下次刷新会用到旧 token:60 秒内服务端走宽限,签发一组新令牌;超过 60 秒则按重用处理。

## refresh token 重用后

最近一次被换下的 refresh token,换下后 60 秒内再拿来刷新,服务端不算重用:基于当前状态再轮换一次,签发一组全新的令牌(不是丢失的那组),Session 照常。并发刷新的输家同样走宽限。更早换下的 token,或超过 60 秒才回来的 token,算重用。用已用 token 调 `/revoke` 始终终止 Session。

服务端发现重用时终止整个 Session:旧 token、新 token 和这个 Session 签发的 access token(在 Account API 上立即,在业务后端最多滞后 10 分钟)都失效。`/token` 返回 `invalid_grant` 时 SDK 清空本地令牌,报告"已登出"(KMP:`PolarisException.SIGNED_OUT`),App 应回到登录页。被吊销、过期、在账号中心下线、账号被删除,表现相同。

## 登出

- 向 `/revoke`(RFC 7009)吊销 refresh token,这会结束服务端的 Session。
- **尽力而为**:吊销失败(离线等)也照样清空本地令牌,登出总是成功;残留的 Session 闲置到期,或由 User 在账号中心下线。

## 注销账号

- `POST /v1/auth/delete`,带 access token。要求 10 分钟内登录过:否则 401 `insufficient_user_authentication`,App 应让 User 确认后重新登录,再调一次。
- 成功(204)后清空本地令牌。最后一个所有者不能注销(409)。

## 令牌存储

默认加密存储:iOS Keychain(`AfterFirstUnlockThisDeviceOnly`,不同步、不随备份迁移到别的设备),Android Keystore 中的 AES-GCM 密钥加密后存入私有 SharedPreferences;解不开(如密钥丢失)视为未登录。存储接口可替换。
