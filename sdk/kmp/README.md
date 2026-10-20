# Polaris KMP SDK

iOS 和 Android App 不经浏览器登录 Polaris:验证码、密码、Sign in with Apple、Passkey、刷新、登出、注销账号。只管协议,不带界面。行为约定见 [SDK 行为说明](../../docs/sdk-behavior.md)。

SDK 0.x 支持服务端 API v1。

## 安装

Android / KMP:

```kotlin
implementation("com.zibyn.polaris:polaris:0.1.0")
```

iOS:KMP 工程直接依赖;纯 Swift 工程用 `./gradlew assemblePolarisXCFramework` 产出的 `Polaris.xcframework`。

## 接入

先在管理端登记一个 public Application(开启 refresh token,配好默认 API),并登记 Team ID + Bundle ID、包名 + 签名指纹(Passkey 要用,见下)。

```kotlin
// Android
val auth = Polaris(PolarisConfig("https://auth.example.com", clientId = "nav-app"), KeystoreTokenStore(context))
// iOS (Kotlin);Swift 中同名
val auth = Polaris(PolarisConfig("https://auth.example.com", clientId = "nav-app"), KeychainTokenStore())
```

整个 App 只建一个实例:single-flight 刷新只在同一实例内成立。

### 验证码登录

```kotlin
val terms = auth.terms()                        // 勾选框链接 terms.termsUrl / terms.privacyUrl
val sent = auth.sendCode("+8613800000000", terms.version)   // 先算 PoW,约一秒
when (val step = auth.verifyCode(sent.session, code)) {
  SignInStep.SignedIn -> …
  is SignInStep.PhoneRequired -> {               // 实例要求绑定手机号
    val phoneSent = auth.sendCode(phone, step.session)
    auth.verifyCode(phoneSent.session, phoneCode)
  }
  is SignInStep.TotpRequired ->                  // User 开了两步验证;之后可能还要绑手机号
    auth.verifyTotp(step.session, totp)          // 或 auth.verifyRecoveryCode(step.session, 恢复码)
  is SignInStep.CodeSent -> Unit                 // 不会出现
}
```

密码登录:`auth.signInWithPassword(identifier, password, terms.version)`(用户名、手机号或邮箱),结果同上。

### Sign in with Apple

App 自己用系统的 Sign in with Apple(`ASAuthorizationAppleIDProvider`,不必请求 `fullName`、`email`)拿到凭证,把其中的 `authorizationCode` 原样交给 SDK;SDK 不内置 Apple 的 SDK,也不需要 identity token 或 nonce。`"apple"` 是管理员添加 Apple Provider 时填的 Provider ID,该 Provider 要填好 App 的 Bundle ID。

```swift
let code = String(data: credential.authorizationCode!, encoding: .utf8)!
let step = try await auth.signInWithProvider(provider: "apple", authorizationCode: code, termsVersion: terms.version)
```

结果同验证码登录。抛出 `error == "invalid_grant"` 表示 Apple 没认这个 code(用过、过期或不属于这个 App),让 User 重新点一次 Apple 登录。

出错抛 `PolarisException`:`error == "invalid_request"` 时 `description` 可直接展示(验证码错误、发送太频繁等);`error == PolarisException.UNSUPPORTED_STEP` 表示服务端要求了这个 SDK 版本不认识的步骤,提示 User 升级 App。

### 调用业务后端

```kotlin
client.get(url) { bearerAuth(auth.accessToken()) }
```

`accessToken()` 自动刷新,并发调用只刷新一次。抛出 `error == PolarisException.SIGNED_OUT` 时回到登录页。

### Passkey

系统的凭证界面(Android Credential Manager / iOS ASAuthorization)由 SDK 弹,App 不带界面,只把 `PasskeyPrompt` 交给 `Polaris`:

```kotlin
// Android:传 Activity 的 context,系统界面弹在它上面
val prompt = passkeyPrompt(this)
// iOS
val prompt = passkeyPrompt()
val auth = Polaris(config, store, passkeys = prompt)
```

前提(缺一不可,否则系统界面不会出现):

- **iOS 16+**。在管理端登记 Team ID + Bundle ID,宿主 App 的 Associated Domains 里加 `webcredentials:<实例域名>`。
- **Android 9+ 且装有 Google Play 服务**。在管理端登记包名 + 签名指纹,`https://<实例域名>/.well-known/assetlinks.json` 要能返回这个 App(服务端按登记生成)。

登录:

```kotlin
if (!auth.passkeysAvailable()) { /* 大陆无 GMS 的机型:隐藏 Passkey 入口 */ }
when (auth.signInWithPasskey(terms.version)) {        // 结果同验证码登录,含 next
  SignInStep.SignedIn -> …
  is SignInStep.PhoneRequired -> …
  is SignInStep.TotpRequired -> …
  is SignInStep.CodeSent -> Unit
}
```

添加(在账号中心的设置页里):先让 User 在账号中心登录一次——10 分钟内有效——再调 `addPasskey()`。

```kotlin
val sent = auth.sendAccountCode("alice@example.com", terms.version)
auth.verifyCode(sent.session, code)                    // 或 auth.signInForAccountWithPassword(id, pw, v)
val passkey = auth.addPasskey()                        // 系统弹出「创建 Passkey」,返回新增的 Passkey
```

- `PASSKEY_CANCELLED`:User 关掉了系统界面,不是失败,保持原界面。
- `PASSKEY_UNAVAILABLE`:这台设备没有可用的系统凭证界面(`passkeysAvailable()` 为 false)。
- `REAUTHENTICATE`:距上次登录账号中心超过 10 分钟,重新登录再调一次 `addPasskey()`。
- 账号中心的令牌(账号中心的「登录」也用 `auth.signInForAccountWithPasskey(version)`)只存在内存里,不影响 `auth.tokens()`;`signOut()` 会一起清掉。

### 登出与注销

- 登出:`auth.signOut()`,离线也会清空本地令牌。
- 注销(应用商店要求 App 内提供入口):二次确认后让 User 重新登录一次,再调 `auth.deleteAccount()`;超过 10 分钟未登录会抛 `PolarisException.REAUTHENTICATE`。

### 自动填充验证码

- iOS:`textContentType = .oneTimeCode`(SwiftUI:`.textContentType(.oneTimeCode)`),键盘上方会出现短信里的验证码。
- Android(Compose):`Modifier.semantics { contentType = ContentType.SmsOtpCode }`;View 体系:`android:autofillHints="smsOTPCode"`(`View.AUTOFILL_HINT_SMS_OTP`)。
- 输入框只放一个,6 位数字,`keyboardType` 为数字。

### 自定义存储

实现 `TokenStore`(`read()` / `write(value)`,`null` 表示登出),传给 `Polaris`。

## 业务后端校验 access token

用主流 JWT 库按 JWKS 本地验签,检查签名(RS256)、`iss`、`aud`(你的 API 标识)、`typ: at+jwt`,权限读 `entitlements`。Node(`jose`):

```js
import { createRemoteJWKSet, jwtVerify } from "jose";

const jwks = createRemoteJWKSet(new URL("https://auth.example.com/jwks"));

export async function verify(authorization) {
  const token = authorization?.replace(/^Bearer /, "");
  const { payload } = await jwtVerify(token, jwks, {
    issuer: "https://auth.example.com",
    audience: "urn:example:nav-api",
    typ: "at+jwt",          // 挡住同一把密钥签的 ID token
    algorithms: ["RS256"],
  });
  return { sub: payload.sub, entitlements: payload.entitlements ?? [] };
}
```

吊销最多滞后一个 access token 的寿命(10 分钟)。

## 开发

```bash
./gradlew testAndroidHostTest       # 单元测试(iOS 目标在 Linux 上只编译)
scripts/integration.sh              # 对本地 Polaris 二进制跑集成测试;需要 Docker 和 web/dist/client
```

发布到 Maven Central:在 `~/.gradle/gradle.properties` 配好 `mavenCentralUsername`、`mavenCentralPassword` 与 `signing.*`(或 `signingInMemoryKey*`),改 `gradle.properties` 的 `VERSION_NAME`,然后 `./gradlew publishAndReleaseToMavenCentral`。
