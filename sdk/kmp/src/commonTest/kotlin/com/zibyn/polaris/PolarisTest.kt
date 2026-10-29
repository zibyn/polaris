package com.zibyn.polaris

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import kotlinx.io.IOException

/** A Polaris that answers by path; tests set the answers they need. */
class FakeServer {
  val forms = mutableListOf<Pair<String, Map<String, String>>>()
  val bodies = mutableListOf<Pair<String, String>>()
  val authHeaders = mutableListOf<Pair<String, String?>>()
  var handlers = mutableMapOf<String, MockRequestHandleScope.(Map<String, String>) -> HttpResponseData>()
  val store = MemoryTokenStore()

  fun calls(path: String) = forms.count { it.first == path }

  fun auth(passkeys: PasskeyPrompt? = null) = Polaris(
    PolarisConfig(issuer = "https://auth.test", clientId = "app"),
    store,
    HttpClient(MockEngine { req ->
      val body = (req.body as? OutgoingContent.ByteArrayContent)?.bytes()?.decodeToString().orEmpty()
      val form = parseQueryString(body).entries().associate { it.key to it.value.firstOrNull().orEmpty() }
      forms += req.url.encodedPath to form
      bodies += req.url.encodedPath to body
      authHeaders += req.url.encodedPath to req.headers[HttpHeaders.Authorization]
      handlers[req.url.encodedPath]?.invoke(this, form) ?: respond("", HttpStatusCode.NotFound)
    }),
    passkeys,
  )
}

/** The system sheet, faked: hands back [response] (null: the User dismissed it) and keeps what it was given. */
class FakePasskeys(
  override val available: Boolean = true,
  private val response: String? = """{"id":"cred"}""",
) : PasskeyPrompt {
  val given = mutableListOf<String>()

  override suspend fun create(optionsJson: String): String? = response.also { given += optionsJson }

  override suspend fun get(optionsJson: String): String? = response.also { given += optionsJson }
}

fun MockRequestHandleScope.json(body: String, status: HttpStatusCode = HttpStatusCode.OK) =
  respond(body, status, headersOf(HttpHeaders.ContentType, "application/json"))

const val solvableChallenge = """{"parameters":{"algorithm":"PBKDF2/SHA-256","nonce":"554e47b3e19cb6fd8f7e8c23ead53957","salt":"2c5905e1896874850e3377650b76c0ff","cost":1,"keyLength":32,"keyPrefix":""},"signature":"x"}"""

fun tokens(n: Int, expiresIn: Int = 600) =
  """{"access_token":"at$n","refresh_token":"rt$n","id_token":"id$n","token_type":"Bearer","expires_in":$expiresIn}"""

class PolarisTest {
  private val server = FakeServer().apply {
    handlers["/altcha/challenge"] = { json(solvableChallenge) }
    handlers["/token"] = { json(tokens(1)) }
  }

  @Test
  fun passwordSignInStoresTheTokens() = runTest {
    server.handlers["/v1/auth/challenge"] = { json("""{"authorization_code":"c1"}""") }
    val auth = server.auth()

    assertEquals(SignInStep.SignedIn, auth.signInWithPassword("alice", "secret123", termsVersion = "2026-01"))

    val (_, challenge) = server.forms.first { it.first == "/v1/auth/challenge" }
    assertEquals("alice", challenge["username"])
    assertEquals("2026-01", challenge["terms_version"])
    assertEquals("S256", challenge["code_challenge_method"])
    val (_, token) = server.forms.first { it.first == "/token" }
    assertEquals("authorization_code", token["grant_type"])
    assertEquals("c1", token["code"])
    assertEquals("app", token["client_id"])
    assertEquals(43, token["code_verifier"]!!.length)
    assertEquals("at1", auth.accessToken())
    assertEquals("id1", auth.tokens()?.idToken)
  }

  // Sign in with Apple: the App hands over the code as is, no PoW, and
  // goes on by next like any sign-in (ADR 0011).
  @Test
  fun providerSignInForwardsTheCode() = runTest {
    server.handlers["/v1/auth/challenge"] = { form ->
      when {
        form["authorization_code"] == "spent" -> json("""{"error":"invalid_grant"}""", HttpStatusCode.BadRequest)
        form["provider"] == "apple" && form["authorization_code"] == "ac1" -> json(insufficient("s1", "totp"), HttpStatusCode.Forbidden)
        else -> error("unexpected $form")
      }
    }
    val auth = server.auth()

    assertIs<SignInStep.TotpRequired>(auth.signInWithProvider("apple", "ac1", termsVersion = "2026-01"))
    assertEquals("invalid_grant", assertFailsWith<PolarisException> { auth.signInWithProvider("apple", "spent", "2026-01") }.error)
    val (_, challenge) = server.forms.first { it.first == "/v1/auth/challenge" }
    assertEquals("2026-01", challenge["terms_version"])
    assertEquals("S256", challenge["code_challenge_method"])
    assertEquals(0, server.calls("/altcha/challenge"))
  }

  // 两步验证: a TOTP code or a 恢复码 in the same auth_session; a wrong one
  // can be entered again.
  @Test
  fun signInAsksForTotpWhenTwoFactorIsOn() = runTest {
    server.handlers["/v1/auth/challenge"] = { form ->
      when {
        form["username"] == "alice" -> json(insufficient("s1", "totp"), HttpStatusCode.Forbidden)
        form["totp"] == "000000" -> json("""{"error":"invalid_request","error_description":"验证码不正确或已用过","auth_session":"s1"}""", HttpStatusCode.BadRequest)
        form["totp"] == "123456" -> json(insufficient("s1", "phone"), HttpStatusCode.Forbidden)
        form["recovery_code"] == "abcd-efgh" -> json("""{"authorization_code":"c1"}""")
        else -> error("unexpected $form")
      }
    }
    val auth = server.auth()

    val totp = assertIs<SignInStep.TotpRequired>(auth.signInWithPassword("alice", "pw", termsVersion = ""))
    val wrong = assertFailsWith<PolarisException> { auth.verifyTotp(totp.session, "000000") }
    assertEquals("invalid_request", wrong.error)
    assertIs<SignInStep.PhoneRequired>(auth.verifyTotp(totp.session, "123456"))
    assertEquals(SignInStep.SignedIn, auth.verifyRecoveryCode(totp.session, "abcd-efgh"))
    val steps = server.forms.filter { it.first == "/v1/auth/challenge" }.map { it.second }
    assertTrue(steps.drop(1).all { it["auth_session"] == "s1" })
  }

  @Test
  fun codeSignInBindsAPhoneWhenAsked() = runTest {
    server.handlers["/v1/auth/challenge"] = { form ->
      when {
        form["identifier"] == "a@example.com" -> json(insufficient("s1", "code"), HttpStatusCode.Forbidden)
        form["code"] == "000000" -> json("""{"error":"invalid_request","error_description":"验证码错误","auth_session":"s1"}""", HttpStatusCode.BadRequest)
        form["code"] == "111111" -> json(insufficient("s1", "phone"), HttpStatusCode.Forbidden)
        form["identifier"] == "+8613800000000" -> json(insufficient("s1", "code"), HttpStatusCode.Forbidden)
        form["code"] == "222222" -> json("""{"authorization_code":"c1"}""")
        else -> error("unexpected $form")
      }
    }
    val auth = server.auth()

    val sent = auth.sendCode("a@example.com", termsVersion = "")
    val wrong = assertFailsWith<PolarisException> { auth.verifyCode(sent.session, "000000") }
    assertEquals("invalid_request", wrong.error)
    assertEquals("验证码错误", wrong.description)
    val phone = assertIs<SignInStep.PhoneRequired>(auth.verifyCode(sent.session, "111111"))
    val phoneSent = auth.sendCode("+8613800000000", phone.session)
    assertEquals(SignInStep.SignedIn, auth.verifyCode(phoneSent.session, "222222"))

    val steps = server.forms.filter { it.first == "/v1/auth/challenge" }.map { it.second }
    assertNotNull(steps[0]["altcha"])
    assertNotNull(steps[0]["code_challenge"])
    assertTrue(steps.drop(1).all { it["auth_session"] == "s1" && it["terms_version"] == "" })
    assertNotNull(steps[3]["altcha"])
    assertEquals("at1", auth.accessToken())
  }

  // A step this SDK version does not know (say, from a newer server) fails
  // rather than show the wrong screen.
  @Test
  fun unknownNextStepFails() = runTest {
    server.handlers["/v1/auth/challenge"] = { json(insufficient("s1", "fingerprint"), HttpStatusCode.Forbidden) }
    val auth = server.auth()

    val e = assertFailsWith<PolarisException> { auth.signInWithPassword("a@example.com", "pw", termsVersion = "") }
    assertEquals(PolarisException.UNSUPPORTED_STEP, e.error)
  }

  @Test
  fun tenConcurrentCallersShareOneRefresh() = runTest {
    server.store.value = stored(expiresAt = 0)
    server.handlers["/token"] = { json(tokens(2)) }
    val auth = server.auth()

    val got = withContext(Dispatchers.Default) { (1..10).map { async { auth.accessToken() } }.awaitAll() }

    assertEquals(List(10) { "at2" }, got)
    assertEquals(1, server.calls("/token"))
    val form = server.forms.single { it.first == "/token" }.second
    assertEquals("refresh_token", form["grant_type"])
    assertEquals("rt1", form["refresh_token"])
    assertTrue(server.store.value!!.contains("rt2"))
  }

  @Test
  fun aRejectedRefreshTokenSignsOut() = runTest {
    server.store.value = stored(expiresAt = 0)
    server.handlers["/token"] = { json("""{"error":"invalid_grant","error_description":"refresh token reused"}""", HttpStatusCode.BadRequest) }
    val auth = server.auth()

    assertEquals(PolarisException.SIGNED_OUT, assertFailsWith<PolarisException> { auth.accessToken() }.error)
    assertNull(server.store.value)
    assertNull(auth.tokens())
  }

  @Test
  fun aFailedRefreshKeepsTheTokensForARetry() = runTest {
    server.store.value = stored(expiresAt = 0)
    server.handlers["/token"] = { json("""{"error":"server_error"}""", HttpStatusCode.InternalServerError) }
    val auth = server.auth()

    assertEquals("server_error", assertFailsWith<PolarisException> { auth.accessToken() }.error)
    server.handlers["/token"] = { json(tokens(2)) }
    assertEquals("at2", auth.accessToken())
  }

  @Test
  fun signOutRevokesAndForgetsEvenOffline() = runTest {
    server.store.value = stored()
    val auth = server.auth()
    auth.signOut()
    assertEquals(mapOf("token" to "rt1", "token_type_hint" to "refresh_token", "client_id" to "app"), server.forms.single().second)
    assertNull(server.store.value)

    server.store.value = stored()
    server.handlers["/revoke"] = { throw IOException("offline") }
    val offline = server.auth()
    offline.signOut()
    assertNull(server.store.value)
    assertEquals(PolarisException.SIGNED_OUT, assertFailsWith<PolarisException> { offline.accessToken() }.error)
  }

  @Test
  fun deleteAccountAsksForAFreshSignIn() = runTest {
    server.store.value = stored()
    server.handlers["/v1/auth/delete"] = {
      respond("", HttpStatusCode.Unauthorized, headersOf(HttpHeaders.WWWAuthenticate, """Bearer error="insufficient_user_authentication", max_age="600""""))
    }
    val auth = server.auth()
    assertEquals(PolarisException.REAUTHENTICATE, assertFailsWith<PolarisException> { auth.deleteAccount() }.error)
    assertNotNull(server.store.value)

    server.handlers["/v1/auth/delete"] = { respond("", HttpStatusCode.NoContent) }
    auth.deleteAccount()
    assertNull(server.store.value)
  }

  @Test
  fun deleteAccountSendsTheAccessToken() = runTest {
    server.store.value = stored()
    var bearer: String? = null
    val auth = Polaris(PolarisConfig("https://auth.test/", "app"), server.store, HttpClient(MockEngine { req ->
      bearer = req.headers[HttpHeaders.Authorization]
      respond("", HttpStatusCode.NoContent)
    }))
    auth.deleteAccount()
    assertEquals("Bearer at1", bearer)
  }

  @Test
  fun setNicknameSendsItWithTheAccessToken() = runTest {
    server.store.value = stored()
    server.handlers["/v1/auth/profile"] = { json("""{"nickname":"小明","picture":"https://auth.test/avatars/K"}""") }
    val auth = server.auth()
    assertEquals(Profile("小明", "https://auth.test/avatars/K"), auth.setNickname(" 小明 "))
    assertEquals("""{"nickname":" 小明 "}""", server.bodies.last { it.first == "/v1/auth/profile" }.second)
    assertEquals("Bearer at1", server.authHeaders.last { it.first == "/v1/auth/profile" }.second)

    server.handlers["/v1/auth/profile"] = {
      json("""{"error":"invalid_request","error_description":"昵称最多 32 个字符"}""", HttpStatusCode.BadRequest)
    }
    val e = assertFailsWith<PolarisException> { auth.setNickname("x".repeat(33)) }
    assertEquals("invalid_request", e.error)
    assertEquals("昵称最多 32 个字符", e.description)
  }

  @Test
  fun uploadAvatarSendsTheImageBytes() = runTest {
    server.store.value = stored()
    var sent: ByteArray? = null
    var method: String? = null
    val auth = Polaris(PolarisConfig("https://auth.test", "app"), server.store, HttpClient(MockEngine { req ->
      method = req.method.value
      sent = (req.body as? OutgoingContent.ByteArrayContent)?.bytes()
      json("""{"picture":"https://auth.test/avatars/NEW"}""")
    }))
    val png = byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte())
    assertEquals(Profile(picture = "https://auth.test/avatars/NEW"), auth.uploadAvatar(png))
    assertEquals("PUT", method)
    assertTrue(png.contentEquals(sent))
  }

  @Test
  fun profileCallsSignOutOnceTheSessionIsGone() = runTest {
    server.store.value = stored()
    server.handlers["/v1/auth/profile/avatar"] = { respond("", HttpStatusCode.Unauthorized) }
    val auth = server.auth()
    assertEquals(PolarisException.SIGNED_OUT, assertFailsWith<PolarisException> { auth.removeAvatar() }.error)
    assertNull(server.store.value)
  }

  @Test
  fun termsComeFromTheServer() = runTest {
    server.handlers["/v1/auth/terms"] = { json("""{"terms_url":"https://t","privacy_url":"https://p","version":"v2"}""") }
    assertEquals(Terms("https://t", "https://p", "v2"), server.auth().terms())
  }

  // Passkey: begin gives the sheet its options, then the assertion goes back
  // on the same auth_session (ADR 0014). No PoW: begin checks no credential.
  @Test
  fun passkeySignInBeginsThenSubmitsTheAssertion() = runTest {
    server.handlers["/v1/auth/challenge"] = { form ->
      when (form["passkey"]) {
        "begin" -> json("""{"auth_session":"s1","options":{"publicKey":{"challenge":"ch","rpId":"auth.test"}}}""")
        "assertion" -> json("""{"authorization_code":"c1"}""")
        else -> error("unexpected $form")
      }
    }
    val sheet = FakePasskeys(response = "assertion")
    val auth = server.auth(sheet)

    assertEquals(SignInStep.SignedIn, auth.signInWithPasskey(termsVersion = "2026-01"))

    // The sheet takes what the browser would put under publicKey.
    assertEquals("""{"challenge":"ch","rpId":"auth.test"}""", sheet.given.single())
    val (_, begin) = server.forms.first { it.first == "/v1/auth/challenge" }
    assertEquals("app", begin["client_id"])
    assertEquals("openid offline_access", begin["scope"])
    assertEquals("S256", begin["code_challenge_method"])
    assertEquals(0, server.calls("/altcha/challenge"))
    val (_, assertion) = server.forms.filter { it.first == "/v1/auth/challenge" }.last()
    assertEquals("s1", assertion["auth_session"])
    assertEquals("assertion", assertion["passkey"])
    assertEquals(listOf<String?>("app"), server.forms.filter { it.first == "/token" }.map { it.second["client_id"] })
  }

  @Test
  fun passkeySignInTakesTheNextStepAfterTheAssertion() = runTest {
    server.handlers["/v1/auth/challenge"] = { form ->
      when (form["passkey"]) {
        "begin" -> json("""{"auth_session":"s1","options":{"publicKey":{"challenge":"ch"}}}""")
        "assertion" -> json(insufficient("s1", "phone"), HttpStatusCode.Forbidden)
        else -> error("unexpected $form")
      }
    }
    val auth = server.auth(FakePasskeys(response = "assertion"))

    val next = assertIs<SignInStep.PhoneRequired>(auth.signInWithPasskey(termsVersion = ""))
    assertEquals("s1", next.session.id)
  }

  // A dismissed sheet leaves the sign-in as it was; it is not a failure.
  @Test
  fun dismissingThePasskeySheetIsNotAFailure() = runTest {
    server.handlers["/v1/auth/challenge"] = { json("""{"auth_session":"s1","options":{"publicKey":{"challenge":"ch"}}}""") }
    val auth = server.auth(FakePasskeys(response = null))

    assertEquals(PolarisException.PASSKEY_CANCELLED, assertFailsWith<PolarisException> { auth.signInWithPasskey("") }.error)
    assertEquals(1, server.calls("/v1/auth/challenge"))
  }

  // No sheet (or one this device cannot use): the App hides its Passkey entry.
  @Test
  fun passkeyWithoutASheetIsUnavailable() = runTest {
    assertEquals(false, server.auth().passkeysAvailable())
    assertFalse(server.auth(FakePasskeys(available = false)).passkeysAvailable())
    assertTrue(server.auth(FakePasskeys()).passkeysAvailable())

    val auth = server.auth()
    assertEquals(PolarisException.PASSKEY_UNAVAILABLE, assertFailsWith<PolarisException> { auth.signInWithPasskey("") }.error)
    assertEquals(PolarisException.PASSKEY_UNAVAILABLE, assertFailsWith<PolarisException> { auth.addPasskey() }.error)
    assertEquals(0, server.forms.size)
  }

  // The Account API takes only the account center's own tokens, so adding a
  // Passkey signs in as polaris-account first, in memory only.
  @Test
  fun addPasskeyUsesTheAccountCentersToken() = runTest {
    server.handlers["/v1/account/passkeys/options"] = { json("""{"options":{"publicKey":{"challenge":"ch","rp":{"id":"auth.test"}}}}""") }
    server.handlers["/v1/account/passkeys"] = { json("""{"id":"p1","name":"Chrome","createdAt":"2026-10-10T00:00:00Z"}""") }
    server.handlers["/v1/auth/challenge"] = { json("""{"authorization_code":"c1"}""") }
    val sheet = FakePasskeys(response = """{"id":"cred","type":"public-key"}""")
    val auth = server.auth(sheet)

    assertEquals(SignInStep.SignedIn, auth.signInForAccountWithPassword("alice", "pw", termsVersion = ""))
    val added = auth.addPasskey()

    assertEquals(Passkey("p1", "Chrome", "2026-10-10T00:00:00Z"), added)
    val (_, signIn) = server.forms.first { it.first == "/v1/auth/challenge" }
    assertEquals(PolarisConfig.ACCOUNT_CLIENT_ID, signIn["client_id"])
    assertEquals("openid", signIn["scope"])
    assertEquals(listOf<String?>("Bearer at1", "Bearer at1"), server.authHeaders.filter { it.first.startsWith("/v1/account/") }.map { it.second })
    assertEquals("""{"challenge":"ch","rp":{"id":"auth.test"}}""", sheet.given.last())
    assertEquals("""{"id":"cred","type":"public-key"}""", server.bodies.last { it.first == "/v1/account/passkeys" }.second)
    // The account center's tokens are not the App's: the store is untouched.
    assertNull(auth.tokens())

    auth.signOut()
    assertNull(auth.tokens())
  }

  @Test
  fun addPasskeyWithoutAnAccountSignInAsksToReauthenticate() = runTest {
    val auth = server.auth(FakePasskeys())

    assertEquals(PolarisException.REAUTHENTICATE, assertFailsWith<PolarisException> { auth.addPasskey() }.error)
    assertEquals(0, server.forms.size)
  }

  // 10 minutes after signing in to the account center, the Account API
  // refuses: sign in again and retry.
  @Test
  fun aStaleAccountSignInAsksToReauthenticate() = runTest {
    server.handlers["/v1/auth/challenge"] = { json("""{"authorization_code":"c1"}""") }
    server.handlers["/v1/account/passkeys/options"] = { json("""{"title":"Forbidden","status":403,"detail":"请先重新验证身份"}""", HttpStatusCode.Forbidden) }
    val auth = server.auth(FakePasskeys())

    auth.signInForAccountWithPassword("alice", "pw", termsVersion = "")
    val e = assertFailsWith<PolarisException> { auth.addPasskey() }
    assertEquals(PolarisException.REAUTHENTICATE, e.error)
    assertEquals("请先重新验证身份", e.description)
  }

  // The Account API refuses a second copy of a Passkey with a Huma error.
  @Test
  fun aRefusedRegistrationKeepsTheServersWords() = runTest {
    server.handlers["/v1/auth/challenge"] = { json("""{"authorization_code":"c1"}""") }
    server.handlers["/v1/account/passkeys/options"] = { json("""{"options":{"publicKey":{"challenge":"ch"}}}""") }
    server.handlers["/v1/account/passkeys"] = { json("""{"title":"Conflict","status":409,"detail":"这把 Passkey 已经存在"}""", HttpStatusCode.Conflict) }
    val auth = server.auth(FakePasskeys())

    auth.signInForAccountWithPassword("alice", "pw", termsVersion = "")
    val e = assertFailsWith<PolarisException> { auth.addPasskey() }
    assertEquals("http_409", e.error)
    assertEquals("这把 Passkey 已经存在", e.description)
  }
}

fun insufficient(session: String, next: String) = """{"error":"insufficient_authorization","auth_session":"$session","next":"$next"}"""

fun stored(expiresAt: Long = 4102444800) = """{"accessToken":"at1","refreshToken":"rt1","idToken":"id1","expiresAt":$expiresAt}"""
