package com.zibyn.polaris

import io.ktor.client.HttpClient
import io.ktor.client.plugins.UserAgent
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.delete
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.ParametersBuilder
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.uuid.Uuid

public class PolarisConfig(
  /** Polaris's address, e.g. `https://auth.example.com`. */
  public val issuer: String,
  /** The App's Application (public) in Polaris. */
  public val clientId: String,
  public val scope: String = "openid offline_access",
) {
  public companion object {
    /**
     * The built-in Application the account center signs in as. Tokens issued
     * to it are for the Account API, which is what adding a Passkey needs;
     * [Polaris.signInForAccountWithPasskey] and friends sign in to it.
     */
    public const val ACCOUNT_CLIENT_ID: String = "polaris-account"
  }
}

/** The tokens of a signed-in User; [expiresAt] is the access token's expiry in Unix seconds. */
@Serializable
public data class Tokens(
  val accessToken: String,
  val refreshToken: String? = null,
  val idToken: String? = null,
  val expiresAt: Long,
)

/** What the terms checkbox links to, and the version to sign in with once it is ticked. */
public data class Terms(val termsUrl: String, val privacyUrl: String, val version: String)

/** The User's 用户资料, as every Application sees it; null for unset. */
@Serializable
public data class Profile(
  val nickname: String? = null,
  /** The avatar's URL: a 512×512 JPEG, a new URL after every upload. */
  val picture: String? = null,
)

/** A Passkey on the User's account, from the account center. */
@Serializable
public data class Passkey(
  val id: String,
  /** How the User knows it: the provider's name until they rename it. */
  val name: String,
  val createdAt: String,
  /** Null until it has signed in once. */
  val lastUsedAt: String? = null,
)

/** A sign-in in progress; pass it to the next step. */
public class AuthSession internal constructor(
  internal val id: String,
  internal val verifier: String,
  internal val termsVersion: String,
  // Signing in to the account center rather than the App: a different
  // Application, whose tokens go to the Account API.
  internal val account: Boolean = false,
)

public sealed interface SignInStep {
  public data object SignedIn : SignInStep
  /** A code went out: ask for it and call [Polaris.verifyCode]. */
  public class CodeSent(public val session: AuthSession) : SignInStep
  /** The instance wants a phone number the User has not bound: [Polaris.sendCode] to one with this session. */
  public class PhoneRequired(public val session: AuthSession) : SignInStep
  /** The User has 两步验证 on: ask for a code from their authenticator ([Polaris.verifyTotp]) or a 恢复码 ([Polaris.verifyRecoveryCode]). */
  public class TotpRequired(public val session: AuthSession) : SignInStep
}

/**
 * An error from Polaris or the SDK. [error] is the OAuth error code, or
 * one of the constants below; for `invalid_request` [description] says what
 * the User got wrong in words fit to show.
 */
public class PolarisException(public val error: String, public val description: String? = null) :
  Exception(if (description == null) error else "$error: $description") {
  public companion object {
    /** No User is signed in, or their Session ended (signed out elsewhere, refresh token reused, deleted). Sign in again. */
    public const val SIGNED_OUT: String = "signed_out"
    /** Deleting the account needs a sign-in in the last 10 minutes: sign in again, then retry. */
    public const val REAUTHENTICATE: String = "insufficient_user_authentication"
    /** The server asked for a sign-in step this SDK version does not know: ask the User to update the App. */
    public const val UNSUPPORTED_STEP: String = "unsupported_step"
    /** The User dismissed the system Passkey sheet. Not a failure: leave the sign-in as it was. */
    public const val PASSKEY_CANCELLED: String = "passkey_cancelled"
    /** This device cannot do Passkeys (an Android phone without Google Play services), or the App passed no [PasskeyPrompt]. */
    public const val PASSKEY_UNAVAILABLE: String = "passkey_unavailable"
  }
}

/**
 * Signs a User in through the direct auth API and holds their tokens.
 * Behaviour (single-flight refresh, reuse, sign-out): docs/sdk-behavior.md.
 */
public class Polaris(
  private val config: PolarisConfig,
  private val store: TokenStore,
  http: HttpClient = HttpClient(),
  // The system's Passkey sheet; without it Passkey sign-in and adding both
  // refuse, and passkeysAvailable() is false.
  private val passkeys: PasskeyPrompt? = null,
) {
  // Swift never sees the defaults above: Kotlin/Native exports one initializer
  // with every parameter, so the plain two-argument form is spelled out here.
  public constructor(config: PolarisConfig, store: TokenStore) : this(config, store, HttpClient())

  // The App's client with the SDK's User-Agent on top: the account center
  // shows the Session by it.
  private val http = http.config { install(UserAgent) { agent = userAgent(currentDevice()) } }
  private val issuer = config.issuer.trimEnd('/')
  private val json = Json { ignoreUnknownKeys = true }
  // Guards the tokens: one refresh at a time, and sign-in, sign-out and
  // deletion never interleave with one.
  private val mutex = Mutex()
  private var loaded = false
  private var current: Tokens? = null
  // The account center's session (docs/sdk-behavior.md#passkey): in memory
  // only, because everything that uses it — adding a Passkey — needs a
  // sign-in from the last 10 minutes anyway.
  private var account: Tokens? = null

  @Throws(Exception::class)
  public suspend fun terms(): Terms {
    val r = http.get("$issuer/v1/auth/terms")
    val t = decode<TermsResponse>(r)
    return Terms(t.termsUrl, t.privacyUrl, t.version)
  }

  /** Sends a code to a +86 phone number or an email address. Solves a proof of work first, which takes about a second. */
  @Throws(Exception::class)
  public suspend fun sendCode(identifier: String, termsVersion: String): SignInStep.CodeSent =
    sendCode(identifier, null, termsVersion)

  /** Sends a code within [session], after [SignInStep.PhoneRequired]. */
  @Throws(Exception::class)
  public suspend fun sendCode(identifier: String, session: AuthSession): SignInStep.CodeSent =
    sendCode(identifier, session, session.termsVersion)

  private suspend fun sendCode(
    identifier: String,
    session: AuthSession?,
    termsVersion: String,
    asAccount: Boolean = false,
  ): SignInStep.CodeSent {
    val altcha = altcha()
    return challenge(session, termsVersion, asAccount) {
      append("identifier", identifier)
      append("altcha", altcha)
    } as? SignInStep.CodeSent ?: throw PolarisException("unexpected_response", "sending a code signed in")
  }

  @Throws(Exception::class)
  public suspend fun verifyCode(session: AuthSession, code: String): SignInStep =
    challenge(session, session.termsVersion) { append("code", code) }

  /** Enters a code from the User's authenticator, after [SignInStep.TotpRequired]. */
  @Throws(Exception::class)
  public suspend fun verifyTotp(session: AuthSession, code: String): SignInStep =
    challenge(session, session.termsVersion) { append("totp", code) }

  /** Enters one of the User's 恢复码 instead of a TOTP code, after [SignInStep.TotpRequired]. */
  @Throws(Exception::class)
  public suspend fun verifyRecoveryCode(session: AuthSession, code: String): SignInStep =
    challenge(session, session.termsVersion) { append("recovery_code", code) }

  /** Signs in with an Identifier (username, phone number or email) and its password. */
  @Throws(Exception::class)
  public suspend fun signInWithPassword(identifier: String, password: String, termsVersion: String): SignInStep =
    passwordSignIn(identifier, password, termsVersion, asAccount = false)

  private suspend fun passwordSignIn(
    identifier: String,
    password: String,
    termsVersion: String,
    asAccount: Boolean,
  ): SignInStep {
    val altcha = altcha()
    return challenge(null, termsVersion, asAccount) {
      append("username", identifier)
      append("password", password)
      append("altcha", altcha)
    }
  }

  /**
   * Signs in at the Provider [provider] (its Provider ID) with what its SDK
   * gave the App, which this SDK forwards as is: for Sign in with Apple, the
   * `authorizationCode` of the credential. Throws `invalid_grant` when the
   * Provider turns it down: have the User sign in with it again.
   */
  @Throws(Exception::class)
  public suspend fun signInWithProvider(provider: String, authorizationCode: String, termsVersion: String): SignInStep =
    challenge(null, termsVersion) {
      append("provider", provider)
      append("authorization_code", authorizationCode)
    }

  // About a second of hashing: off the caller's (often the main) thread.
  private suspend fun altcha(): String {
    val challenge = http.get("$issuer/altcha/challenge").bodyAsText()
    return withContext(Dispatchers.Default) { solveAltcha(challenge) }
  }

  /** Whether this device can do Passkeys; the App hides its Passkey entry when it cannot. */
  public fun passkeysAvailable(): Boolean = passkeys?.available ?: false

  /**
   * Signs in with a Passkey in two round trips: the SDK asks Polaris for
   * the assertion options, hands them to the system sheet, and submits what
   * the sheet produced. The User sees one system prompt and nothing else.
   * Dismissing it throws [PolarisException.PASSKEY_CANCELLED], which is not
   * a failure: leave the sign-in as it was.
   */
  @Throws(Exception::class)
  public suspend fun signInWithPasskey(termsVersion: String): SignInStep =
    passkeySignIn(termsVersion, asAccount = false)

  /** Sends a code for signing in to the account center, the way [sendCode] does for the App. */
  @Throws(Exception::class)
  public suspend fun sendAccountCode(identifier: String, termsVersion: String): SignInStep.CodeSent =
    sendCode(identifier, session = null, termsVersion, asAccount = true)

  /** Signs in to the account center with an Identifier and its password, the way [signInWithPassword] does for the App. */
  @Throws(Exception::class)
  public suspend fun signInForAccountWithPassword(identifier: String, password: String, termsVersion: String): SignInStep =
    passwordSignIn(identifier, password, termsVersion, asAccount = true)

  /** Signs in to the account center with a Passkey; [signInWithPasskey] for what the App itself signs in as. */
  @Throws(Exception::class)
  public suspend fun signInForAccountWithPasskey(termsVersion: String): SignInStep =
    passkeySignIn(termsVersion, asAccount = true)

  /**
   * Adds a Passkey to the User's account, through the system sheet. Needs an
   * account center session — [signInForAccountWithPasskey], [sendAccountCode]
   * or [signInForAccountWithPassword] — from the last 10 minutes; without one
   * it throws [PolarisException.REAUTHENTICATE]. Dismissing the sheet
   * throws [PolarisException.PASSKEY_CANCELLED].
   */
  @Throws(Exception::class)
  public suspend fun addPasskey(): Passkey {
    val prompt = systemPasskeys()
    val token = mutex.withLock { accountAccessToken() }
    val begin = http.post("$issuer/v1/account/passkeys/options") { bearerAuth(token) }
    if (begin.status == HttpStatusCode.Forbidden) throw reauthenticated(begin)
    val options = decode<PasskeyOptionsResponse>(begin).options.underPublicKey()
    val registration = prompt.create(options) ?: throw PolarisException(PolarisException.PASSKEY_CANCELLED)
    val r = http.post("$issuer/v1/account/passkeys") {
      bearerAuth(token)
      contentType(ContentType.Application.Json)
      setBody(registration)
    }
    if (r.status == HttpStatusCode.Forbidden) throw reauthenticated(r)
    return decode<Passkey>(r)
  }

  private suspend fun passkeySignIn(termsVersion: String, asAccount: Boolean): SignInStep {
    val prompt = systemPasskeys()
    val verifier = newVerifier()
    val begin = http.submitForm("$issuer/v1/auth/challenge", Parameters.build {
      firstStep(verifier, termsVersion, asAccount)
      append("passkey", "begin")
    })
    val started = decode<PasskeyBeginResponse>(begin)
    val assertion = prompt.get(started.options.underPublicKey())
      ?: throw PolarisException(PolarisException.PASSKEY_CANCELLED)
    return challenge(AuthSession(started.authSession, verifier, termsVersion, asAccount), termsVersion) {
      append("passkey", assertion)
    }
  }

  private fun systemPasskeys(): PasskeyPrompt =
    passkeys?.takeIf { it.available }
      ?: throw PolarisException(PolarisException.PASSKEY_UNAVAILABLE, "this device has no system Passkey sheet")

  // The first request of a sign-in: everything but the credentials themselves.
  private fun ParametersBuilder.firstStep(verifier: String, termsVersion: String, asAccount: Boolean) {
    append("client_id", clientId(asAccount))
    append("terms_version", termsVersion)
    append("response_type", "code")
    append("scope", if (asAccount) ACCOUNT_SCOPE else config.scope)
    append("code_challenge", base64Url.encode(sha256(verifier.encodeToByteArray())))
    append("code_challenge_method", "S256")
  }

  private fun clientId(asAccount: Boolean): String =
    if (asAccount) PolarisConfig.ACCOUNT_CLIENT_ID else config.clientId

  private suspend fun challenge(
    session: AuthSession?,
    termsVersion: String,
    asAccount: Boolean = false,
    step: ParametersBuilder.() -> Unit,
  ): SignInStep {
    val onAccount = session?.account ?: asAccount
    val verifier = session?.verifier ?: newVerifier()
    val r = http.submitForm("$issuer/v1/auth/challenge", Parameters.build {
      if (session != null) {
        append("client_id", clientId(onAccount))
        append("terms_version", termsVersion)
        append("auth_session", session.id)
      } else {
        firstStep(verifier, termsVersion, onAccount)
      }
      step()
    })
    if (r.status == HttpStatusCode.Forbidden) {
      val body = r.bodyAsText()
      val e = json.decodeFromString<ErrorResponse>(body)
      if (e.error == "insufficient_authorization" && e.authSession != null) {
        val next = AuthSession(e.authSession, verifier, termsVersion, onAccount)
        // Unknown values come from a newer server: fail rather than guess (ADR 0010).
        return when (e.next) {
          "code" -> SignInStep.CodeSent(next)
          "phone" -> SignInStep.PhoneRequired(next)
          "totp" -> SignInStep.TotpRequired(next)
          else -> throw PolarisException(PolarisException.UNSUPPORTED_STEP, "next step not supported by this SDK version: ${e.next}")
        }
      }
      throw errorOf(r, body)
    }
    val code = decode<CodeResponse>(r).authorizationCode
    val t = tokenRequest(clientId(onAccount)) {
      append("grant_type", "authorization_code")
      append("code", code)
      append("code_verifier", verifier)
    }
    mutex.withLock { if (onAccount) account = t else save(t) }
    return SignInStep.SignedIn
  }

  /** The current tokens, or null when signed out. The access token may have expired: use [accessToken] to call APIs. */
  public suspend fun tokens(): Tokens? = mutex.withLock { load() }

  /**
   * A live access token, refreshed when it has under 30 seconds left. While
   * one refresh is under way, other callers wait for it rather than refresh
   * again. Throws [PolarisException.SIGNED_OUT] once the Session is gone.
   */
  @Throws(Exception::class)
  public suspend fun accessToken(): String = mutex.withLock { freshAccessToken() }

  // Call with the mutex held.
  private suspend fun freshAccessToken(): String {
    val t = load() ?: throw signedOut()
    if (t.expiresAt - 30 > now()) return t.accessToken
    val refresh = t.refreshToken ?: run { save(null); throw signedOut() }
    // Not cancellable: once the server rotates, dropping the answer would
    // leave only the spent token, whose reuse ends the Session.
    return withContext(NonCancellable) {
      val fresh = try {
        tokenRequest(clientId(false)) {
          append("grant_type", "refresh_token")
          append("refresh_token", refresh)
        }
      } catch (e: PolarisException) {
        // The refresh token is dead: revoked, expired, or reused (which ends
        // the Session on the server). Other failures keep it for a retry.
        if (e.error == "invalid_grant") { save(null); throw signedOut() }
        throw e
      }
      save(fresh.copy(refreshToken = fresh.refreshToken ?: refresh, idToken = fresh.idToken ?: t.idToken))
      fresh.accessToken
    }
  }

  /** Ends the Session on the server, best effort, and forgets the tokens whatever happens. */
  @Throws(Exception::class)
  public suspend fun signOut(): Unit = mutex.withLock {
    val refresh = load()?.refreshToken
    try {
      if (refresh != null) {
        http.submitForm("$issuer/revoke", Parameters.build {
          append("token", refresh)
          append("token_type_hint", "refresh_token")
          append("client_id", config.clientId)
        })
      }
    } catch (e: Exception) {
      if (e is CancellationException) throw e
    } finally {
      save(null)
      account = null
    }
  }

  /**
   * Deletes the User's account at once and signs out. Needs a sign-in in
   * the last 10 minutes, else throws [PolarisException.REAUTHENTICATE]:
   * confirm with the User, sign them in again, and call this again.
   */
  @Throws(Exception::class)
  public suspend fun deleteAccount() {
    mutex.withLock {
      val token = freshAccessToken()
      val r = http.post("$issuer/v1/auth/delete") { bearerAuth(token) }
      when {
        r.status.isSuccess() -> { save(null); account = null }
        r.status == HttpStatusCode.Unauthorized -> {
          val why = r.headers[HttpHeaders.WWWAuthenticate].orEmpty()
          if ("insufficient_user_authentication" in why) throw PolarisException(PolarisException.REAUTHENTICATE)
          save(null)
          account = null
          throw signedOut()
        }
        else -> decode<Unit>(r)
      }
    }
  }

  /**
   * Sets the User's nickname, trimmed; an empty one clears it. At most 32
   * characters and no control characters, else throws [PolarisException]
   * `invalid_request` with the reason to show.
   */
  @Throws(Exception::class)
  public suspend fun setNickname(nickname: String): Profile = profileCall {
    http.patch("$issuer/v1/auth/profile") {
      bearerAuth(it)
      contentType(ContentType.Application.Json)
      setBody(json.encodeToString(NicknameRequest(nickname)))
    }
  }

  /**
   * Uploads [image] (JPEG, PNG or WebP bytes, at most 5 MB) as the User's
   * avatar; Polaris crops it square and keeps a 512×512 JPEG. A file that is
   * not one throws [PolarisException] `invalid_request`.
   */
  @Throws(Exception::class)
  public suspend fun uploadAvatar(image: ByteArray): Profile = profileCall {
    http.put("$issuer/v1/auth/profile/avatar") {
      bearerAuth(it)
      contentType(ContentType.Application.OctetStream)
      setBody(image)
    }
  }

  /** Removes the User's avatar. */
  @Throws(Exception::class)
  public suspend fun removeAvatar(): Profile = profileCall {
    http.delete("$issuer/v1/auth/profile/avatar") { bearerAuth(it) }
  }

  // A 401 means the Session is gone: forget the tokens.
  private suspend fun profileCall(call: suspend (token: String) -> HttpResponse): Profile {
    val r = call(accessToken())
    if (r.status == HttpStatusCode.Unauthorized) {
      mutex.withLock { save(null); account = null }
      throw signedOut()
    }
    return decode<Profile>(r)
  }

  // Call with the mutex held. The account center's token, which the Account
  // API takes; in memory only, so it is either from this run or gone.
  private fun accountAccessToken(): String {
    val t = account
    if (t != null && t.expiresAt - 30 > now()) return t.accessToken
    account = null
    throw reauthenticate()
  }

  private suspend fun tokenRequest(clientId: String, grant: ParametersBuilder.() -> Unit): Tokens {
    val r = http.submitForm("$issuer/token", Parameters.build {
      grant()
      append("client_id", clientId)
    })
    val t = decode<TokenResponse>(r)
    return Tokens(t.accessToken, t.refreshToken, t.idToken, now() + t.expiresIn)
  }

  private fun load(): Tokens? {
    if (!loaded) {
      current = store.read()?.let { runCatching { json.decodeFromString<Tokens>(it) }.getOrNull() }
      loaded = true
    }
    return current
  }

  // Memory first: should the store fail, this instance still holds the
  // rotated refresh token and won't reuse the spent one.
  private fun save(t: Tokens?) {
    current = t
    loaded = true
    store.write(t?.let { json.encodeToString(it) })
  }

  private suspend inline fun <reified T> decode(r: HttpResponse): T {
    val body = r.bodyAsText()
    if (r.status.isSuccess()) return if (T::class == Unit::class) Unit as T else json.decodeFromString(body)
    throw errorOf(r, body)
  }

  // The direct auth API answers OAuth errors (error / error_description), the
  // Account API Huma errors (title / detail).
  private fun errorOf(r: HttpResponse, body: String): PolarisException {
    val e = runCatching { json.decodeFromString<ErrorResponse>(body) }.getOrNull()
    return PolarisException(
      e?.error ?: "http_${r.status.value}",
      e?.description ?: e?.detail ?: e?.title,
    )
  }

  // The Account API refuses a sign-in older than 10 minutes with a 403.
  private suspend fun reauthenticated(r: HttpResponse) = reauthenticate(errorOf(r, r.bodyAsText()))

  private fun reauthenticate(from: PolarisException? = null) =
    PolarisException(PolarisException.REAUTHENTICATE, from?.description ?: "sign in to the account center first")

  private fun signedOut() = PolarisException(PolarisException.SIGNED_OUT)

  private fun now() = Clock.System.now().epochSeconds
}

private const val ACCOUNT_SCOPE = "openid"

private val base64Url = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

// The system sheets take the options the browser would put under publicKey;
// Polaris answers with the PublicKeyCredential*OptionsJSON wrapped in it.
private fun JsonElement.underPublicKey(): String =
  (this as? JsonObject)?.get("publicKey")?.toString() ?: toString()

// RFC 7636: 43 base64url characters. Uuid.random() is cryptographically
// secure on every platform; two give 244 random bits (each fixes 6).
private fun newVerifier(): String = base64Url.encode(Uuid.random().toByteArray() + Uuid.random().toByteArray())

@Serializable private class TermsResponse(
  @SerialName("terms_url") val termsUrl: String,
  @SerialName("privacy_url") val privacyUrl: String,
  val version: String,
)

// passkey=begin answers 200 with the auth_session the assertion goes back on.
@Serializable private class PasskeyBeginResponse(
  @SerialName("auth_session") val authSession: String,
  val options: JsonElement,
)

@Serializable private class PasskeyOptionsResponse(val options: JsonElement)

@Serializable private class NicknameRequest(val nickname: String)

@Serializable private class CodeResponse(@SerialName("authorization_code") val authorizationCode: String)

@Serializable private class TokenResponse(
  @SerialName("access_token") val accessToken: String,
  @SerialName("refresh_token") val refreshToken: String? = null,
  @SerialName("id_token") val idToken: String? = null,
  @SerialName("expires_in") val expiresIn: Long,
)

@Serializable private class ErrorResponse(
  // The direct auth API's fields.
  val error: String? = null,
  @SerialName("error_description") val description: String? = null,
  @SerialName("auth_session") val authSession: String? = null,
  val next: String? = null,
  // The Account API's (Huma's).
  val title: String? = null,
  val detail: String? = null,
)
