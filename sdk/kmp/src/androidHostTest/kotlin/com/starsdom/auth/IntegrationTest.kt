package com.starsdom.auth

import com.sun.net.httpserver.HttpServer
import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpSend
import io.ktor.client.plugins.plugin
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeTrue
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The SDK against a running Polaris: scripts/integration.sh starts one and
 * sets the environment. Skipped without it.
 */
class IntegrationTest {
  private val url = System.getenv("STARS_AUTH_TEST_URL")
  private val config by lazy { StarsAuthConfig(url!!, System.getenv("STARS_AUTH_TEST_CLIENT")!!) }
  private var tokenCalls = 0
  private val http = HttpClient().apply {
    plugin(HttpSend).intercept { req ->
      if (req.url.build().encodedPath == "/token") tokenCalls++
      execute(req)
    }
  }
  private val codes = LinkedBlockingQueue<String>()

  private fun auth(store: TokenStore = MemoryTokenStore()) = StarsAuth(config, store, http)

  @Test
  fun signInRefreshSignOutAndDelete() = runBlocking {
    assumeTrue("set by scripts/integration.sh", url != null)
    val terms = auth().terms().version

    // Password: the owner, whose tokens (this App defaults to the Management
    // API) point the email Channel at codes, below.
    val ownerStore = MemoryTokenStore()
    val owner = auth(ownerStore)
    assertEquals(SignInStep.SignedIn, owner.signInWithPassword(System.getenv("STARS_AUTH_TEST_USERNAME")!!, System.getenv("STARS_AUTH_TEST_PASSWORD")!!, terms))
    val catcher = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
      createContext("/") { ex ->
        val body = Json.parseToJsonElement(ex.requestBody.readBytes().decodeToString()).jsonObject
        codes += body.getValue("code").jsonPrimitive.content
        ex.sendResponseHeaders(204, -1)
        ex.close()
      }
      start()
    }
    try {
      val put = http.put("$url/v1/management/channels/email") {
        bearerAuth(owner.accessToken())
        contentType(ContentType.Application.Json)
        setBody("""{"plugin":"webhook","config":{"url":"http://127.0.0.1:${catcher.address.port}/","secret":"s"}}""")
      }
      assertTrue(put.status.isSuccess(), "channel: ${put.status}")

      // Code: a new User.
      val store = MemoryTokenStore()
      signInByCode(auth(store), terms)

      // Ten callers, one refresh; the rotated token works.
      expire(store)
      val user = auth(store)
      tokenCalls = 0
      val got = withContext(Dispatchers.Default) { (1..10).map { async { user.accessToken() } }.awaitAll() }
      assertEquals(1, tokenCalls)
      assertEquals(1, got.toSet().size)
      expire(store)
      auth(store).accessToken()

      // A refresh token used twice ends the Session for every holder.
      val stale = store.value
      expire(store)
      auth(store).accessToken()
      assertSignedOut(auth(MemoryTokenStore(stale).also(::expire)))
      assertSignedOut(auth(store.also(::expire)))

      // Deletion, fresh from a sign-in.
      val again = MemoryTokenStore()
      val deleting = auth(again)
      signInByCode(deleting, terms)
      deleting.deleteAccount()
      assertNull(again.value)

      // The last owner can't leave.
      val refused = assertFailsWith<StarsAuthException> { owner.deleteAccount() }
      assertEquals("invalid_request", refused.error)
      assertNotNull(refused.description)
      assertNotNull(ownerStore.value)

      // Sign-out ends the Session on the server.
      val before = ownerStore.value
      owner.signOut()
      assertNull(ownerStore.value)
      assertSignedOut(auth(MemoryTokenStore(before).also(::expire)))
    } finally {
      catcher.stop(0)
    }
  }

  private suspend fun signInByCode(auth: StarsAuth, terms: String) {
    val sent = auth.sendCode("sdk-${System.nanoTime()}@example.com", terms)
    val code = codes.poll(10, TimeUnit.SECONDS) ?: error("no code arrived")
    assertIs<SignInStep.SignedIn>(auth.verifyCode(sent.session, code))
  }

  private suspend fun assertSignedOut(auth: StarsAuth) {
    assertEquals(StarsAuthException.SIGNED_OUT, assertFailsWith<StarsAuthException> { auth.accessToken() }.error)
  }

  private fun expire(store: MemoryTokenStore) {
    val t = Json.decodeFromString<Tokens>(store.value!!)
    store.value = Json.encodeToString(t.copy(expiresAt = 0))
  }
}
