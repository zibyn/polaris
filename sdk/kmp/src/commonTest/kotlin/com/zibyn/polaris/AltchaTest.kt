package com.zibyn.polaris

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals

class AltchaTest {
  // Made and solved by altcha-lib-go v2, the server's library.
  private val challenge = """{"parameters":{"algorithm":"PBKDF2/SHA-256","nonce":"554e47b3e19cb6fd8f7e8c23ead53957","salt":"2c5905e1896874850e3377650b76c0ff","cost":1000,"keyLength":32,"keyPrefix":"b88d630e56102e52b138467b8ab7e36a","expiresAt":4102444800},"signature":"f70eb1e0b7a4ed888fe312a532a93d1229a507ff17bf99123e803c1013393917"}"""

  @Test
  fun solvesWhatTheServerSolves() {
    val payload = Json.parseToJsonElement(Base64.decode(solveAltcha(challenge)).decodeToString()).jsonObject
    val solution = payload["solution"]!!.jsonObject
    assertEquals(37, solution["counter"]!!.jsonPrimitive.content.toInt())
    assertEquals("b88d630e56102e52b138467b8ab7e36a341e83d3c987a42548674274fc7a8599", solution["derivedKey"]!!.jsonPrimitive.content)
    // The challenge goes back untouched: the server checks its signature.
    assertEquals(Json.parseToJsonElement(challenge), payload["challenge"] as JsonObject)
  }
}
