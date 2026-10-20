package com.zibyn.polaris

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.io.encoding.Base64

/**
 * Solves an ALTCHA v2 challenge (GET /altcha/challenge, as JSON) the way
 * altcha-lib-go does with uint32 counters, and returns the base64 payload the
 * challenge endpoint takes as `altcha`. Only the PBKDF2/SHA-256 algorithm the
 * server uses is supported.
 */
internal fun solveAltcha(challengeJson: String): String {
  val challenge = Json.parseToJsonElement(challengeJson).jsonObject
  val params = challenge.getValue("parameters").jsonObject
  fun str(key: String) = params.getValue(key).jsonPrimitive.content
  require(str("algorithm") == "PBKDF2/SHA-256") { "unsupported ALTCHA algorithm ${str("algorithm")}" }
  val nonce = str("nonce").hexToByteArray()
  val salt = str("salt").hexToByteArray()
  val cost = params.getValue("cost").jsonPrimitive.int
  val keyLength = params["keyLength"]?.jsonPrimitive?.int ?: 32
  val prefix = str("keyPrefix").lowercase()
  val password = nonce.copyOf(nonce.size + 4)
  for (n in 0..Int.MAX_VALUE) {
    for (i in 0..3) password[nonce.size + i] = (n ushr (24 - 8 * i)).toByte()
    val key = pbkdf2Sha256(password, salt, cost, keyLength).toHexString()
    if (key.startsWith(prefix)) {
      val payload = buildJsonObject {
        // Sent back as it came: the server checks its signature.
        put("challenge", challenge)
        put("solution", buildJsonObject { put("counter", n); put("derivedKey", key) })
      }
      return Base64.encode(payload.toString().encodeToByteArray())
    }
  }
  error("ALTCHA challenge has no solution")
}

internal expect fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray

internal expect fun sha256(data: ByteArray): ByteArray
