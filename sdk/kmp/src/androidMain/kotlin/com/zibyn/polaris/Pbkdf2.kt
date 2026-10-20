package com.zibyn.polaris

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// PBEKeySpec takes the password as chars; the nonce is raw bytes, so PBKDF2
// (RFC 8018) is spelled out over HMAC. One block covers 32-byte keys.
internal actual fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
  require(keyLength <= 32) { "keyLength over one SHA-256 block" }
  val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
  var u = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1))
  val t = u.copyOf()
  repeat(iterations - 1) {
    u = mac.doFinal(u)
    for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
  }
  return t.copyOf(keyLength)
}

internal actual fun sha256(data: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(data)
