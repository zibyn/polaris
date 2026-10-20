package com.zibyn.polaris

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CCKeyDerivationPBKDF
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreCrypto.kCCPBKDF2
import platform.CoreCrypto.kCCPRFHmacAlgSHA256
import platform.CoreCrypto.kCCSuccess

@OptIn(ExperimentalForeignApi::class)
internal actual fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
  val out = ByteArray(keyLength)
  val status = password.usePinned { p ->
    salt.usePinned { s ->
      out.usePinned { o ->
        CCKeyDerivationPBKDF(
          kCCPBKDF2, p.addressOf(0).reinterpret(), password.size.convert(),
          s.addressOf(0).reinterpret(), salt.size.convert(),
          kCCPRFHmacAlgSHA256, iterations.convert(),
          o.addressOf(0).reinterpret(), keyLength.convert(),
        )
      }
    }
  }
  check(status == kCCSuccess) { "CCKeyDerivationPBKDF: $status" }
  return out
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun sha256(data: ByteArray): ByteArray {
  val out = UByteArray(CC_SHA256_DIGEST_LENGTH)
  data.usePinned { d -> out.usePinned { o -> CC_SHA256(if (data.isEmpty()) null else d.addressOf(0), data.size.convert(), o.addressOf(0)) } }
  return out.asByteArray()
}
