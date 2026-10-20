package com.zibyn.polaris

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData

/**
 * The default [TokenStore] on iOS: a generic password item in the Keychain,
 * readable after the first unlock and never synced or restored to another
 * device.
 */
@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
public class KeychainTokenStore(private val service: String = "com.zibyn.polaris") : TokenStore {
  override fun read(): String? = memScoped {
    val result = alloc<CFTypeRefVar>()
    val status = query(kSecReturnData to kCFBooleanTrue, kSecMatchLimit to kSecMatchLimitOne) { SecItemCopyMatching(it, result.ptr) }
    if (status != errSecSuccess) return null
    val data = CFBridgingRelease(result.value) as NSData
    NSString.create(data = data, encoding = NSUTF8StringEncoding)?.toString()
  }

  // Updated in place, never deleted first: a failed write keeps the old item.
  override fun write(value: String?) {
    if (value == null) {
      query { SecItemDelete(it) }
      return
    }
    val data = NSString.create(string = value).dataUsingEncoding(NSUTF8StringEncoding)
    var status = query { q -> dictionary(kSecValueData to data) { SecItemUpdate(q, it) } }
    if (status == errSecItemNotFound) {
      status = query(kSecValueData to data, kSecAttrAccessible to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) { SecItemAdd(it, null) }
    }
    check(status == errSecSuccess) { "Keychain write: $status" }
  }

  /** Runs block with this store's item query plus extra. */
  private fun <T> query(vararg extra: Pair<CFStringRef?, Any?>, block: (CFDictionaryRef?) -> T): T =
    dictionary(kSecClass to kSecClassGenericPassword, kSecAttrService to service, kSecAttrAccount to "tokens", *extra, block = block)

  private fun <T> dictionary(vararg entries: Pair<CFStringRef?, Any?>, block: (CFDictionaryRef?) -> T): T {
    val q = CFDictionaryCreateMutable(null, 0, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
    fun put(key: CFStringRef?, value: Any?) {
      if (value is CPointer<*>) {
        CFDictionarySetValue(q, key, value)
      } else {
        val ref = CFBridgingRetain(value)
        CFDictionarySetValue(q, key, ref)
        CFRelease(ref) // the dictionary holds its own
      }
    }
    entries.forEach { put(it.first, it.second) }
    try {
      return block(q)
    } finally {
      CFRelease(q)
    }
  }
}
