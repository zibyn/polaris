package com.zibyn.polaris

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The default [TokenStore] on Android: AES-GCM under a key that never leaves
 * the Android Keystore, kept in a private SharedPreferences file. What can't
 * be decrypted (the key was wiped, e.g. by a backup restored to another
 * device) reads as signed out.
 */
public class KeystoreTokenStore(context: Context, private val alias: String = "polaris-tokens") : TokenStore {
  private val prefs = context.getSharedPreferences(alias, Context.MODE_PRIVATE)

  override fun read(): String? {
    val stored = prefs.getString(KEY, null) ?: return null
    return runCatching {
      val bytes = Base64.decode(stored, Base64.NO_WRAP)
      val cipher = Cipher.getInstance(AES_GCM)
      cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes, 0, IV))
      cipher.doFinal(bytes, IV, bytes.size - IV).decodeToString()
    }.getOrNull()
  }

  override fun write(value: String?) {
    if (value == null) {
      check(prefs.edit().remove(KEY).commit()) { "token store: write failed" }
      return
    }
    val cipher = Cipher.getInstance(AES_GCM)
    cipher.init(Cipher.ENCRYPT_MODE, key())
    val sealed = cipher.iv + cipher.doFinal(value.encodeToByteArray())
    check(prefs.edit().putString(KEY, Base64.encodeToString(sealed, Base64.NO_WRAP)).commit()) { "token store: write failed" }
  }

  private fun key(): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (ks.getKey(alias, null) as? SecretKey)?.let { return it }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
      init(
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .build(),
      )
    }.generateKey()
  }

  private companion object {
    const val KEY = "tokens"
    const val AES_GCM = "AES/GCM/NoPadding"
    const val IV = 12
  }
}
