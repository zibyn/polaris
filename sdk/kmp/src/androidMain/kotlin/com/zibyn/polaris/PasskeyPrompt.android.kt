package com.zibyn.polaris

import android.content.Context
import android.os.Build
import androidx.credentials.CredentialManager
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException

/**
 * The system Passkey sheet, Credential Manager. Pass an Activity's context:
 * the sheet opens on it. Pass this to [Polaris].
 */
public fun passkeyPrompt(context: Context): PasskeyPrompt = AndroidPasskeyPrompt(context)

private class AndroidPasskeyPrompt(private val context: Context) : PasskeyPrompt {
  private val manager = CredentialManager.create(context)

  // ponytail: Google Play services installed and Android 9+, rather than a
  // round trip to a provider that may not be there to answer. 大陆 phones
  // without GMS are what this is for.
  override val available: Boolean =
    Build.VERSION.SDK_INT >= 28 &&
      runCatching { context.packageManager.getApplicationInfo("com.google.android.gms", 0) }.isSuccess

  override suspend fun create(optionsJson: String): String? = try {
    (manager.createCredential(context, CreatePublicKeyCredentialRequest(optionsJson))
      as CreatePublicKeyCredentialResponse).registrationResponseJson
  } catch (e: CreateCredentialCancellationException) {
    null
  }

  override suspend fun get(optionsJson: String): String? = try {
    (manager.getCredential(
      context,
      GetCredentialRequest(listOf(GetPublicKeyCredentialOption(optionsJson))),
    ).credential as PublicKeyCredential).authenticationResponseJson
  } catch (e: GetCredentialCancellationException) {
    null
  }
}
