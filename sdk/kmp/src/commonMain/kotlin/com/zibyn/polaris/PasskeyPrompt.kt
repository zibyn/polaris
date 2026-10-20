package com.zibyn.polaris

/**
 * The system's Passkey sheet, and the only part of Passkey that is not the
 * same on every platform: Android Credential Manager, iOS ASAuthorization.
 * The SDK hands it the WebAuthn options and takes back what the sheet
 * produced; the sheet itself belongs to the OS, not to the SDK.
 *
 * Build one with `passkeyPrompt(context)` on Android, `passkeyPrompt()` on
 * iOS (see the SDK README), and pass it to [Polaris].
 */
public interface PasskeyPrompt {
  /**
   * Whether this device can do Passkeys at all. An Android phone without
   * Google Play services cannot, and the App should hide its Passkey entry
   * rather than open one that is bound to fail.
   */
  public val available: Boolean

  /**
   * Runs the system's "create a Passkey" sheet. [optionsJson] is the
   * PublicKeyCredentialCreationOptionsJSON (the value that goes under
   * `publicKey`). Returns the RegistrationResponseJSON to hand back to Polaris, or null if the User dismissed the sheet: not a failure.
   */
  public suspend fun create(optionsJson: String): String?

  /**
   * Runs the system's "use a Passkey" sheet. [optionsJson] is the
   * PublicKeyCredentialRequestOptionsJSON (the value that goes under
   * `publicKey`). Returns the AuthenticationResponseJSON to hand back to
   * Polaris, or null if the User dismissed the sheet: not a failure.
   */
  public suspend fun get(optionsJson: String): String?
}
