package com.zibyn.polaris

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import platform.AuthenticationServices.ASAuthorization
import platform.AuthenticationServices.ASAuthorizationController
import platform.AuthenticationServices.ASAuthorizationControllerDelegateProtocol
import platform.AuthenticationServices.ASAuthorizationControllerPresentationContextProvidingProtocol
import platform.AuthenticationServices.ASAuthorizationErrorCanceled
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialAssertion
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialDescriptor
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialProvider
import platform.AuthenticationServices.ASAuthorizationPlatformPublicKeyCredentialRegistration
import platform.AuthenticationServices.ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired
import platform.AuthenticationServices.ASAuthorizationRequest
import platform.AuthenticationServices.ASPresentationAnchor
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.base64EncodedStringWithOptions
import platform.Foundation.create
import platform.UIKit.UIApplication
import platform.UIKit.UISceneActivationStateForegroundActive
import platform.UIKit.UIWindow
import platform.UIKit.UIWindowScene
import platform.darwin.NSObject
import kotlin.coroutines.Continuation

/**
 * The system Passkey sheet on iOS, `AuthenticationServices`. Pass this to
 * [Polaris]. The App needs the `webcredentials:` associated domain and
 * iOS 16+; see the SDK README.
 */
public fun passkeyPrompt(): PasskeyPrompt = IosPasskeyPrompt()

@OptIn(ExperimentalForeignApi::class)
private class IosPasskeyPrompt : PasskeyPrompt {

  override val available: Boolean = true

  // One sheet at a time: AuthenticationServices keeps the controller and its
  // delegate weakly, and nothing else outlives the suspension, so this holds
  // them until the one callback comes back.
  private var delegate: PasskeyDelegate? = null

  override suspend fun create(optionsJson: String): String? {
    val o = json.decodeFromString<CreationOptions>(optionsJson)
    val request = ASAuthorizationPlatformPublicKeyCredentialProvider(o.rp.id)
      .createCredentialRegistrationRequestWithChallenge(
        challenge = o.challenge.unBase64Url(),
        name = o.user.name,
        userID = o.user.id.unBase64Url(),
      )
    request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired
    // ponytail: iOS cannot exclude the User's existing credentials, so an
    // authenticator may offer a second one here; the server refuses the same
    // credential twice either way.
    return perform(request) { auth ->
      (auth.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration)?.let { registrationJson(it) }
    }
  }

  override suspend fun get(optionsJson: String): String? {
    val o = json.decodeFromString<AssertionOptions>(optionsJson)
    val request = ASAuthorizationPlatformPublicKeyCredentialProvider(o.rpId)
      .createCredentialAssertionRequestWithChallenge(o.challenge.unBase64Url())
    request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired
    request.allowedCredentials = o.allowCredentials.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(it.id.unBase64Url()) }
    return perform(request) { auth ->
      (auth.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion)?.let { assertionJson(it) }
    }
  }

  private suspend fun perform(request: ASAuthorizationRequest, credentialJson: (ASAuthorization) -> String?): String? {
    val credential = suspendCancellableCoroutine<String?> { cont ->
      val d = PasskeyDelegate(cont, credentialJson)
      delegate = d
      val controller = ASAuthorizationController(listOf(request))
      controller.delegate = d
      controller.presentationContextProvider = d
      d.controller = controller
      controller.performRequests()
    }
    delegate = null
    return credential
  }
}

private class PasskeyDelegate(
  private val continuation: Continuation<String?>,
  private val credentialJson: (ASAuthorization) -> String?,
) : NSObject(),
  ASAuthorizationControllerDelegateProtocol,
  ASAuthorizationControllerPresentationContextProvidingProtocol {

  // The controller does not retain its delegate (nor does it, but it does
  // retain the request), so the delegate retains the controller.
  var controller: ASAuthorizationController? = null

  private var done = false

  override fun authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization: ASAuthorization) {
    finish(Result.success(credentialJson(didCompleteWithAuthorization)))
  }

  override fun authorizationController(controller: ASAuthorizationController, didCompleteWithError: NSError) {
    finish(
      // Only the User closing the sheet means "no result". Anything else — no
      // associated domain, no credential for the account — is a failure the
      // App should see, not a cancellation.
      if (didCompleteWithError.domain == ASAuthorizationErrorDomain && didCompleteWithError.code == ASAuthorizationErrorCanceled) {
        Result.success(null)
      } else {
        Result.failure(PolarisException("passkey_failed", didCompleteWithError.localizedDescription))
      },
    )
  }

  private fun finish(result: Result<String?>) {
    if (done) return
    done = true
    controller = null
    continuation.resumeWith(result)
  }

  override fun presentationAnchorForAuthorizationController(controller: ASAuthorizationController): ASPresentationAnchor =
    UIApplication.sharedApplication.connectedScenes
      .filterIsInstance<UIWindowScene>()
      .firstOrNull { it.activationState == UISceneActivationStateForegroundActive }
      ?.keyWindow
      ?: UIApplication.sharedApplication.keyWindow
      ?: UIWindow()
}

private val json = Json { ignoreUnknownKeys = true }

@Serializable private class CreationOptions(
  val rp: Rp,
  val user: User,
  val challenge: String,
)

@Serializable private class Rp(val id: String)

@Serializable private class User(val id: String, val name: String)

@Serializable private class AssertionOptions(
  val rpId: String,
  val challenge: String,
  val allowCredentials: List<Descriptor> = emptyList(),
)

@Serializable private class Descriptor(val id: String)

private fun registrationJson(c: ASAuthorizationPlatformPublicKeyCredentialRegistration): String {
  val id = c.credentialID.base64Url()
  return buildJsonObject {
    put("id", id)
    put("rawId", id)
    put("type", "public-key")
    putJsonObject("response") {
      put("clientDataJSON", c.rawClientDataJSON.base64Url())
      c.rawAttestationObject?.let { put("attestationObject", it.base64Url()) }
    }
  }.toString()
}

private fun assertionJson(c: ASAuthorizationPlatformPublicKeyCredentialAssertion): String {
  val id = c.credentialID.base64Url()
  return buildJsonObject {
    put("id", id)
    put("rawId", id)
    put("type", "public-key")
    putJsonObject("response") {
      put("clientDataJSON", c.rawClientDataJSON.base64Url())
      c.rawAuthenticatorData?.let { put("authenticatorData", it.base64Url()) }
      c.signature?.let { put("signature", it.base64Url()) }
      // What the server looks the credential up by.
      c.userID?.let { put("userHandle", it.base64Url()) }
    }
  }.toString()
}

private fun NSData.base64Url(): String =
  base64EncodedStringWithOptions(0u).replace('+', '-').replace('/', '_').trimEnd('=')

@OptIn(BetaInteropApi::class)
private fun String.unBase64Url(): NSData =
  NSData.create(
    base64EncodedString = replace('-', '+').replace('_', '/').let { it + "=".repeat((4 - it.length % 4) % 4) },
    options = 0u,
  ) ?: error("not base64url: $this")
