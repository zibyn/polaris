package com.zibyn.polaris

/**
 * Where [Polaris] keeps the signed-in User's tokens, as one opaque string;
 * null means signed out. The defaults encrypt it: `KeystoreTokenStore` on
 * Android, `KeychainTokenStore` on iOS. Calls come from one coroutine at a
 * time.
 */
public interface TokenStore {
  public fun read(): String?
  public fun write(value: String?)
}
