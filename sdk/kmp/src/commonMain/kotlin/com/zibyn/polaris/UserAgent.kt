package com.zibyn.polaris

// Keep in step with VERSION_NAME in gradle.properties.
internal const val SDK_VERSION: String = "0.1.0"

/** What the User-Agent says about the App and the device it runs on. */
internal class Device(
  val appName: String,
  val appVersion: String,
  val system: String,
  val systemVersion: String,
  val model: String,
  /** The App's id (package name, bundle id), for a name that cannot go in a header. */
  val fallbackName: String = "",
)

internal expect fun currentDevice(): Device

/**
 * `<App>/<version> (<system> <version>; <model>) Polaris-KMP/<SDK version>`,
 * which the account center reads back as the Session's device.
 */
internal fun userAgent(d: Device, sdkVersion: String = SDK_VERSION): String {
  // OkHttp refuses a header that is not printable ASCII.
  fun ascii(s: String) = s.takeIf { it.isNotBlank() && it.all { c -> c in ' '..'~' } }
  fun part(s: String) = ascii(s.trim()) ?: "unknown"
  val name = (ascii(d.appName.trim()) ?: ascii(d.fallbackName.trim()) ?: "App").replace(' ', '-')
  return "$name/${part(d.appVersion)} (${part(d.system)} ${part(d.systemVersion)}; ${part(d.model)}) Polaris-KMP/$sdkVersion"
}
