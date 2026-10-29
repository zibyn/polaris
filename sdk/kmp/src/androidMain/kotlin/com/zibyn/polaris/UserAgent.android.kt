package com.zibyn.polaris

import android.content.Context
import android.os.Build

internal actual fun currentDevice(): Device {
  // shortcut: Polaris takes no Context (PolarisConfig gets no new option), so the
  // Application comes from ActivityThread by reflection; if a future Android
  // hides it, the App shows as "App/unknown" — then take a Context instead.
  val app = runCatching {
    Class.forName("android.app.ActivityThread").getMethod("currentApplication").invoke(null) as Context?
  }.getOrNull()
  val pm = app?.packageManager
  @Suppress("DEPRECATION") // getPackageInfo(String, PackageInfoFlags) is API 33+
  val info = runCatching { app?.let { pm?.getPackageInfo(it.packageName, 0) } }.getOrNull()
  return Device(
    appName = runCatching { app?.applicationInfo?.loadLabel(pm!!)?.toString() }.getOrNull().orEmpty(),
    appVersion = info?.versionName.orEmpty(),
    system = "Android",
    // Null outside a device (host tests run against stubs).
    systemVersion = runCatching { Build.VERSION.RELEASE }.getOrNull().orEmpty(),
    model = runCatching { Build.MODEL }.getOrNull().orEmpty(),
    fallbackName = app?.packageName.orEmpty(),
  )
}
