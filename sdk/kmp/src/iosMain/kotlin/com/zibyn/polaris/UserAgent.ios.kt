package com.zibyn.polaris

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.toKString
import platform.Foundation.NSBundle
import platform.UIKit.UIDevice
import platform.posix.uname
import platform.posix.utsname

@OptIn(ExperimentalForeignApi::class)
internal actual fun currentDevice(): Device {
  val bundle = NSBundle.mainBundle
  fun info(key: String) = bundle.objectForInfoDictionaryKey(key) as? String
  // The hardware id, e.g. iPhone15,2; UIDevice.model only says "iPhone".
  val machine = memScoped {
    val u = alloc<utsname>()
    uname(u.ptr)
    u.machine.toKString()
  }
  return Device(
    appName = info("CFBundleDisplayName") ?: info("CFBundleName").orEmpty(),
    appVersion = info("CFBundleShortVersionString").orEmpty(),
    system = UIDevice.currentDevice.systemName,
    systemVersion = UIDevice.currentDevice.systemVersion,
    model = machine,
    fallbackName = bundle.bundleIdentifier.orEmpty(),
  )
}
