// The Polaris SDK for iOS and Android Apps: the direct auth API, tokens and
// their storage. No UI. Behaviour: docs/sdk-behavior.md at the repo root.
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
  id("org.jetbrains.kotlin.multiplatform") version "2.4.20"
  id("com.android.kotlin.multiplatform.library") version "9.3.1"
  id("org.jetbrains.kotlin.plugin.serialization") version "2.4.20"
  id("com.vanniktech.maven.publish") version "0.37.0"
}

kotlin {
  explicitApi()
  android {
    namespace = "com.zibyn.polaris"
    compileSdk = 37
    minSdk = 26
    withHostTest {}
  }
  val xcf = XCFramework("Polaris")
  listOf(iosArm64(), iosSimulatorArm64()).forEach {
    it.binaries.framework {
      baseName = "Polaris"
      xcf.add(this)
    }
  }
  sourceSets {
    commonMain.dependencies {
      api("io.ktor:ktor-client-core:3.6.0")
      implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
      implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    }
    commonTest.dependencies {
      implementation(kotlin("test"))
      implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
      implementation("io.ktor:ktor-client-mock:3.6.0")
    }
    androidMain.dependencies {
      implementation("io.ktor:ktor-client-okhttp:3.6.0")
      // The system Passkey sheet.
      implementation("androidx.credentials:credentials:1.5.0")
      implementation("androidx.credentials:credentials-play-services-auth:1.5.0")
    }
    iosMain.dependencies {
      implementation("io.ktor:ktor-client-darwin:3.6.0")
    }
    getByName("androidHostTest").dependencies {
      implementation(kotlin("test-junit"))
    }
  }
}

mavenPublishing {
  publishToMavenCentral()
  coordinates(artifactId = "polaris")
  pom {
    name = "Polaris KMP SDK"
    description = "Sign Users in to Polaris from iOS and Android Apps, without a browser."
    url = "https://github.com/zibyn/polaris"
    licenses { license { name = "Apache-2.0"; url = "https://www.apache.org/licenses/LICENSE-2.0" } }
    developers { developer { id = "zibyn"; name = "zibyn" } }
    scm { url = "https://github.com/zibyn/polaris" }
  }
}
