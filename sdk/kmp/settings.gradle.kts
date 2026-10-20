pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
// Provisions the JDK 21 the daemon needs (gradle/gradle-daemon-jvm.properties).
plugins { id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0" }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "polaris"
