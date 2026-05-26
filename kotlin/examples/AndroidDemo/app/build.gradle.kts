import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("plugin.serialization") version "1.9.25"
}

android {
    namespace = "com.solana.mpp.demo"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.solana.mpp.demo"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    // The MPP Kotlin SDK lives at ../../src/main/kotlin. The SDK is a
    // pure JVM module in its parent build but its only runtime
    // dependencies (OkHttp, kotlinx-serialization, BouncyCastle) are
    // Android-compatible, so we vendor the sources directly into the
    // app's main source set rather than publishing to mavenLocal. This
    // keeps the demo self-contained and avoids a second Gradle build.
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java", "../../../src/main/kotlin")
        }
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.15"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            )
        }
    }
}

kotlin {
    jvmToolchain(17)
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Compose BOM keeps the UI artifacts pinned to a known-good set.
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.9.2")

    // SDK runtime deps. The SDK sources are vendored above via
    // sourceSets, so we only need its transitive dependencies here.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // multimult ships Base58 used by com.solana.mpp.crypto.Base58. The SDK
    // sources are vendored into this Android module via sourceSets, so the
    // dependency cannot be inherited from kotlin/build.gradle.kts and must
    // be declared explicitly here. We pin the Android variant (not -jvm)
    // because this module's target is Android.
    implementation("io.github.funkatronics:multimult:0.2.3")

    // Solana Mobile Wallet Adapter client library. The demo delegates
    // transaction signing to a real wallet (Phantom, Solflare, Backpack,
    // or solana-mobile/mock-mwa-wallet for emulator testing) instead of
    // holding a private key locally.
    //
    // Pinned to 2.0.0 (rather than 2.0.7) to match the Kotlin 1.9.x +
    // AGP 8.5.x toolchain this demo uses. 2.0.7 transitively pulls
    // androidx artifacts compiled against Kotlin 2.1, whose metadata
    // the 1.9 compiler cannot read. The
    // solana-mobile/solana-kotlin-compose-scaffold reference project
    // pins 2.0.0 for the same reason.
    implementation("com.solanamobile:mobile-wallet-adapter-clientlib-ktx:2.0.0")
}
