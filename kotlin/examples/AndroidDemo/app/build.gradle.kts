import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.application")
    kotlin("android")
    // From Kotlin 2.0 the Compose compiler ships in-tree and is enabled via
    // this plugin instead of the standalone composeOptions compiler-extension
    // pin (which only existed for Kotlin 1.x). Version is inherited from the
    // root build's `apply false` declaration.
    kotlin("plugin.compose")
    kotlin("plugin.serialization") version "2.2.20"
}

android {
    namespace = "com.solana.paykit.demo"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.solana.paykit.demo"
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
    // The full SDK source set is compiled, including the x402 exact client
    // (protocols/x402 + client/PayKitClient + client/X402Interceptor). The
    // unified PayKitClient references the x402 package directly, so it cannot
    // be excluded; its web3-solana dependency is declared below and resolves
    // under the Kotlin 2.2 toolchain.
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
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
    // Pinned to 1.9.0 to match kotlin/build.gradle.kts and the version
    // web3-solana transitively requires; the Kotlin 2.2 toolchain reads its
    // metadata.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    // Coroutines back PayKitClient's suspend call surface (Dispatchers.IO).
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // web3-solana backs the vendored x402 exact client's SPL transferChecked
    // builder (paycore lowers the resulting TransactionInstruction). Matches
    // kotlin/build.gradle.kts.
    implementation("com.solanamobile:web3-solana:0.3.1")
    // multimult ships Base58 used by com.solana.paykit.paycore.Base58. The SDK
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
    // Pinned to 2.0.0 to match the
    // solana-mobile/solana-kotlin-compose-scaffold reference project. The
    // clientlib is consumed as a prebuilt AAR, so its own build toolchain
    // does not constrain this module's Kotlin compiler version.
    implementation("com.solanamobile:mobile-wallet-adapter-clientlib-ktx:2.0.0")
}
