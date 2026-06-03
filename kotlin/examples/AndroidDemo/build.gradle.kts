// Root project for the MPP Android demo. AGP and Kotlin plugins are
// declared here with apply false so the :app module can resolve them
// without duplicating versions.
//
// Kotlin is pinned to 2.2.20 (not 1.9.x) because the vendored x402 exact
// client pulls in com.solanamobile:web3-solana, which transitively requires
// kotlinx-serialization 1.9.0. That serialization runtime ships Kotlin
// metadata version 2.2.0, which only a Kotlin 2.2+ compiler can read; the
// older 1.9.25 toolchain fails with "incompatible version of Kotlin"
// against the x402 @Serializable types. From Kotlin 2.0 the Compose
// compiler ships in-tree via the `plugin.compose` Gradle plugin (applied in
// :app), so the standalone composeOptions compiler-extension pin is gone.
plugins {
    id("com.android.application") version "8.5.2" apply false
    kotlin("android") version "2.2.20" apply false
    kotlin("plugin.compose") version "2.2.20" apply false
}
