plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.serialization") version "2.3.21"
    application
}

dependencies {
    // Path-included build, see settings.gradle.kts.
    implementation("com.solana.paykit:solana-pay-kit-kotlin")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.solana.paykit.conformance.MainKt")
}

tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
