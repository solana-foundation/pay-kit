plugins {
    kotlin("jvm") version "2.3.21"
    application
}

dependencies {
    // Path-included build, see settings.gradle.kts.
    implementation("com.solana.paykit:solana-pay-kit-kotlin")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.solana.paykit.x402harness.MainKt")
}

tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
