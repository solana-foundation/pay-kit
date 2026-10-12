plugins {
    kotlin("jvm") version "2.3.21"
    application
}

dependencies {
    // Path-included build, see settings.gradle.kts.
    implementation("com.solana.paykit:solana-pay-kit-kotlin")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.solana.paykit.protocolrunner.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
