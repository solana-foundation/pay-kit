plugins {
    kotlin("jvm") version "2.3.21"
    application
}

group = "org.solana.x402"
version = "0.0.0-local"

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("com.google.code.gson:gson:2.13.2")

    testImplementation(kotlin("test"))
}

application {
    mainClass.set("org.solana.x402.exact.InteropClientKt")
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("runInteropClient") {
    group = "verification"
    description = "Runs the Kotlin x402 exact interop client."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("org.solana.x402.exact.InteropClientKt")
}
