plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.serialization") version "2.3.21"
    jacoco
}

group = "com.solana.mpp"
version = "0.1.0"

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    // BouncyCastle gives a deterministic Ed25519 signer that takes the raw
    // 32 byte seed format Solana keypair files (and the MPP interop
    // harness) ship in. The JDK Ed25519 provider does not expose that
    // wire-level seed import path on every JVM.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // OkHttp is the canonical Kotlin/JVM HTTP client. Used by MppHttpClient
    // for 402-triggered credential build and retry.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation(kotlin("test"))
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required = true
        html.required = true
    }
}

tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.jacocoTestReport)
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.90".toBigDecimal()
            }
        }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}
