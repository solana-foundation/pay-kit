plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.serialization") version "2.3.21"
    `java-library`
    `maven-publish`
    jacoco
    id("org.jetbrains.dokka") version "1.9.20"
}

group = "com.solana.paykit"
// Default version for local builds. JitPack builds from a git tag and passes
// it via `-Pversion=$VERSION` (see jitpack.yml), which overrides this default
// so the published artifact carries the tag.
version = (findProperty("version") as String?)?.takeIf { it != "unspecified" } ?: "0.1.0"

kotlin {
    jvmToolchain(17)
}

// Publish sources and javadoc jars alongside the library so consumers get
// IDE navigation and documentation. JitPack harvests whatever
// publishToMavenLocal writes, so wiring these into the `java` component is
// enough — no extra tasks to invoke.
java {
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    // Coroutines back the idiomatic suspend call surface (PayKitClient.get).
    // OkHttp 4 is blocking, so the suspend methods offload the call onto
    // Dispatchers.IO; this is the same bridge Retrofit's suspend adapter uses.
    // `api`, not `implementation`: the public call surface returns suspend
    // functions, so coroutines is part of the SDK's exported API.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
    // BouncyCastle gives a deterministic Ed25519 signer that takes the raw
    // 32 byte seed format Solana keypair files (and the MPP harness
    // harness) ship in. The JDK Ed25519 provider does not expose that
    // wire-level seed import path on every JVM.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // multimult is the Base58 codec maintained by Solana Mobile and used
    // by web3-solana and mobile-wallet-adapter-clientlib. Pulling it in
    // lets the SDK share the exact same Bitcoin-alphabet Base58
    // implementation as the rest of the Solana Mobile Kotlin stack
    // instead of carrying a hand-rolled BigInteger-based codec.
    implementation("io.github.funkatronics:multimult-jvm:0.2.3")
    // web3-solana is the Solana Mobile Kotlin transaction/instruction
    // library (production-used). The x402 exact client builds its
    // instructions through web3-solana's TransactionInstruction / AccountMeta
    // / SolanaPublicKey / TokenProgram.transferChecked so the SPL transfer
    // layout comes from a maintained library instead of being hand-rolled.
    // What it does NOT provide (and so stays hand-rolled in paycore): v0
    // VersionedMessage *compilation* (web3-solana's Message.Builder only
    // produces a LegacyMessage; VersionedMessage is a bare data class with no
    // try_compile path), the ComputeBudget program, and a synchronous ATA
    // derivation (only a suspend `find`). See Payment.kt for the bridge.
    implementation("com.solanamobile:web3-solana:0.3.1")
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

// Dokka GFM — emit GitHub-flavored markdown to the unified docs/api/kotlin/
// tree alongside the other languages' MD output. Invoke via
// `./gradlew dokkaGfm` or `just docs-kt`.
tasks.named<org.jetbrains.dokka.gradle.DokkaTask>("dokkaGfm") {
    outputDirectory.set(rootDir.parentFile.resolve("docs/api/kotlin"))
    moduleName.set("com.solana.paykit")
}

// Maven publication. JitPack builds this repo from a git tag on demand and
// harvests the artifact written by `publishToMavenLocal`; it overrides the
// version with the tag at build time (the `0.1.0` above is only a default).
// Consumer coordinate (monorepo / JitPack): the groupId is forced to
// `com.github.<owner>.<repo>` by JitPack and the artifactId is this Gradle
// module name (`solana-pay-kit-kotlin`, from settings.gradle.kts), so the
// dependency reads:
//   com.github.solana-foundation.pay-kit:solana-pay-kit-kotlin:<tag>
// Maven surfaces POM metadata (name/description/url/scm) rather than a README,
// so the description below is the discoverability surface for this artifact.
publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])

            pom {
                name.set("pay-kit (Kotlin)")
                description.set("Building blocks for Agentic payments (x402, MPP, AP2)")
                url.set("https://github.com/solana-foundation/pay-kit")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://github.com/solana-foundation/pay-kit/blob/main/LICENSE")
                    }
                }

                developers {
                    developer {
                        id.set("solana-foundation")
                        name.set("Solana Foundation")
                        url.set("https://github.com/solana-foundation")
                    }
                }

                scm {
                    url.set("https://github.com/solana-foundation/pay-kit")
                    connection.set("scm:git:https://github.com/solana-foundation/pay-kit.git")
                    developerConnection.set("scm:git:git@github.com:solana-foundation/pay-kit.git")
                }
            }
        }
    }
}
