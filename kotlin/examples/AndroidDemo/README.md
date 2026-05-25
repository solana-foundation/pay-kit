# MPP Charge Demo (Android)

A minimal Jetpack Compose Android app that pays a 402-protected route
using the Kotlin MPP SDK at `kotlin/`.

Tracked under issue #114.

## Layout

```
kotlin/examples/AndroidDemo
├── app/
│   ├── build.gradle.kts          AGP + Compose configuration
│   └── src/main/
│       ├── AndroidManifest.xml   single launcher activity
│       └── java/com/solana/mpp/demo/MainActivity.kt
├── build.gradle.kts              root project, declares plugins
├── settings.gradle.kts           single `:app` module
└── gradle/wrapper/               pinned Gradle 8.10.2
```

The Kotlin SDK lives at `../../src/main/kotlin` and is vendored into
the Android module via `sourceSets`. This avoids running the SDK's
pure JVM build alongside an Android library build and keeps the demo
buildable in isolation.

## Install Android SDK (from scratch)

On macOS:

```bash
brew install --cask android-commandlinetools
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

A JDK 17 toolchain is also required. Microsoft and Temurin builds both
work:

```bash
brew install --cask temurin@17
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
```

## Build

```bash
cd kotlin/examples/AndroidDemo
./gradlew :app:assembleDebug
```

Output APK: `app/build/outputs/apk/debug/app-debug.apk`.

## Run on an emulator

```bash
sdkmanager "system-images;android-34;google_apis;arm64-v8a" "emulator"
yes | avdmanager create avd -n mpp-demo -k 'system-images;android-34;google_apis;arm64-v8a' -d pixel
"$ANDROID_HOME/emulator/emulator" -avd mpp-demo -no-snapshot &
adb wait-for-device
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.solana.mpp.demo/.MainActivity
```

## Configure RPC + merchant URL

The single screen exposes two text fields:

- Merchant URL. Defaults to `https://402.surfnet.dev/protected`.
- Solana RPC URL. Defaults to `https://402.surfnet.dev/rpc`.

For a local surfpool + interop server on the host machine, point
both at `http://10.0.2.2:<port>` from inside the emulator (Android's
loopback alias for the host). The app permits cleartext HTTP only
for `10.0.2.2`, `127.0.0.1`, and `localhost` via
`app/src/main/res/xml/network_security_config.xml`. All other
destinations remain HTTPS-only.

## End-to-end screenshot

End-to-end run in the Android 34 (arm64) emulator against local
Surfpool + the iOSDemo's `MerchantServer/serve.py`. App shows
"HTTP 200", the fortune body, and the on-chain settlement signature.

![Android emulator screenshot showing HTTP 200 and settlement signature](docs/android-demo-screenshot.png)

## Expected UI state

1. On cold start the app shows the demo signer's base58 public key.
   Fund this account on devnet before pressing Pay.
2. Tapping Pay runs `MppHttpClient.mppGet`, which receives a 402,
   builds and signs the credential, and replays with
   `Authorization: Payment ...`.
3. On success the UI shows the HTTP status, the response body, and a
   Solana Explorer URL for the on-chain signature.
4. On failure the UI shows the exception class and message.

## Solana Seeker / Mobile Wallet Adapter integration

The `SolanaSigner` interface in
`kotlin/src/main/kotlin/com/solana/mpp/SolanaSigner.kt` is the swap
point. The demo wires a `MemorySigner` so it is verifiable end-to-end
without hardware. To target the Seeker dev kit or any MWA-compliant
wallet:

1. Add `com.solanamobile:mobile-wallet-adapter-clientlib-ktx:2.0.3`
   as a dependency.
2. Implement `SolanaSigner.sign(message)` by calling the MWA
   `signMessages` primitive.
3. Pass the MWA-backed signer to `MppHttpClient(...)`.

Follow-up to flesh out the MWA path is tracked on issue #114.

## CI

`assembleDebug` runs on PRs that touch `kotlin/**` or this directory
via `.github/workflows/android-demo.yml`.
