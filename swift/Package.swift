// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SolanaMpp",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "SolanaMpp",
            targets: ["SolanaMpp"]
        ),
        .library(
            name: "X402",
            targets: ["X402"]
        ),
        .executable(
            name: "x402-interop-client",
            targets: ["X402InteropClient"]
        ),
    ],
    dependencies: [
        // SwiftCrypto provides Curve25519 (Ed25519) + SHA256 on Linux without a
        // CryptoKit dependency, so the X402 client builds and runs on the same
        // ubuntu-latest runners the rest of the interop harness uses.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "SolanaMpp"),
        .testTarget(
            name: "SolanaMppTests",
            dependencies: ["SolanaMpp"]
        ),
        .target(
            name: "X402",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "X402InteropClient",
            dependencies: ["X402"]
        ),
        .testTarget(
            name: "X402Tests",
            dependencies: ["X402"]
        ),
    ]
)
