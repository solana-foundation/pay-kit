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
    targets: [
        .target(name: "SolanaMpp"),
        .testTarget(
            name: "SolanaMppTests",
            dependencies: ["SolanaMpp"]
        ),
        .target(name: "X402"),
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
