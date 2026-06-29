// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftHarnessClient",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "SwiftHarnessClient",
            dependencies: [
                .product(name: "SolanaPayKit", package: "pay-kit"),
            ]
        ),
    ]
)
