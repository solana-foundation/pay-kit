// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftX402Client",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "SwiftX402Client",
            dependencies: [
                .product(name: "SolanaPayKit", package: "pay-kit"),
            ]
        ),
    ]
)
