// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftX402UptoClient",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(name: "SolanaPayKit", path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "SwiftX402UptoClient",
            dependencies: [
                .product(name: "SolanaPayKit", package: "SolanaPayKit"),
            ]
        ),
    ]
)
