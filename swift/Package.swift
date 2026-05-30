// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SolanaPayKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "SolanaPayKit",
            targets: ["SolanaPayKit"]
        ),
    ],
    targets: [
        .target(name: "SolanaPayKit"),
        .testTarget(
            name: "SolanaPayKitTests",
            dependencies: ["SolanaPayKit"]
        ),
    ]
)
