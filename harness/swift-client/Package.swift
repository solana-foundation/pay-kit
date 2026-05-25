// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftInteropClient",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(path: "../../../swift"),
    ],
    targets: [
        .executableTarget(
            name: "SwiftInteropClient",
            dependencies: [
                .product(name: "SolanaMpp", package: "swift"),
            ]
        ),
    ]
)
