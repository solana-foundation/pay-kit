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
    ],
    targets: [
        .target(name: "SolanaMpp"),
        .testTarget(
            name: "SolanaMppTests",
            dependencies: ["SolanaMpp"]
        ),
    ]
)
