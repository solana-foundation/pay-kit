// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VerifyE2E",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../../../../"),
    ],
    targets: [
        .executableTarget(
            name: "VerifyE2E",
            dependencies: [
                .product(name: "SolanaMpp", package: "swift"),
            ]
        ),
    ]
)
