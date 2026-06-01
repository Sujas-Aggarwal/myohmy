// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "my",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "my", targets: ["my"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0")
    ],
    targets: [
        .executableTarget(
            name: "my",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            path: "Sources"
        )
    ]
)
