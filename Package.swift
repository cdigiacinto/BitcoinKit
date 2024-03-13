// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "BitcoinKit",
    products: [
        .library(name: "BitcoinKit", targets: ["BitcoinKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/zhangliugang/ripemd160", .branch("master")),
        .package(url: "https://github.com/cdigiacinto/Msecp256k1.swift", .branch("master")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.5.1")
    ],
    targets: [
        .target(
            name: "BitcoinKit",
            dependencies: ["Msecp256k1", "ripemd160", "CryptoSwift"]
        ),
        .testTarget(
            name: "BitcoinKitTests",
            dependencies: ["BitcoinKit"]
        )
    ],
    swiftLanguageVersions: [.v5]
)
