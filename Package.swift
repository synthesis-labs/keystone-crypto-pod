// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "keystoneCrypto",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "keystoneCrypto",
            targets: ["keystoneCrypto"]),
    ],
    dependencies: [
        .package(url: "https://github.com/iosdevzone/IDZSwiftCommonCrypto.git", exact: "0.13.1"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "keystoneCrypto",
            dependencies: [.product(name: "IDZSwiftCommonCrypto", package: "idzswiftcommoncrypto")],
        path: "KeystoneCrypto"),
        .testTarget(
            name: "keystoneCryptoTests",
            dependencies: ["keystoneCrypto"]),
    ]
)
