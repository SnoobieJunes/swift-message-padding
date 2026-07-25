// swift-tools-version:6.0
// SPDX-License-Identifier: Apache-2.0
import PackageDescription

// swift-message-padding — fixed-size bucket padding, applied to plaintext BEFORE
// AEAD encryption, so ciphertext length stops leaking message length.
//
// ZERO dependencies, by design. One file of pure Foundation that any messenger can
// adopt without inheriting a protocol, a crypto stack, or an opinion about how it
// encrypts. If you find yourself adding a dependency here, the change probably
// belongs in a different package.
let package = Package(
    name: "swift-message-padding",
    platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v9)],
    products: [
        .library(name: "MessagePadding", targets: ["MessagePadding"])
    ],
    targets: [
        .target(
            name: "MessagePadding",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "MessagePaddingTests",
            dependencies: ["MessagePadding"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
