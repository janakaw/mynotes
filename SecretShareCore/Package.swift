// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SecretShareCore",
    platforms: [.iOS("26.0"), .macOS("15.5")],
    products: [
        .library(name: "SecretShareCore", targets: ["SecretShareCore"]),
    ],
    dependencies: [
        // swift-sodium's last tagged release (0.9.1) is old; pin a recent master commit.
        .package(url: "https://github.com/jedisct1/swift-sodium.git",
                 revision: "cfd195c76882aa9b997560ca7cb95d72fbf5db00"),
    ],
    targets: [
        .target(
            name: "SecretShareCore",
            dependencies: [.product(name: "Sodium", package: "swift-sodium")]
        ),
        .testTarget(
            name: "SecretShareCoreTests",
            dependencies: ["SecretShareCore"]
        ),
    ]
)
