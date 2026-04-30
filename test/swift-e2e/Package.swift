// swift-tools-version: 5.9
import PackageDescription

// [TEST: Linux runner] Platform-dependent library path for ubuntu runner testing.
// Original macOS-only: let libraryPath = "Libraries/macos"
#if os(macOS)
let libraryPath = "Libraries/macos"
let openSslLinkerSettings: [LinkerSetting] = []
#else
let libraryPath = "Libraries/linux"
let openSslLinkerSettings: [LinkerSetting] = [
    .linkedLibrary("crypto"),
    .linkedLibrary("ssl"),
]
#endif

let package = Package(
    name: "SwiftUniffiE2E",
    // [TEST: Linux runner] Original macOS platform constraint:
    // platforms: [
    //     .macOS(.v13),
    // ],
    products: [
        .library(name: "RGBLightningNode", targets: ["RGBLightningNode"]),
    ],
    targets: [
        .systemLibrary(
            name: "RGBLightningNodeFFI",
            path: "FFI"
        ),
        .target(
            name: "RGBLightningNode",
            dependencies: ["RGBLightningNodeFFI"],
            path: "Sources/RGBLightningNode",
            linkerSettings: [
                .unsafeFlags([
                    "-L",
                    libraryPath,  // [TEST: Linux runner] was: "Libraries/macos"
                ]),
                .linkedLibrary("rgb_lightning_node"),
            ] + openSslLinkerSettings
        ),
        .testTarget(
            name: "SwiftUniffiE2ETests",
            dependencies: ["RGBLightningNode"],
            path: "Tests/SwiftUniffiE2ETests"
        ),
    ]
)
