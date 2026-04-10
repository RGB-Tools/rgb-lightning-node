# Swift UniFFI E2E

Minimal SwiftPM/XCTest smoke harness for the Swift UniFFI consumer path.

Current scope:
- generate Swift bindings from `bindings/rgb_lightning_node.udl`
- build the Rust library for a macOS host target
- wire Swift bindings to the generated FFI module
- run one smoke test:
  - `SdkNode.create(...)`
  - `unlock(...)`
  - `nodeInfo()`
  - `address()`

This is intentionally a small first test. It validates the Swift consumer surface without pulling in channel/payment/swap complexity yet.

## Repository Layout

- `Package.swift`
  - SwiftPM package definition
- `scripts/swift_uniffi_e2e.sh`
  - prepares generated bindings + native library, then runs `swift test`
- `Tests/SwiftUniffiE2ETests/SwiftUniffiE2ESmokeTests.swift`
  - smoke XCTest
- `.gitignore`
  - excludes generated Swift/FFI/native artifacts

Generated files are staged at runtime and are **not** committed:
- `Sources/RGBLightningNode/RGBLightningNode.swift`
- `FFI/RGBLightningNodeFFI.h`
- `FFI/module.modulemap`
- `Libraries/macos/librgb_lightning_node.a`

## DevOps / CI Requirements

This harness is intended for a **macOS runner**.

Required toolchain:
- Xcode / Apple Swift toolchain with `swift test`
- Rust toolchain
- `rustup`
- `docker`

The runner script builds the Rust static library for the current macOS host architecture:
- Apple Silicon: `aarch64-apple-darwin`
- Intel: `x86_64-apple-darwin`

The script auto-installs the needed Rust target with:

```sh
rustup target add <host-target>
```

## Required Environment

The smoke test uses the same regtest services as the other consumer-path tests.

Required environment variables:
- `BITCOIND_RPC_USERNAME`
- `BITCOIND_RPC_PASSWORD`
- `BITCOIND_RPC_HOST`
- `BITCOIND_RPC_PORT`

Optional environment variables:
- `INDEXER_URL`
- `PROXY_ENDPOINT`

If a required variable is missing, the XCTest is skipped with an explicit message.

## Local Run on macOS

From the repository root:

```sh
./scripts/swift_uniffi_e2e.sh
```

What the script does:
1. detects the current macOS host architecture
2. installs the matching Rust target
3. builds `librgb_lightning_node.a` with `--features uniffi`
4. generates Swift bindings via `./scripts/ci/uniffi_generate_swift.sh`
5. copies generated artifacts into the SwiftPM package layout
6. runs `swift test`

## CI Recommendation

Recommended job shape:

1. use a self-hosted macOS runner with Docker available
2. export the regtest/indexer/proxy env vars
3. run:

```sh
./scripts/swift_uniffi_e2e.sh
```

Suggested responsibility split:
- this harness should validate the Swift consumer API wiring
- heavier Swift parity/e2e scenarios can be added later after this smoke path is stable

Current repository CI uses this as a self-hosted macOS smoke path, not a
GitHub-hosted `macos-latest` job.

## Notes

- This is not expected to run on Linux.
- Generated Swift bindings may differ slightly after UniFFI upgrades; the runner always regenerates them instead of relying on committed output.
- If CI fails here, first separate whether the failure is:
  - Rust build / native artifact generation
  - Swift binding generation
  - SwiftPM linking/module import
  - smoke-test runtime against regtest services
