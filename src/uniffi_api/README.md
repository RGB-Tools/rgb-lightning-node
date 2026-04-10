# UniFFI Bindings

REST is **not** part of the SDK surface. REST endpoints remain a compatibility
wrapper for existing integrations and tests. The SDK surface is exposed through
the Rust library + UniFFI bindings.

Current lifecycle/threading model:
- UniFFI SDK is instance-based via `SdkNode` object handles.
- Create a node with `SdkNode.create(SdkInitRequest)`, then call methods on that instance.
- Multiple SDK node instances are supported per process.
- Legacy global `sdk_*` wrappers remain in Rust for compatibility but are no longer part of generated UniFFI bindings.
- UniFFI methods are synchronous entrypoints bridged to async internals:
  `MultiThread` Tokio runtime uses `block_in_place + handle.block_on`, while
  `CurrentThread` (or no runtime) uses a shared dedicated Tokio runtime to avoid
  `block_in_place` panic paths.

## Dependency layering

Current internal layering is:

- `uniffi_api` -> `sdk` -> `ldk` (+ shared node/app state)
- `routes` (HTTP compatibility layer) -> `sdk`/`ldk`

Important notes:

- UniFFI does not call HTTP route handlers; it calls SDK methods directly.
- SDK is expected to depend on LDK core logic (it is a wrapper, not a separate node implementation).
- `ldk::start_ldk` now accepts `core_types::UnlockRequest` and SDK unlock uses `sdk::UnlockRequest`, so unlock flow is not typed against route-layer DTOs.
- A small `routes` diff remains for shared `AppState` transition helpers (`pub(crate)` visibility), used by SDK unlock lifecycle handling.

## E2E and parity harnesses

Harness-specific runbooks live in:
- `test/python-e2e/README.md`
- `test/kotlin-e2e/README.md`
- `android-e2e/README.md`
- `test/swift-e2e/README.md`
- `src/test/lib_sdk/README.md`

## Route parity status (`routes.rs` -> SDK/UniFFI)

Implemented mappings:
- `address` -> `address`
- `asset_balance` -> `asset_balance`
- `asset_metadata` -> `asset_metadata`
- `btc_balance` -> `btc_balance`
- `check_indexer_url` -> `check_indexer_url`
- `check_proxy_endpoint` -> `check_proxy_endpoint`
- `close_channel` -> `closechannel`
- `connect_peer` -> `connectpeer`
- `create_utxos` -> `createutxos`
- `decode_ln_invoice` -> `decode_ln_invoice`
- `decode_rgb_invoice` -> `decode_rgb_invoice`
- `disconnect_peer` -> `disconnectpeer`
- `estimate_fee` -> `estimate_fee`
- `fail_transfers` -> `failtransfers`
- `get_asset_media` -> `get_asset_media`
- `get_channel_id` -> `get_channel_id`
- `get_payment` -> `get_payment`
- `get_swap` -> `get_swap`
- `init` -> `init`
- `invoice_status` -> `invoice_status`
- `issue_asset_cfa` -> `issueassetcfa`
- `issue_asset_nia` -> `issueassetnia`
- `issue_asset_uda` -> `issueassetuda`
- `keysend` -> `keysend`
- `list_assets` -> `list_assets`
- `list_channels` -> `list_channels`
- `list_payments` -> `list_payments`
- `list_peers` -> `list_peers`
- `list_swaps` -> `list_swaps`
- `list_transactions` -> `list_transactions`
- `list_transfers` -> `list_transfers`
- `list_unspents` -> `list_unspents`
- `ln_invoice` -> `ln_invoice` (SDK internals use `create_ln_invoice`)
- `maker_execute` -> `makerexecute`
- `maker_init` -> `makerinit`
- `network_info` -> `network_info`
- `node_info` -> `node_info`
- `open_channel` -> `openchannel`
- `post_asset_media` -> `postassetmedia`
- `refresh_transfers` -> `refreshtransfers`
- `rgb_invoice` -> `rgbinvoice`
- `send_btc` -> `sendbtc`
- `send_onion_message` -> `sendonionmessage`
- `send_payment` -> `sendpayment`
- `send_rgb` -> `send_rgb`
- `sign_message` -> `sign_message`
- `sync` -> `sync`
- `taker` -> `taker`
- `unlock` -> `unlock`

Still missing route mappings in SDK/UniFFI:
- `backup`
- `change_password`
- `lock`
- `restore`
- `revoke_token`

Special note:
- `shutdown` exists on `SdkNode` as a native node-handle operation, but there is no dedicated route-parity `sdk::shutdown` function matching `routes::shutdown`.

Manual mixed-language interop runbook:
- `RUST_PYTHON_INTEROP_MANUAL.md` in this directory (Rust daemon node + Python UniFFI node).

## Maintenance

`rgb-lightning-node` is a fork and we keep feature parity with upstream.
UniFFI support adds a required manual sync checklist when upstream changes:

1. Sync upstream changes into this fork.
2. Re-check SDK/REST parity for changed endpoints in `src/routes.rs` and `src/sdk/mod.rs`.
3. Update `bindings/rgb_lightning_node.udl` for any public API shape changes.
4. Add/update converters in `src/ffi/types.rs` for new structured identifiers.
5. Regenerate bindings:
   - `./scripts/ci/uniffi_generate_all.sh`
6. Re-run required tests:
   - `cargo test -- --test-threads=1`
   - `cargo test --features uniffi --lib uniffi_smoke_tests:: -- --test-threads=1`
   - `cargo test zero_amount_invoice -- --test-threads=1`
   - `cargo test send_receive -- --test-threads=1`

## Release checklist

1. Run Rust checks:
   - `cargo check`
   - `cargo check --features uniffi`
2. Run core tests:
   - `cargo test -- --test-threads=1`
   - `cargo test --features uniffi --lib uniffi_smoke_tests:: -- --test-threads=1`
3. Regenerate bindings and verify changed output:
   - `./scripts/ci/uniffi_generate_all.sh`
4. Ensure CI workflows pass:
   - `.github/workflows/test.yaml`
   - `.github/workflows/sdk-e2e.yaml`
   - `.github/workflows/uniffi-artifacts.yaml`

## Main code changes in `uniffi_api/mod.rs`

`mod.rs` is now the main UniFFI API surface and was reworked around four goals:

1. Keep UniFFI entrypoints thin and deterministic.
2. Reuse SDK/core logic from `crate::sdk` instead of route handlers.
3. Move from global process state to instance-based node usage.
4. Preserve temporary compatibility for older global `sdk_*` call patterns.

Detailed structure:

1. Input normalization and node construction:
- `network_from_str` validates external string input and maps it to
  `rgb_lib::BitcoinNetwork`.
- `handle_from_request` builds `NodeConfig` and creates a `NodeHandle` using
  `block_on_app(...)`.
- This isolates initialization concerns so both object API and compatibility
  wrappers reuse the same constructor path.

2. Shared operation helpers:
- `send_rgb_from_state` performs argument validation and request conversion from
  UniFFI DTOs into internal `routes`/`rgb_lib` recipient representations.
- The function is intentionally separated from `SdkNode` methods so both
  instance and compatibility paths share identical behavior.

3. Instance-based API (`SdkNode`):
- `SdkNode::create` owns node initialization and returns a concrete instance.
- Methods (`node_info`, `get_channel_id`, `get_payment`, `get_swap`,
  `ln_invoice`, `send_rgb`, `shutdown`) call `crate::sdk::*` and map outputs
  into UniFFI-safe DTOs.
- This removed the previous hard single-global-handle requirement for generated
  bindings and enables multiple independent SDK node objects per process.

4. Compatibility wrappers (`sdk_*`):
- `sdk_initialize`, `sdk_shutdown`, and `sdk_*` read/write a global slot through
  `state.rs` and internally delegate to `SdkNode` methods.
- They remain for transition and internal compatibility, but the generated UDL
  surface is instance-first.

5. Error conversion behavior:
- Conversion failures and internal mapping failures return `RlnError::Internal`.
- User/input/domain validation failures are surfaced as `RlnError::InvalidRequest`.
- Missing resources (`PaymentNotFound`, `SwapNotFound`, `Unknown*`) map to
  `RlnError::NotFound`.
- State conflicts (`OpenChannelInProgress`, `Already*`, etc.) map to
  `RlnError::Conflict`.
- Initialization/locked-state situations return `RlnError::NotInitialized`.

## Main code changes in `uniffi_api/state.rs`

`state.rs` was refactored into a dedicated bridge layer for three concerns:
global compatibility state, sync/async runtime bridging, and stable error
mapping.

Detailed structure:

1. Global compatibility state management:
- The global slot stores `Option<NodeHandle>` (not raw daemon-only state), so
  wrappers can delegate through the same node abstraction used by instance API.
- `set_uniffi_node_handle`, `clear_uniffi_node_handle`,
  `is_uniffi_app_state_initialized`, and `get_uniffi_app_state` are the only
  access points.
- Lock poisoning is handled explicitly; no `unwrap()` is used on mutex lock.
  Failures are logged and mapped to controlled errors instead of panicking.

2. Runtime bridge for synchronous UniFFI calls:
- `block_on_sdk` executes futures returning `Result<T, APIError>`.
- `block_on_app` executes futures returning `Result<T, AppError>`.
- Runtime policy:
  - If in Tokio `MultiThread`: use `block_in_place(|| handle.block_on(...))`.
  - If in Tokio `CurrentThread`: use shared fallback runtime.
  - If no runtime exists: use shared fallback runtime.
- `shared_uniffi_runtime()` centralizes fallback runtime creation with
  `OnceLock`, avoiding per-call runtime creation and preventing current-thread
  `block_in_place` panic paths.

3. Stable public error mapping:
- `map_api_error` converts internal `APIError` variants into narrow public
  `RlnError` categories used by foreign bindings.
- `map_app_error` does the same for `AppError`.
- This keeps external error contracts stable even when internal errors evolve.

4. Why this split exists:
- `mod.rs` focuses on API behavior and request/response conversion.
- `state.rs` focuses on execution context and safety boundaries.
- Separating them reduces coupling, makes runtime logic testable in isolation,
  and avoids repeating bridge code in every UniFFI method.

Build with UniFFI enabled:
```sh
cargo check --features uniffi
```

Generate all bindings:
```sh
./scripts/ci/uniffi_generate_all.sh
```

Generate per language:
```sh
./scripts/ci/uniffi_generate_kotlin.sh
./scripts/ci/uniffi_generate_kotlin_android.sh
./scripts/ci/uniffi_generate_python.sh
./scripts/ci/uniffi_generate_swift.sh
```

Quick SDK smoke tests:
```sh
cargo test --features uniffi --lib uniffi_smoke_tests:: -- --test-threads=1
```

Library-only test suite (no daemon/API routing):
```sh
cargo test --features "uniffi,test-utils" \
  --test lib_core_uniffi_state \
  --test lib_core_type_converters \
  --test lib_core_error_mapping \
  --test lib_core_node_handle_invariants
```

Strict lint after library-core changes:
```sh
cargo clippy --all-targets --all-features -- -D warnings
```

PR CI gate for these tests:
- `.github/workflows/uniffi-artifacts.yaml` job: `library-core-tests`

Kotlin/JVM artifact build (Linux host):
```sh
cargo build --release --features uniffi --lib
./scripts/ci/uniffi_generate_kotlin.sh
```

Kotlin/Android artifact build (requires `ANDROID_NDK_HOME` + `cargo-ndk`):
```sh
./scripts/ci/uniffi_generate_kotlin_android.sh
./scripts/ci/build_android_jni.sh
```

Local Android NDK setup (Ubuntu, CLI):
```sh
# 1) Install Java + Rust helper
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk unzip cmake clang pkg-config build-essential ninja-build
cargo install cargo-ndk --version 3.5.4 --locked
cargo install bindgen-cli --version 0.71.1 --locked

# 2) Install Android cmdline-tools (pick your own SDK root if needed)
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
cd /tmp
wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdline-tools.zip
unzip -q cmdline-tools.zip
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools/latest"
mv cmdline-tools/* "$ANDROID_SDK_ROOT/cmdline-tools/latest/"

# 3) Install NDK + build tools used by local checks/CI
"$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" --licenses
"$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" \
  "ndk;26.3.11579264" "platform-tools" "build-tools;34.0.0"

# 4) Export env vars for this shell
export ANDROID_NDK_HOME="$ANDROID_SDK_ROOT/ndk/26.3.11579264"
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$PATH"
```

Then build Android artifacts:
```sh
./scripts/ci/uniffi_generate_kotlin_android.sh
./scripts/ci/build_android_jni.sh
```

Swift artifact build (macOS):
```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo build --release --features uniffi --lib --target aarch64-apple-ios
cargo build --release --features uniffi --lib --target aarch64-apple-ios-sim
cargo build --release --features uniffi --lib --target x86_64-apple-ios
./scripts/ci/uniffi_generate_swift.sh
./scripts/ci/package_swift_xcframework.sh
```

Parity tests used in CI:
```sh
cargo test zero_amount_invoice -- --test-threads=1
cargo test send_receive -- --test-threads=1
```

CI artifact packaging workflow:
- `.github/workflows/uniffi-artifacts.yaml`
- Artifacts produced:
  - Swift: `RGBLightningNode.xcframework`
  - Kotlin JVM host bundle: generated Kotlin sources + Linux `librgb_lightning_node.so`
  - Kotlin Android: `jniLibs` + generated Kotlin sources
