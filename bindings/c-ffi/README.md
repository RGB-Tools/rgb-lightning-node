# C and C++ bindings for rgb-lightning-node

This crate exposes the `SdkNode` API of `rgb-lightning-node` over a C ABI so it
can be consumed from any language with a C FFI (Node.js / Bun via N-API,
[Bare](https://github.com/holepunchto/bare-runtime), Swift via clang module
import, Python via ctypes, etc.).

It is a thin extern-"C" shim on top of the existing UniFFI-exposed API in
[`src/uniffi_api/`](../../src/uniffi_api). All complex types cross the boundary
as JSON strings; the same async-bridge (`block_on_sdk` in
[`state.rs`](../../src/uniffi_api/state.rs)) is reused, so callers see a
synchronous API.

> :warning: **Use at your own risk.** These bindings are unstable and the
> JSON schema may evolve.

## Building

From this directory:

```sh
cargo build              # debug static + dylib
cargo build --release    # optimized
```

Output artefacts (under `target/{debug,release}/`):

- `librlncffi.a` — static library, suitable for embedding into another binding
  (e.g. a Bare native addon).
- `librlncffi.dylib` / `librlncffi.so` — dynamic library, suitable for direct
  loading via `ctypes` / `dlopen`.
- `rln.h` / `rln.hpp` — generated headers (committed-to-tree-friendly via
  `build.rs`).

## API surface

Every public method on `uniffi_api::SdkNode` is exposed as a `rln_<method>`
extern "C" function that takes an opaque `COpaqueStruct*` handle plus
per-method JSON request strings, and returns `CResultString` (JSON response
or error message). The lifecycle functions are:

- `rln_sdk_node_new(request_json) -> CResult` — create an `SdkNode`.
- `rln_sdk_node_init(handle, password, mnemonic_opt) -> CResultString`
- `rln_sdk_node_unlock(handle, request_json) -> CResultString`
- `rln_sdk_node_shutdown(handle) -> CResultString`
- `free_sdk_node(handle)` — drops the boxed handle.

A small set of namespace-level helpers (`rln_uniffi_healthcheck`,
`rln_uniffi_is_initialized`, `rln_sdk_initialize`, `rln_sdk_shutdown`) mirror
the global-singleton path used by some UniFFI clients.

## Memory ownership

- Strings returned in the `inner` field of `CResultString` are heap-allocated
  by the FFI; the caller must free them with `rln_free_string`.
- Opaque `COpaqueStruct` handles returned in `CResult.inner` are owned by the
  caller and must be released with the appropriate `free_*` function (e.g.
  `free_sdk_node`).

## Format

```sh
make format
```
