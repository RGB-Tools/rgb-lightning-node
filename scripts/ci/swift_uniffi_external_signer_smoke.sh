#!/usr/bin/env bash
# UniFFI smoke: NativeExternalSigner + initWithNativeExternalSigner + unlockWithNativeExternalSigner.
# Requires regtest (bitcoind, electrs, proxy). Builds with `uniffi,vls,vss` and generates Swift from the
# release library so proc-macro exports match the linked binary.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$ROOT_DIR/test/swift-e2e"
SWIFT_GEN_DIR="$ROOT_DIR/target/uniffi/swift-from-library"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command '$1' not found"
    exit 1
  }
}

ensure_regtest_available() {
  local compose="docker compose"
  $compose ps >/dev/null 2>&1 || {
    echo "ERROR: could not query docker compose state"
    exit 1
  }

  local service
  for service in bitcoind electrs proxy; do
    $compose ps --services --status running | grep -qx "$service" || {
      echo "ERROR: regtest service '$service' is not running; start it with './regtest.sh start'"
      exit 1
    }
  done
}

need_cmd cargo
need_cmd rustup
need_cmd swift
need_cmd docker

ensure_regtest_available

case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64) RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-aarch64-apple-darwin}" ;;
      x86_64) RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-x86_64-apple-darwin}" ;;
      *) echo "unsupported macOS architecture: $(uname -m)"; exit 1 ;;
    esac
    LIB_DIR="Libraries/macos"
    ;;
  Linux)
    RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-x86_64-unknown-linux-gnu}"
    LIB_DIR="Libraries/linux"
    ;;
  *)
    echo "unsupported OS: $(uname -s)"
    exit 1
    ;;
esac

rustup target add "$RUST_TARGET"

cd "$ROOT_DIR"
cargo build --release --features "uniffi,vls,vss" --lib --target "$RUST_TARGET"

UNIFFI_LIB=""
for ext in so dylib; do
  candidate="$ROOT_DIR/target/$RUST_TARGET/release/librgb_lightning_node.$ext"
  if [[ -f "$candidate" ]]; then
    UNIFFI_LIB="$candidate"
    break
  fi
done
if [[ -z "$UNIFFI_LIB" ]]; then
  echo "ERROR: no librgb_lightning_node.so or .dylib under target/$RUST_TARGET/release"
  exit 1
fi

"$ROOT_DIR/scripts/ci/uniffi_generate_from_library.sh" swift "$SWIFT_GEN_DIR" "$UNIFFI_LIB"

mkdir -p \
  "$TEST_DIR/Sources/RGBLightningNode" \
  "$TEST_DIR/FFI" \
  "$TEST_DIR/$LIB_DIR"

cp "$SWIFT_GEN_DIR/RGBLightningNode.swift" "$TEST_DIR/Sources/RGBLightningNode/RGBLightningNode.swift"
cp "$SWIFT_GEN_DIR/RGBLightningNodeFFI.h" "$TEST_DIR/FFI/RGBLightningNodeFFI.h"
cp "$SWIFT_GEN_DIR/RGBLightningNodeFFI.modulemap" "$TEST_DIR/FFI/module.modulemap"
cp "$ROOT_DIR/target/$RUST_TARGET/release/librgb_lightning_node.a" "$TEST_DIR/$LIB_DIR/librgb_lightning_node.a"

cd "$TEST_DIR"
# Must match SwiftExternalSignerSmokeTests.swift `#if RLN_UNIFFI_LIBRARY_VLS`
swift test -Xswiftc -DRLN_UNIFFI_LIBRARY_VLS --filter SwiftExternalSignerSmokeTests
