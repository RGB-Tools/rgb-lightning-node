#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$ROOT_DIR/test/swift-e2e"
SWIFT_GEN_DIR="$ROOT_DIR/target/uniffi/swift"

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

# [TEST: Linux runner] Original macOS-only guard commented out for ubuntu runner testing.
# if [[ "$(uname -s)" != "Darwin" ]]; then
#   echo "swift-e2e requires macOS"
#   exit 1
# fi

need_cmd cargo
need_cmd rustup
need_cmd swift
need_cmd docker

ensure_regtest_available

# [TEST: Linux runner] Original macOS-only target detection:
# case "$(uname -m)" in
#   arm64)
#     MACOS_RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-aarch64-apple-darwin}"
#     ;;
#   x86_64)
#     MACOS_RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-x86_64-apple-darwin}"
#     ;;
#   *)
#     echo "unsupported macOS architecture: $(uname -m)"
#     exit 1
#     ;;
# esac

# [TEST: Linux runner] Cross-platform target detection (macOS + Linux).
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64)  RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-aarch64-apple-darwin}" ;;
      x86_64) RUST_TARGET="${SWIFT_UNIFFI_RUST_TARGET:-x86_64-apple-darwin}" ;;
      *)      echo "unsupported macOS architecture: $(uname -m)"; exit 1 ;;
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
cargo build --release --features uniffi --lib --target "$RUST_TARGET"
./scripts/ci/uniffi_generate_swift.sh

mkdir -p \
  "$TEST_DIR/Sources/RGBLightningNode" \
  "$TEST_DIR/FFI" \
  "$TEST_DIR/$LIB_DIR"

cp "$SWIFT_GEN_DIR/RGBLightningNode.swift" "$TEST_DIR/Sources/RGBLightningNode/RGBLightningNode.swift"
cp "$SWIFT_GEN_DIR/RGBLightningNodeFFI.h" "$TEST_DIR/FFI/RGBLightningNodeFFI.h"
cp "$SWIFT_GEN_DIR/RGBLightningNodeFFI.modulemap" "$TEST_DIR/FFI/module.modulemap"
cp "$ROOT_DIR/target/$RUST_TARGET/release/librgb_lightning_node.a" "$TEST_DIR/$LIB_DIR/librgb_lightning_node.a"

cd "$TEST_DIR"
swift test
