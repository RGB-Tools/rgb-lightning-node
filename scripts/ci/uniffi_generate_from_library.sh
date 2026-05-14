#!/usr/bin/env bash
# Generate Kotlin or Swift bindings from a built rgb_lightning_node library so that
# proc-macro-only exports (e.g. NativeExternalSigner behind `vls`) are included.
# Requires: `cargo build --release --features "uniffi,vls" --lib` first.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

LANGUAGE="${1:-}"
if [[ "$LANGUAGE" != "kotlin" && "$LANGUAGE" != "swift" ]]; then
  echo "usage: $0 <kotlin|swift> [output_dir] [path_to_librgb_lightning_node.so_or_dylib] [config_path]"
  exit 1
fi

OUT_DIR="${2:-}"
if [[ -z "$OUT_DIR" ]]; then
  case "$LANGUAGE" in
    kotlin) OUT_DIR="target/uniffi/kotlin-from-library" ;;
    swift) OUT_DIR="target/uniffi/swift-from-library" ;;
  esac
fi

# Default: host `target/release/`. When Cargo builds with `--target <triple>`, use that tree or pass
# the .so/.dylib path as the 3rd argument (or set UNIFFI_LIBRARY_PATH).
LIB_PATH="${3:-${UNIFFI_LIBRARY_PATH:-}}"
CONFIG_PATH="${4:-${UNIFFI_CONFIG_PATH:-$ROOT_DIR/uniffi.toml}}"
if [[ -z "$LIB_PATH" ]]; then
  if [[ -f "$ROOT_DIR/target/release/librgb_lightning_node.so" ]]; then
    LIB_PATH="$ROOT_DIR/target/release/librgb_lightning_node.so"
  elif [[ -f "$ROOT_DIR/target/release/librgb_lightning_node.dylib" ]]; then
    LIB_PATH="$ROOT_DIR/target/release/librgb_lightning_node.dylib"
  elif [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    if [[ -f "$ROOT_DIR/target/${CARGO_BUILD_TARGET}/release/librgb_lightning_node.so" ]]; then
      LIB_PATH="$ROOT_DIR/target/${CARGO_BUILD_TARGET}/release/librgb_lightning_node.so"
    elif [[ -f "$ROOT_DIR/target/${CARGO_BUILD_TARGET}/release/librgb_lightning_node.dylib" ]]; then
      LIB_PATH="$ROOT_DIR/target/${CARGO_BUILD_TARGET}/release/librgb_lightning_node.dylib"
    fi
  fi
fi

if [[ -z "$LIB_PATH" || ! -f "$LIB_PATH" ]]; then
  echo "ERROR: release library not found for UniFFI --library (pass as 3rd arg or set UNIFFI_LIBRARY_PATH)."
  echo "  Tried: target/release/librgb_lightning_node.{so,dylib}"
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    echo "  Also: target/${CARGO_BUILD_TARGET}/release/librgb_lightning_node.{so,dylib}"
  fi
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command '$1' not found"
    exit 1
  }
}
need_cmd cargo

mkdir -p "$OUT_DIR"

TEMP_UDL="$ROOT_DIR/src/rgb_lightning_node.udl"
CLEANUP_UDL=0
if [[ ! -e "$TEMP_UDL" ]]; then
  cp "$ROOT_DIR/bindings/rgb_lightning_node.udl" "$TEMP_UDL"
  CLEANUP_UDL=1
fi

cargo run --manifest-path "$ROOT_DIR/bindings/uniffi-bindgen/Cargo.toml" -- \
  generate "$LIB_PATH" \
  --library \
  --crate rgb_lightning_node \
  --language "$LANGUAGE" \
  --config "$CONFIG_PATH" \
  -o "$OUT_DIR"

if [[ "$CLEANUP_UDL" == "1" ]]; then
  rm -f "$TEMP_UDL"
fi

echo "Generated $LANGUAGE bindings from library into $OUT_DIR"
