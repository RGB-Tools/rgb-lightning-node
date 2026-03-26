#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# If a project venv exists, prefer its executables (e.g. yapf for uniffi-bindgen formatting).
if [[ -d "$ROOT_DIR/.venv/bin" ]]; then
  export PATH="$ROOT_DIR/.venv/bin:$PATH"
fi

OUT_DIR="target/uniffi/python"
mkdir -p "$OUT_DIR"

cargo run --manifest-path bindings/uniffi-bindgen/Cargo.toml -- \
  generate bindings/rgb_lightning_node.udl \
  --language python \
  --config uniffi.toml \
  -o "$OUT_DIR"

# UniFFI Python loader expects the native library next to rgb_lightning_node.py.
if [[ "$OSTYPE" == "darwin"* ]]; then
  LIB_NAME="librgb_lightning_node.dylib"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  LIB_NAME="rgb_lightning_node.dll"
else
  LIB_NAME="librgb_lightning_node.so"
fi

if [[ -f "target/release/$LIB_NAME" ]]; then
  cp "target/release/$LIB_NAME" "$OUT_DIR/$LIB_NAME"
  echo "Copied native library to $OUT_DIR/$LIB_NAME"
else
  echo "warning: target/release/$LIB_NAME not found. Build it first with:"
  echo "  cargo build --release --features uniffi --lib"
fi

echo "Generated Python bindings in $OUT_DIR"
