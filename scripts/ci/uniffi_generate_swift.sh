#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="target/uniffi/swift"
mkdir -p "$OUT_DIR"

cargo run --manifest-path bindings/uniffi-bindgen/Cargo.toml -- \
  generate bindings/rgb_lightning_node.udl \
  --language swift \
  --config uniffi.toml \
  -o "$OUT_DIR"

echo "Generated Swift bindings in $OUT_DIR"
