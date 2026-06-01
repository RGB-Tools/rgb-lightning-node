#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-$ANDROID_NDK_HOME}"
CARGO_FEATURES="${UNIFFI_CARGO_FEATURES:-uniffi}"

OUT_DIR="target/uniffi/kotlin-android/jniLibs"
rm -rf "$OUT_DIR/x86_64"

rm -rf "target/x86_64-linux-android/release/build/aws-lc-sys-"* || true
cargo ndk -t x86_64 -o "$OUT_DIR" build --release --features "$CARGO_FEATURES" --lib

echo "Built Android JNI libs for x86_64 in $OUT_DIR"
