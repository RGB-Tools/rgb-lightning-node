#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="target/uniffi/kotlin-android/jniLibs"
rm -rf "$OUT_DIR"

clean_awslc_build_dirs() {
  local target_triple="$1"
  rm -rf "target/${target_triple}/release/build/aws-lc-sys-"* || true
}

clean_awslc_build_dirs aarch64-linux-android
cargo ndk -t arm64-v8a -o "$OUT_DIR" build --release --features uniffi --lib

clean_awslc_build_dirs armv7-linux-androideabi
cargo ndk -t armeabi-v7a -o "$OUT_DIR" build --release --features uniffi --lib

clean_awslc_build_dirs x86_64-linux-android
cargo ndk -t x86_64 -o "$OUT_DIR" build --release --features uniffi --lib

echo "Built Android JNI libs in $OUT_DIR"
