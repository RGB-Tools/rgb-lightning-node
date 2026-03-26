#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SWIFT_DIR="target/uniffi/swift"
mkdir -p "$SWIFT_DIR/headers"
cp "$SWIFT_DIR/RGBLightningNodeFFI.h" "$SWIFT_DIR/headers/"
cp "$SWIFT_DIR/RGBLightningNodeFFI.modulemap" "$SWIFT_DIR/headers/module.modulemap"

SIM_ARM64_LIB="target/aarch64-apple-ios-sim/release/librgb_lightning_node.a"
SIM_X86_64_LIB="target/x86_64-apple-ios/release/librgb_lightning_node.a"
SIM_UNIVERSAL_DIR="target/uniffi/swift/simulator-universal"
SIM_UNIVERSAL_LIB="$SIM_UNIVERSAL_DIR/librgb_lightning_node.a"
mkdir -p "$SIM_UNIVERSAL_DIR"
lipo -create "$SIM_ARM64_LIB" "$SIM_X86_64_LIB" -output "$SIM_UNIVERSAL_LIB"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/librgb_lightning_node.a -headers "$SWIFT_DIR/headers" \
  -library "$SIM_UNIVERSAL_LIB" -headers "$SWIFT_DIR/headers" \
  -output "$SWIFT_DIR/RGBLightningNode.xcframework"

echo "Packaged $SWIFT_DIR/RGBLightningNode.xcframework"
