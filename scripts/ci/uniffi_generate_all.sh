#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

"$ROOT_DIR/scripts/ci/uniffi_generate_kotlin.sh"
"$ROOT_DIR/scripts/ci/uniffi_generate_kotlin_android.sh"
"$ROOT_DIR/scripts/ci/uniffi_generate_swift.sh"
"$ROOT_DIR/scripts/ci/uniffi_generate_python.sh"

echo "Generated all UniFFI bindings"
