#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

JNA_JAR="${JNA_JAR:-/usr/share/java/jna.jar}"
OUT_DIR="target/uniffi/kotlin-external-signer-smoke"
SMOKE_JAR="$OUT_DIR/smoke.jar"
MAIN_SRC="test/kotlin-external-signer-smoke/ExternalSignerSmoke.kt"
KOTLIN_FROM_LIB="target/uniffi/kotlin-from-library"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command '$1' not found"
    exit 1
  }
}

need_cmd cargo
need_cmd java
need_cmd kotlinc

[ -f "$JNA_JAR" ] || {
  echo "ERROR: JNA jar not found at '$JNA_JAR' (override with JNA_JAR=/path/to/jna.jar)"
  exit 1
}

cargo build --release --features "uniffi,vls,vss" --lib
"$ROOT_DIR/scripts/ci/uniffi_generate_from_library.sh" kotlin "$KOTLIN_FROM_LIB"

mkdir -p "$OUT_DIR"

mapfile -t GENERATED_SOURCES < <(find "$KOTLIN_FROM_LIB" -type f -name '*.kt' | sort)
[ "${#GENERATED_SOURCES[@]}" -gt 0 ] || {
  echo "ERROR: no generated Kotlin sources found under $KOTLIN_FROM_LIB"
  exit 1
}

kotlinc \
  -cp "$JNA_JAR" \
  "${GENERATED_SOURCES[@]}" \
  "$MAIN_SRC" \
  -include-runtime \
  -d "$SMOKE_JAR"

echo "Built Kotlin external-signer smoke jar at $SMOKE_JAR"
