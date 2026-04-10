#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_ROOT="${KOTLIN_E2E_ARTIFACT_ROOT:-$ROOT_DIR}"
JNA_JAR="${JNA_JAR:-/usr/share/java/jna.jar}"
E2E_JAR="${KOTLIN_E2E_JAR:-$ARTIFACT_ROOT/target/uniffi/kotlin-e2e/e2e.jar}"
LIB_DIR="${KOTLIN_E2E_LIB_DIR:-$ARTIFACT_ROOT/target/release}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command '$1' not found"
    exit 1
  }
}

need_cmd java

[ -f "$JNA_JAR" ] || {
  echo "ERROR: JNA jar not found at '$JNA_JAR' (override with JNA_JAR=/path/to/jna.jar)"
  exit 1
}

[ -f "$E2E_JAR" ] || {
  echo "ERROR: Kotlin E2E jar not found at '$E2E_JAR'"
  exit 1
}

[ -f "$LIB_DIR/librgb_lightning_node.so" ] || {
  echo "ERROR: librgb_lightning_node.so not found under '$LIB_DIR'"
  exit 1
}

LD_LIBRARY_PATH="$LIB_DIR:${LD_LIBRARY_PATH:-}" \
java \
  -Djna.library.path="$LIB_DIR" \
  -cp "$E2E_JAR:$JNA_JAR" \
  KotlinUniffiE2eKt
