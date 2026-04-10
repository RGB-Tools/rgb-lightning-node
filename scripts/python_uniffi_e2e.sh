#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

E2E_MAIN="test/python-e2e/PythonUniffiE2e.py"

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

need_cmd cargo
need_cmd python3
need_cmd docker

ensure_regtest_available

cargo build --release --features uniffi --lib
./scripts/ci/uniffi_generate_python.sh

PYTHONPATH="$ROOT_DIR/target/uniffi/python:${PYTHONPATH:-}" \
LD_LIBRARY_PATH="$ROOT_DIR/target/release:${LD_LIBRARY_PATH:-}" \
python3 "$E2E_MAIN"
