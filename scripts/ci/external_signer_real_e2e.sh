#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

START_REGTEST="${START_REGTEST:-0}"
RESET_DATA="${RESET_DATA:-1}"
OPEN_CHANNEL_CONFIRM_BLOCKS="${OPEN_CHANNEL_CONFIRM_BLOCKS:-12}"
CHANNEL_READY_TIMEOUT_SEC="${CHANNEL_READY_TIMEOUT_SEC:-300}"
EXTERNAL_SIGNER_SCENARIO="${EXTERNAL_SIGNER_SCENARIO:-regular-flow-real}"
REGTEST_STARTED_BY_SCRIPT=0

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: required command '$1' not found"
        exit 1
    }
}

cleanup() {
    if [[ "${REGTEST_STARTED_BY_SCRIPT}" == "1" ]]; then
        ./regtest.sh stop >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

ensure_regtest_available() {
    local services
    services="$(docker compose ps --services --status running)"
    local service
    for service in bitcoind electrs proxy; do
        echo "$services" | grep -qx "$service" || {
            echo "ERROR: regtest service '$service' is not running"
            exit 1
        }
    done
}

need_cmd cargo
need_cmd python3
need_cmd docker

if [[ "${START_REGTEST}" == "1" ]]; then
    ./regtest.sh start
    REGTEST_STARTED_BY_SCRIPT=1
fi

ensure_regtest_available

# `mixed-asset-channel-real` is opt-in inside the Python scenario; enable it automatically
# when this script is used with that scenario so CI/local runs do not silently skip the flow.
if [[ "${EXTERNAL_SIGNER_SCENARIO}" == "mixed-asset-channel-real" ]]; then
    export RUN_MIXED_ASSET_EXTERNAL_E2E="${RUN_MIXED_ASSET_EXTERNAL_E2E:-1}"
fi

echo "Building UniFFI library..."
cargo build --release --features uniffi,vls,vss --lib
./scripts/ci/uniffi_generate_python.sh
cp target/release/librgb_lightning_node.so target/uniffi/python/librgb_lightning_node.so

echo "Running native external signer Python UniFFI E2E: ${EXTERNAL_SIGNER_SCENARIO}"
PYTHONPATH="$ROOT_DIR/target/uniffi/python:${PYTHONPATH:-}" \
LD_LIBRARY_PATH="$ROOT_DIR/target/release:${LD_LIBRARY_PATH:-}" \
RESET_DATA="${RESET_DATA}" \
OPEN_CHANNEL_CONFIRM_BLOCKS="${OPEN_CHANNEL_CONFIRM_BLOCKS}" \
CHANNEL_READY_TIMEOUT_SEC="${CHANNEL_READY_TIMEOUT_SEC}" \
RUN_MIXED_ASSET_EXTERNAL_E2E="${RUN_MIXED_ASSET_EXTERNAL_E2E:-}" \
PY_EXT_SIGNER_SCENARIO="${EXTERNAL_SIGNER_SCENARIO}" \
python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
  --scenario "${EXTERNAL_SIGNER_SCENARIO}"

echo "Native external signer UniFFI E2E passed: ${EXTERNAL_SIGNER_SCENARIO}"
