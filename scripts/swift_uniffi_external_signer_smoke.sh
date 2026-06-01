#!/usr/bin/env bash
# Local entrypoint: regtest must be running (`./regtest.sh start`).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

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
need_cmd rustup
need_cmd swift
need_cmd docker

ensure_regtest_available

./scripts/ci/swift_uniffi_external_signer_smoke.sh
