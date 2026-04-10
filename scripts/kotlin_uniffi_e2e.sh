#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

JNA_JAR="${JNA_JAR:-/usr/share/java/jna.jar}"

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
need_cmd java
need_cmd kotlinc
need_cmd docker

[ -f "$JNA_JAR" ] || {
    echo "ERROR: JNA jar not found at '$JNA_JAR' (override with JNA_JAR=/path/to/jna.jar)"
    exit 1
}

ensure_regtest_available

JNA_JAR="$JNA_JAR" ./scripts/ci/build_kotlin_e2e.sh
JNA_JAR="$JNA_JAR" ./scripts/ci/run_kotlin_e2e.sh
