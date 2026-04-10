#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: required command '$1' not found"
        exit 1
    }
}

need_env() {
    [ -n "${!1:-}" ] || {
        echo "ERROR: required environment variable '$1' is not set"
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

ensure_android_device_available() {
    adb start-server >/dev/null 2>&1 || true

    adb devices | awk '
        NR > 1 && $2 == "device" { found = 1 }
        END { exit found ? 0 : 1 }
    ' || {
        echo "ERROR: no Android emulator/device visible in 'adb devices'"
        exit 1
    }
}

need_cmd cargo
need_cmd java
need_cmd adb
need_cmd docker

need_env ANDROID_NDK_HOME

ensure_regtest_available
ensure_android_device_available

./scripts/ci/build_android_jni_x86_64.sh
./scripts/ci/uniffi_generate_kotlin_android.sh

(
    cd android-e2e
    ./gradlew connectedDebugAndroidTest
)
