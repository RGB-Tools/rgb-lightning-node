# Python UniFFI E2E Harness

This harness runs local regtest end-to-end scenarios against the public `SdkNode`
/ UniFFI path from Python.

Current scenarios:

1. `payment`
2. `openchannel_push_asset_amount`
3. `getchannelid_fail`
4. `openchannel_fail_no_utxos`
5. `openchannel_fail_unknown_asset`

## Prerequisites

Required tools:
- `cargo`
- `python3`
- `docker`

Start local regtest services:

```sh
./regtest.sh start
```

## Run

Default scenario:

```sh
RESET_DATA=1 ./scripts/python_uniffi_e2e.sh
```

Run a specific scenario:

```sh
RESET_DATA=1 PYTHON_E2E_SCENARIO=payment ./scripts/python_uniffi_e2e.sh
RESET_DATA=1 PYTHON_E2E_SCENARIO=openchannel_push_asset_amount ./scripts/python_uniffi_e2e.sh
RESET_DATA=1 PYTHON_E2E_SCENARIO=getchannelid_fail ./scripts/python_uniffi_e2e.sh
RESET_DATA=1 PYTHON_E2E_SCENARIO=openchannel_fail_no_utxos ./scripts/python_uniffi_e2e.sh
RESET_DATA=1 PYTHON_E2E_SCENARIO=openchannel_fail_unknown_asset ./scripts/python_uniffi_e2e.sh
```

Run all scenarios locally:

```sh
cargo build --release --features uniffi --lib
./scripts/ci/uniffi_generate_python.sh

export PYTHONPATH="$PWD/target/uniffi/python:${PYTHONPATH:-}"
export LD_LIBRARY_PATH="$PWD/target/release:${LD_LIBRARY_PATH:-}"

RESET_DATA=1 PYTHON_E2E_SCENARIO=all python3 test/python-e2e/PythonUniffiE2e.py
```

## CI Usage

Recommended CI shape:
- build Python UniFFI artifacts once
- upload:
  - `target/release/librgb_lightning_node.so`
  - `target/uniffi/python/**`
- fan out with a matrix over scenarios
- in each matrix job:
  - download artifacts into a known directory
  - export `PYTHONPATH` and `LD_LIBRARY_PATH` to that directory
  - start regtest
  - run one scenario
  - stop regtest with `if: always()`

When adding a new Python scenario, update all three places:
1. this README scenario list
2. `test/python-e2e/PythonUniffiE2e.py`
3. `.github/workflows/sdk-e2e.yaml` matrix

## Cleanup

```sh
./regtest.sh stop
```
