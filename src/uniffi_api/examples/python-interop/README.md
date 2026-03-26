# Python UniFFI Asset Channel Example

This example runs a full local regtest flow from Python and demonstrates:

1. Create two `SdkNode` instances in-process
2. `init` + `unlock` both
3. Fund both nodes on regtest
4. Call SDK methods `createutxos` and `issueassetnia` before channel open
5. `connectpeer` + open an RGB asset channel (`asset_id` + `asset_amount`)
6. Create RGB invoice on node B via `ln_invoice` with asset fields
7. Pay from node A via `sendpayment` with the same asset fields
8. Verify final invoice status via `invoice_status`

## Prerequisites

From repo root:

Build library and generate Python bindings:

```sh
cargo build --release --features uniffi --lib
./scripts/ci/uniffi_generate_python.sh
```

Set env:

```sh
export PYTHONPATH="$PWD/target/uniffi/python:${PYTHONPATH:-}"
export LD_LIBRARY_PATH="$PWD/target/release:${LD_LIBRARY_PATH:-}"
```

Start regtest dependencies:

```sh
./regtest.sh start
```

## Run

```sh
python3 src/uniffi_api/examples/python-interop/manual_py_full_n2n.py
```

Optional env overrides:

```sh
RESET_DATA=1 \
NODE_A_STORAGE="$PWD/sdkdata_py/node_a" \
NODE_B_STORAGE="$PWD/sdkdata_py/node_b" \
NODE_A_PEER_PORT=9735 \
NODE_B_PEER_PORT=9736 \
OPEN_CHANNEL_ASSET_AMOUNT=200 \
PAYMENT_ASSET_AMOUNT=50 \
PAYMENT_MSAT=3000000 \
OPEN_CHANNEL_CONFIRM_BLOCKS=12 \
CHANNEL_READY_TIMEOUT_SEC=300 \
python3 src/uniffi_api/examples/python-interop/manual_py_full_n2n.py
```

Notes:

- `RESET_DATA=1` removes storage dirs before run.
- Script uses `./regtest.sh sendtoaddress` and `./regtest.sh mine` for funding/confirmations.
- Script uses SDK methods (`createutxos`, `issueassetnia`) before opening the channel.
- Script shuts down both SDK nodes on exit.

## Cleanup

```sh
./regtest.sh stop
```
