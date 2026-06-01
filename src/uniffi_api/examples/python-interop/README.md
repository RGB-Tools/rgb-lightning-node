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
# Internal-signer-only flows (e.g. `manual_py_full_n2n.py`):
cargo build --release --features uniffi --lib

# Flows that use `NativeExternalSigner` / VLS (`manual_py_external_signer_e2e.py`):
cargo build --release --features uniffi,vls --lib

./scripts/ci/uniffi_generate_python.sh
```

`LnInvoiceRequest` is keyword-only in Python; pass `payment_hash=None` when you do not set a custom payment hash (see `manual_py_full_n2n.py`).

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

Virtual channels SDK test:

```sh
python3 src/uniffi_api/examples/python-interop/manual_py_virtual_channels_sdk.py
```

External signer E2E examples:

1. Regular channel flow with real native external signer via UniFFI:

```sh
RESET_DATA=1 \
python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
  --scenario regular-flow-real
```

Note:
- No HTTP endpoint is used in this flow.
- Python constructs `NativeExternalSigner(...)` from a fixed `seed_hex` (passed in-memory; no signer-side seed persistence in RLN).
- The signer seed is created and persisted inside that signer directory.
- The UniFFI flow now uses:
  - `init_with_native_external_signer(...)`
  - `unlock_with_native_external_signer(...)`

Stable shell target for the same real flow:

```sh
START_REGTEST=1 \
./scripts/ci/external_signer_real_e2e.sh
```

Optional env overrides:

```sh
export RLN_TEST_NATIVE_SIGNER_NETWORK="regtest"
export RLN_TEST_NATIVE_SIGNER_PERMISSIVE_POLICY="1"
./scripts/ci/external_signer_real_e2e.sh
```

2. Real signer mismatch rejection on restart:

```sh
RESET_DATA=1 \
python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
  --scenario restart-mismatch-real
```

3. Real signer restart-without-reattach and recovery:

```sh
RESET_DATA=1 \
python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
  --scenario connection-loss-real
```

4. **Mixed RGB + external signer scenario** (`mixed-asset-channel-real`): **skipped by default**
   (prints `SKIP …` unless you opt in). Internal signer on node A, `NativeExternalSigner` (VLS) on
   node B; requires `RUN_MIXED_ASSET_EXTERNAL_E2E=1` and a `uniffi,vls` build.

   ```sh
   RUN_MIXED_ASSET_EXTERNAL_E2E=1 RESET_DATA=1 \
   python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
     --scenario mixed-asset-channel-real
   ```

   Optional env for this flow:

   - `PY_EXT_SIGNER_DEBUG=1` — print ~10s progress while waiting on funding / visibility.
   - `PY_EXT_SIGNER_FUNDING_MEMPOOL_FALLBACK=0` — disable the regtest-only heuristic that treats a
     **sole** mempool transaction as the funding tx when `list_channels()` is slow to expose
     `funding_txid` (single-channel flows only).
   - `PAYMENT_SUCCEEDED_TIMEOUT_SEC` — seconds to wait for `HtlcStatus.SUCCEEDED` after `sendpayment`
     (default `300`; payment wait also syncs the peer and mines a block every 5 polls, like `lib_sdk`).

5. **Mixed RGB round-trip payment** (`mixed-asset-channel-roundtrip-real`): same mixed
   internal/external RGB flow, then attempt to send the same RGB amount back from the
   external-signer node to the internal node. Use this as the direct validation/regression scenario
   for outbound RGB from RLN with external signer. This scenario opens the channel with a higher
   push amount by default (`ROUNDTRIP_OPEN_CHANNEL_PUSH_MSAT=6000000`) so the external-signer node
   has enough outbound msat to satisfy the RGB HTLC minimum on the reverse payment.

   ```sh
   RUN_MIXED_ASSET_EXTERNAL_E2E=1 RESET_DATA=1 \
   python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
     --scenario mixed-asset-channel-roundtrip-real
   ```

6. **Mixed RGB cooperative close settlement** (`mixed-asset-channel-coop-close-real`): same mixed
   internal/external RGB flow, then cooperative close and explicit on-chain balance assertions.

   ```sh
   RUN_MIXED_ASSET_EXTERNAL_E2E=1 RESET_DATA=1 \
   python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
     --scenario mixed-asset-channel-coop-close-real
   ```

7. **Mixed RGB force-close settlement** (`mixed-asset-channel-force-close-real`): same mixed
   internal/external RGB flow, then force close and wait for balances to settle after CSV.
   Useful as a focused regression scenario for receiver-side sweep and settlement after CSV.

   ```sh
   RUN_MIXED_ASSET_EXTERNAL_E2E=1 RESET_DATA=1 \
   python3 src/uniffi_api/examples/python-interop/manual_py_external_signer_e2e.py \
     --scenario mixed-asset-channel-force-close-real
   ```

Note:
- `mixed-asset-channel-real` honors `OPEN_CHANNEL_PUSH_MSAT` and has been validated with a non-zero
  BTC push (`3_500_000 msat`) on the current branch.
- The regular example scenarios still default to `push_msat=0` unless explicitly changed in the
  script.

Stable shell target for any supported native signer scenario:

```sh
START_REGTEST=1 \
EXTERNAL_SIGNER_SCENARIO=regular-flow-real \
./scripts/ci/external_signer_real_e2e.sh
```

Other supported scenarios:

```sh
START_REGTEST=1 \
EXTERNAL_SIGNER_SCENARIO=restart-mismatch-real \
./scripts/ci/external_signer_real_e2e.sh

START_REGTEST=1 \
EXTERNAL_SIGNER_SCENARIO=connection-loss-real \
./scripts/ci/external_signer_real_e2e.sh

START_REGTEST=1 \
EXTERNAL_SIGNER_SCENARIO=mixed-asset-channel-roundtrip-real \
./scripts/ci/external_signer_real_e2e.sh

START_REGTEST=1 \
EXTERNAL_SIGNER_SCENARIO=mixed-asset-channel-coop-close-real \
./scripts/ci/external_signer_real_e2e.sh

START_REGTEST=1 \
EXTERNAL_SIGNER_SCENARIO=mixed-asset-channel-force-close-real \
./scripts/ci/external_signer_real_e2e.sh
```

In this scenario:
- payment succeeds
- node restarts without a reattached signer and unlock fails
- same signer is reattached
- unlock succeeds and payment resumes

Or for the virtual channels SDK test:

```sh
RESET_DATA=1 \
python3 src/uniffi_api/examples/python-interop/manual_py_virtual_channels_sdk.py
```

Note: trusted virtual close is currently host-authoritative: node A (host side)
can close successfully while node B may temporarily keep a non-usable/opened
view. `REQUIRE_CLOSE_SUCCESS=1` now validates host-side close completion.

Notes:

- `RESET_DATA=1` removes storage dirs before run.
- Script uses `./regtest.sh sendtoaddress` and `./regtest.sh mine` for funding/confirmations.
- Script uses SDK methods (`createutxos`, `issueassetnia`) before opening the channel.
- Script shuts down both SDK nodes on exit.
- `manual_py_virtual_channels_sdk.py` focuses on virtual channels:
  creates a `trusted_no_broadcast` channel, verifies `virtual_open_mode`
  in `list_channels`, sends a `keysend` over that channel, and closes it.

## Cleanup

```sh
./regtest.sh stop
```
