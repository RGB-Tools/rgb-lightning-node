# Rust SDK Parity Tests

This suite runs the public `SdkNode` / UniFFI library path and checks parity
against the existing HTTP-based test scenarios.

## Prerequisites

Start local regtest services:

```sh
./regtest.sh start
```

## Run

Run the full SDK suite:

```sh
cargo test --features uniffi --test lib_sdk -- --test-threads=1
```

Run a single scenario:

```sh
cargo test --features uniffi --test lib_sdk <test_name> -- --test-threads=1
```

Examples of `<test_name>`:
- `success`
- `send_receive`
- `close_coop_standard`
- `close_coop_other_side`
- `close_force_standard`
- `multi_hop`
- `openchannel_push_asset_amount`
- `restart`
- `swap_roundtrip_buy`
- `vanilla_payment_on_rgb_channel`
- `with_anchors`
- `without_anchors`

## Cleanup

```sh
./regtest.sh stop
```
