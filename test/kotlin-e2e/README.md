# Kotlin JVM UniFFI E2E Harness

This harness runs local regtest end-to-end scenarios against the public `SdkNode`
/ UniFFI path from Kotlin/JVM.

Current scenarios:

1. `payment`
2. `openchannel_push_asset_amount`
3. `close_coop_vanilla_with_anchors`
4. `close_coop_vanilla_without_anchors`
5. `openchannel_optional_addr_forward`
6. `openchannel_optional_addr_reverse`

## Prerequisites

Required tools:
- `cargo`
- `java`
- `kotlinc`
- `libjna-java`
- `docker`

Start local regtest services:

```sh
./regtest.sh start
```

If needed, override the default JNA jar path:

```sh
export JNA_JAR=/path/to/jna.jar
```

## Run

Default scenario:

```sh
RESET_DATA=1 ./scripts/kotlin_uniffi_e2e.sh
```

Run a specific scenario:

```sh
RESET_DATA=1 KOTLIN_E2E_SCENARIO=<scenario_name> ./scripts/kotlin_uniffi_e2e.sh
```

## CI Usage

Recommended CI shape:
- build Kotlin E2E artifacts once:

```sh
JNA_JAR=/usr/share/java/jna.jar ./scripts/ci/build_kotlin_e2e.sh
```

- upload:
  - `target/release/librgb_lightning_node.so`
  - `target/uniffi/kotlin-e2e/e2e.jar`
- fan out with a matrix over scenarios
- in each matrix job:
  - start regtest
  - run one scenario with:

```sh
RESET_DATA=1 KOTLIN_E2E_SCENARIO=<scenario_name> JNA_JAR=/usr/share/java/jna.jar ./scripts/ci/run_kotlin_e2e.sh
```

  - stop regtest with `if: always()`

## Cleanup

```sh
./regtest.sh stop
```
