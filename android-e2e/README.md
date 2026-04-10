# Android UniFFI E2E Harness

This project runs Android instrumented end-to-end tests against the public
`SdkNode` / UniFFI path.

Current scenarios:

1. `payment`
2. `multi_open_close`
3. `restart`
4. `concurrent_btc_payments`
5. `swap_roundtrip_buy`

## Prerequisites

Required tools:
- `cargo`
- `java`
- `adb`
- `docker`

Required environment:
- `ANDROID_NDK_HOME`

Start local regtest services:

```sh
cd /path/to/rgb-lightning-node
./regtest.sh start
```

Make sure an Android emulator is already running and visible in `adb devices`.
The runner does not start an emulator for you; it only checks that at least one
Android device is in `device` state. Offline entries in `adb devices` do not
block the run as long as there is at least one online device.

The Android test connects to local regtest services through `10.0.2.2`:
- bitcoind RPC: `10.0.2.2:18443`
- electrs: `10.0.2.2:50001`
- proxy: `10.0.2.2:3000`

Current Android CI uses the emulator `x86_64` ABI only.

## Run

Run via script:

```sh
cd /path/to/rgb-lightning-node
./scripts/android_uniffi_e2e.sh
```

This script:
- checks required commands and `ANDROID_NDK_HOME`
- checks that local regtest services are running
- checks that an Android emulator/device is visible in `adb devices`
- builds Android JNI libraries for `x86_64`
- generates Kotlin Android UniFFI bindings
- runs `connectedDebugAndroidTest`

Manual Gradle run from the Android project:

Before running Gradle directly, first prepare Android artifacts:

```sh
./scripts/ci/build_android_jni_x86_64.sh
./scripts/ci/uniffi_generate_kotlin_android.sh
```

```sh
cd android-e2e
./gradlew connectedDebugAndroidTest
```

## CI Usage

GitHub Actions runs Android e2e in two phases:

1. build Android UniFFI artifacts once:
```sh
./scripts/ci/uniffi_generate_kotlin_android.sh
./scripts/ci/build_android_jni_x86_64.sh
```
2. run instrumented tests as a matrix on an `x86_64` Android emulator:
```sh
./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=<test_class>
```

Current CI test classes:
- `org.rgblightningnode.PaymentTest`
- `org.rgblightningnode.RestartTest`
- `org.rgblightningnode.MultiOpenCloseTest`
- `org.rgblightningnode.SwapRoundtripBuyTest`
- `org.rgblightningnode.ConcurrentBtcPaymentsTest`

## Cleanup

```sh
./regtest.sh stop
```
