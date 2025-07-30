# RGB Lightning Node - Example Scenarios

This directory contains executable shell scripts that demonstrate various use cases and workflows for the RGB Lightning Node (RLN). These examples are designed to be run in a local `regtest` environment and serve as live documentation for the API.

## Prerequisites

Before running any examples, ensure you have the following installed:
1.  **Docker & Docker Compose**: For running the Bitcoin and Electrs backend services.
2.  **jq**: For parsing JSON output in the scripts.
3.  **The `rgb-lightning-node` binary**: Compile the project and make sure the binary is in your `PATH` or the project's root directory.
    ```sh
    cargo install --locked --path .
    ```

## Running the Examples

Each script is self-contained and manages the full lifecycle of the required services (start, stop, and cleanup).

To run an example, simply execute the script from the project's root directory:
```sh
./examples/script_name.sh
```

All scripts include automatic cleanup, so if you interrupt a script (e.g., with `Ctrl+C`), it will attempt to shut down all running nodes and Docker containers.

---

## Available Scenarios

### 1. Simple RGB Channel Workflow

**File:** `simple_rgb_channel.sh`

This scenario demonstrates the fundamental RGB-on-Lightning workflow. It covers issuing an asset, opening a channel with that asset, making a payment, and closing the channel to settle the balance on-chain.

**To Run:**
```sh
./examples/simple_rgb_channel.sh
```

**Workflow Steps:**
1.  **Setup**: Starts the `bitcoind`, `electrs`, and `proxy` services. Starts two RLN daemons (`Node 1` and `Node 2`).
2.  **Initialize & Unlock**: Initializes and unlocks both nodes with a default password.
3.  **Fund & Issue**: Funds `Node 1` with regtest bitcoin and uses it to issue a new RGB NIA (fungible) asset.
4.  **Open Channel**: `Node 1` opens a new Lightning channel to `Node 2`, dedicating 600 units of the newly issued asset to it.
5.  **Send Payment**: `Node 2` creates a Lightning invoice for 100 units of the RGB asset. `Node 1` pays this invoice.
6.  **Close Channel**: The channel is closed cooperatively.
7.  **Verify**: The final on-chain balances are checked to confirm that `Node 1` has 900 units and `Node 2` has 100 units of the asset.
8.  **Cleanup**: All node processes and Docker containers are stopped and data is cleaned up.

### 2. Atomic Swap: BTC for RGB Asset

**File:** `swap_btc_for_rgb.sh`

This scenario demonstrates the atomic swap functionality. `Node 1` (the Maker) creates an offer to sell an RGB asset in exchange for Bitcoin (satoshis). `Node 2` (the Taker) accepts and executes the swap trustlessly over Lightning.

**To Run:**
```sh
./examples/swap_btc_for_rgb.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, and funds both nodes.
3.  **Issue Asset & Provide Liquidity**: `Node 1` issues an RGB asset. To facilitate the swap, two channels are opened:
    *   `Node 1` -> `Node 2`: An RGB channel to provide the asset liquidity.
    *   `Node 2` -> `Node 1`: A standard Bitcoin channel to provide the satoshi liquidity.
4.  **Maker Initiates Swap**: `Node 1` calls the `/makerinit` API to create a swap offer (e.g., "sell 10 RGB units for 50,000 msats"). This returns a `swapstring`.
5.  **Taker Accepts Swap**: `Node 2` calls the `/taker` API with the `swapstring` to accept the offer and "whitelist" the corresponding payment hash.
6.  **Maker Executes Swap**: `Node 1` calls `/makerexecute` to begin the multi-hop HTLC payment that executes the swap atomically.
7.  **Verify**: The script polls the swap status on both nodes until it shows "Succeeded" and checks that the LN channel balances have been updated correctly.
8.  **Cleanup**: All services are stopped.

### 3. Vanilla Channel Workflow

**File:** `vanilla_channel.sh`

This scenario demonstrates the fundamental Lightning use case without any RGB assets. It covers opening a standard BTC channel, making a BTC payment, and closing the channel.

**To Run:**
```sh
./examples/vanilla_channel.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, and funds both nodes.
3.  **Open Channel**: `Node 1` opens a standard BTC channel to `Node 2`.
4.  **Send Payment**: `Node 2` creates a Lightning invoice for 50,000 msats. `Node 1` pays this invoice.
5.  **Close Channel**: The channel is closed cooperatively.
6.  **Cleanup**: All services are stopped.

### 4. Force Close Channel

**File:** `force_close_channel.sh`

This scenario demonstrates how to handle a channel close when the counterparty is offline, showing the force-close mechanism and CSV delay.

**To Run:**
```sh
./examples/force_close_channel.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, and funds both nodes.
3.  **Open Channel**: `Node 1` opens a channel to `Node 2`.
4.  **Simulate Peer Offline**: Stop `Node 2`'s process.
5.  **Force Close**: `Node 1` initiates a force-close by calling `/closechannel` with `force: true`.
6.  **Wait for CSV Delay**: Mine 144 blocks to wait out the CSV delay.
7.  **Verify**: Check that `Node 1`'s on-chain balance reflects the swept funds.
8.  **Cleanup**: All services are stopped.

### 5. Multi-hop Payment (BTC)

**File:** `multihop_payment_btc.sh`

This scenario demonstrates routing a standard BTC payment through an intermediary node.

**To Run:**
```sh
./examples/multihop_payment_btc.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and three RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, and funds all three nodes.
3.  **Open Channels**: `Node 1` opens a channel to `Node 2`, and `Node 2` opens a channel to `Node 3`.
4.  **Send Payment**: `Node 3` creates a standard BTC invoice. `Node 1` pays the invoice, routing through `Node 2`.
5.  **Verify**: Check that balances have been updated correctly across all three nodes.
6.  **Cleanup**: All services are stopped.

### 6. Multi-hop Payment (RGB)

**File:** `multihop_payment_rgb.sh`

This scenario demonstrates routing an RGB asset payment through an intermediary node.

**To Run:**
```sh
./examples/multihop_payment_rgb.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and three RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, and funds all three nodes.
3.  **Issue Asset**: `Node 1` issues an RGB asset.
4.  **Provide Liquidity**: `Node 1` sends some of the new asset on-chain to `Node 2`.
5.  **Open Channels**: `Node 1` opens an RGB channel to `Node 2`, and `Node 2` opens an RGB channel to `Node 3`.
6.  **Send Payment**: `Node 3` creates an RGB invoice. `Node 1` pays the invoice, routing through `Node 2`.
7.  **Verify**: Check that RGB asset balances have been updated correctly across all three nodes.
8.  **Cleanup**: All services are stopped.

### 7. Full Asset Lifecycle (UDA with Media)

**File:** `asset_lifecycle.sh`

This scenario shows the complete process for a collectible asset: creating media, issuing the asset with it, sending it on-chain, and having the recipient retrieve the media.

**To Run:**
```sh
./examples/asset_lifecycle.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, and funds `Node 1`.
3.  **Upload Media**: `Node 1` uploads media content and receives a digest.
4.  **Issue UDA**: `Node 1` issues a UDA (collectible) asset referencing the media digest.
5.  **Transfer Asset**: `Node 2` generates a blinded UTXO. `Node 1` sends the UDA to `Node 2`.
6.  **Verify**: `Node 2` retrieves the media content using the digest from its new asset.
7.  **Cleanup**: All services are stopped.

### 8. Backup and Restore

**File:** `backup_restore.sh`

This scenario verifies that the backup and restore functionality correctly preserves the node's entire state, including keys, assets, and channels.

**To Run:**
```sh
./examples/backup_restore.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Initialize & Fund**: Initializes, unlocks, funds `Node 1`, and issues an asset.
3.  **Open Channel**: Open a channel between `Node 1` and `Node 2`.
4.  **Create Backup**: Lock `Node 1` and create a backup file.
5.  **Wipe State**: Stop `Node 1` and remove its data directory.
6.  **Restore**: Start a new empty daemon for `Node 1` and restore from the backup.
7.  **Verify**: Check that the node's pubkey, channel state, and asset balances match the original.
8.  **Cleanup**: All services are stopped.

### 9. Swap RGB for BTC (Sell Offer)

**File:** `swap_rgb_for_btc.sh`

This scenario demonstrates the inverse of the BTC-for-RGB swap, where a maker wants to sell an RGB asset for satoshis.

**To Run:**
```sh
./examples/swap_rgb_for_btc.sh
```

**Workflow Steps:**
1.  **Setup**: Similar to `swap_btc_for_rgb.sh` but with the swap direction reversed.
2.  **Maker Initiates Swap**: `Node 1` calls `/makerinit` with `from_asset` as the RGB asset ID and `to_asset` as `null` (BTC).
3.  **Taker Accepts**: `Node 2` accepts the swap.
4.  **Maker Executes**: `Node 1` executes the swap.
5.  **Verify**: Check that `Node 1`'s BTC balance has increased and its RGB balance has decreased.
6.  **Cleanup**: All services are stopped.

### 10. Swap RGB-A for RGB-B

**File:** `swap_rgb_for_rgb.sh`

This scenario demonstrates a swap between two different RGB assets.

**To Run:**
```sh
./examples/swap_rgb_for_rgb.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Issue Assets**: `Node 1` issues "Asset A" and `Node 2` issues "Asset B".
3.  **Open Channels**: Each node opens a channel to the other with their respective assets.
4.  **Execute Swap**: `Node 1` initiates a swap of Asset A for Asset B, `Node 2` accepts, and `Node 1` executes.
5.  **Verify**: Check that both nodes now have balances of both assets.
6.  **Cleanup**: All services are stopped.

### 11. Multi-hop Swap

**File:** `multihop_swap.sh`

This scenario executes a swap between two nodes that are not directly connected, requiring routing through an intermediary.

**To Run:**
```sh
./examples/multihop_swap.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and three RLN daemons.
2.  **Issue Asset**: `Taker` issues "Asset B".
3.  **Open Channels**: Create a network of channels for both BTC and RGB assets.
4.  **Execute Swap**: `Maker` initiates a swap of BTC for Asset B, `Taker` accepts, and `Maker` executes.
5.  **Verify**: Check that balances have been updated correctly across all nodes.
6.  **Cleanup**: All services are stopped.

### 12. Swap Timeout

**File:** `swap_timeout.sh`

This scenario shows that a swap correctly expires if it's not acted upon in time.

**To Run:**
```sh
./examples/swap_timeout.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Initialize Swap**: `Maker` initiates a swap with a very short timeout (5 seconds).
3.  **Wait**: Wait for the timeout to expire.
4.  **Verify**: `Taker` attempts to accept the expired swap and receives an error.
5.  **Cleanup**: All services are stopped.

### 13. Insufficient Funds/Assets

**File:** `insufficient_funds.sh`

This scenario demonstrates predictable API failures when conditions are not met.

**To Run:**
```sh
./examples/insufficient_funds.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Issue Asset**: `Node 1` issues a limited amount of an RGB asset.
3.  **Test Cases**: Attempt operations that should fail due to insufficient funds or assets.
4.  **Verify**: Confirm that appropriate error messages are returned.
5.  **Cleanup**: All services are stopped.

### 14. High Fee Refusal

**File:** `high_fee_refusal.sh`

This scenario demonstrates a payment failing due to routing fees being too high.

**To Run:**
```sh
./examples/high_fee_refusal.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and three RLN daemons.
2.  **Open Channels**: `Node 1` opens a channel to `Node 2`, and `Node 2` opens a channel to `Node 3` with very high fees.
3.  **Attempt Payment**: `Node 3` creates an invoice, and `Node 1` attempts to pay it.
4.  **Verify**: Confirm that the payment fails due to high fees.
5.  **Cleanup**: All services are stopped.

### 15. Keysend (BTC & RGB)

**File:** `keysend.sh`

This scenario demonstrates invoice-less payments for both BTC and RGB assets.

**To Run:**
```sh
./examples/keysend.sh
```

**Workflow Steps:**
1.  **Setup**: Starts services and two RLN daemons.
2.  **Open Channels**: Open both a vanilla and an RGB channel between the nodes.
3.  **BTC Keysend**: `Node 1` sends a BTC keysend payment to `Node 2`.
4.  **RGB Keysend**: `Node 1` sends an RGB keysend payment to `Node 2`.
5.  **Verify**: Check that both payments succeeded.
6.  **Cleanup**: All services are stopped.
