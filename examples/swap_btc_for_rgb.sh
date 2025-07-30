#!/bin/bash

# Atomic Swap: BTC for RGB Asset Example
# This script demonstrates the atomic swap functionality:
# - Node 1 (Maker) creates an offer to sell RGB asset in exchange for Bitcoin
# - Node 2 (Taker) accepts and executes the swap trustlessly over Lightning

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Atomic Swap: BTC for RGB Asset Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (Maker)
start_node 1  # Node 2 (Taker)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund both nodes with bitcoin
fund_node 0 0.1
fund_node 1 0.1

# Step 5: Issue a new RGB asset on Node 1 (Maker)
print_header "Issuing RGB Asset"
asset_id=$(issue_rgb_asset 0 "RGB Swap Asset" 1000 0)
echo "Issued asset with ID: $asset_id"

# Wait a moment for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Check the asset balance on Node 1
print_header "Asset Balance on Node 1 (Maker)"
list_assets 0

# Step 7: Open an RGB channel from Node 1 (Maker) to Node 2 (Taker)
print_header "Opening RGB Channel (Maker -> Taker)"
rgb_channel_id=$(open_channel 0 1 1000000 0 $asset_id 500)
echo "Opened RGB channel with ID: $rgb_channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the RGB channel..."
mine_blocks 6
sleep 5

# Step 8: Wait for the RGB channel to be ready
wait_for_channel_ready 0 $rgb_channel_id

# Step 9: Open a standard BTC channel from Node 2 (Taker) to Node 1 (Maker)
print_header "Opening BTC Channel (Taker -> Maker)"
btc_channel_id=$(open_channel 1 0 1000000 0)
echo "Opened BTC channel with ID: $btc_channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the BTC channel..."
mine_blocks 6
sleep 5

# Step 10: Wait for the BTC channel to be ready
wait_for_channel_ready 1 $btc_channel_id

# Step 11: Check channel status on both nodes
print_header "Channel Status on Node 1 (Maker)"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 (Taker)"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 12: Maker initiates the swap (sell 10 RGB units for 50,000 msats)
print_header "Maker Initiating Swap"
swap_response=$(maker_init_swap 0 $asset_id "null" 10 50000 600)
swapstring=$(echo $swap_response | jq -r .swapstring)
echo "Swap initiated with swapstring: $swapstring"

# Step 13: Taker accepts the swap
print_header "Taker Accepting Swap"
taker_response=$(taker_accept_swap 1 $swapstring)
echo "Swap accepted: $taker_response"

# Step 14: Maker executes the swap
print_header "Maker Executing Swap"
execute_response=$(maker_execute_swap 0 $swapstring)
echo "Swap execution initiated: $execute_response"

# Step 15: Wait for the swap to complete
print_header "Waiting for Swap to Complete"
wait_for_swap 0 $swapstring

# Step 16: Check swap status on both nodes
print_header "Swap Status on Maker"
get_swap_status 0 $swapstring

print_header "Swap Status on Taker"
get_swap_status 1 $swapstring

# Step 17: Check channel status after swap
print_header "Channel Status on Node 1 (Maker) After Swap"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 (Taker) After Swap"
curl -s http://127.0.0.1:3001/listchannels | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up two nodes with bidirectional channels (RGB and BTC)"
echo "2. Maker (Node 1) initiating a swap to sell 10 RGB units for 50,000 msats"
echo "3. Taker (Node 2) accepting the swap"
echo "4. Maker executing the swap"
echo "5. Verifying the swap completed successfully and channel balances updated"

# Cleanup is handled by the trap
exit 0
