#!/bin/bash

# Swap RGB-A for RGB-B Example
# This script demonstrates a swap between two different RGB assets.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Swap RGB-A for RGB-B Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (Maker, has Asset A)
start_node 1  # Node 2 (Taker, has Asset B)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund both nodes with bitcoin
fund_node 0 0.1
fund_node 1 0.1

# Step 5: Issue Asset A on Node 1 (Maker)
print_header "Issuing Asset A on Node 1 (Maker)"
asset_a_id=$(issue_rgb_asset 0 "RGB Asset A" 1000 0)
echo "Issued Asset A with ID: $asset_a_id"

# Wait for the asset to be confirmed
print_info "Waiting for Asset A to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Issue Asset B on Node 2 (Taker)
print_header "Issuing Asset B on Node 2 (Taker)"
asset_b_id=$(issue_rgb_asset 1 "RGB Asset B" 1000 0)
echo "Issued Asset B with ID: $asset_b_id"

# Wait for the asset to be confirmed
print_info "Waiting for Asset B to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 7: Check the asset balances on both nodes
print_header "Asset Balance on Node 1 (Maker)"
list_assets 0

print_header "Asset Balance on Node 2 (Taker)"
list_assets 1

# Step 8: Open an Asset A channel from Node 1 (Maker) to Node 2 (Taker)
print_header "Opening Asset A Channel (Maker -> Taker)"
channel_a_id=$(open_channel 0 1 1000000 0 $asset_a_id 500)
echo "Opened Asset A channel with ID: $channel_a_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the Asset A channel..."
mine_blocks 6
sleep 5

# Step 9: Wait for the Asset A channel to be ready
wait_for_channel_ready 0 $channel_a_id

# Step 10: Open an Asset B channel from Node 2 (Taker) to Node 1 (Maker)
print_header "Opening Asset B Channel (Taker -> Maker)"
channel_b_id=$(open_channel 1 0 1000000 0 $asset_b_id 500)
echo "Opened Asset B channel with ID: $channel_b_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the Asset B channel..."
mine_blocks 6
sleep 5

# Step 11: Wait for the Asset B channel to be ready
wait_for_channel_ready 1 $channel_b_id

# Step 12: Check channel status on both nodes
print_header "Channel Status on Node 1 (Maker)"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 (Taker)"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 13: Maker initiates the swap (swap 50 units of Asset A for 30 units of Asset B)
print_header "Maker Initiating Swap (Asset A -> Asset B)"
swap_response=$(maker_init_swap 0 $asset_a_id $asset_b_id 50 30 600)
swapstring=$(echo $swap_response | jq -r .swapstring)
echo "Swap initiated with swapstring: $swapstring"

# Step 14: Taker accepts the swap
print_header "Taker Accepting Swap"
taker_response=$(taker_accept_swap 1 $swapstring)
echo "Swap accepted: $taker_response"

# Step 15: Maker executes the swap
print_header "Maker Executing Swap"
execute_response=$(maker_execute_swap 0 $swapstring)
echo "Swap execution initiated: $execute_response"

# Step 16: Wait for the swap to complete
print_header "Waiting for Swap to Complete"
wait_for_swap 0 $swapstring

# Step 17: Check swap status on both nodes
print_header "Swap Status on Maker"
get_swap_status 0 $swapstring

print_header "Swap Status on Taker"
get_swap_status 1 $swapstring

# Step 18: Check channel status after swap
print_header "Channel Status on Node 1 (Maker) After Swap"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 (Taker) After Swap"
curl -s http://127.0.0.1:3001/listchannels | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up two nodes, each issuing their own RGB asset"
echo "2. Opening bidirectional RGB channels with each asset"
echo "3. Maker (Node 1) initiating a swap of 50 units of Asset A for 30 units of Asset B"
echo "4. Taker (Node 2) accepting the swap"
echo "5. Maker executing the swap"
echo "6. Verifying the swap completed successfully and channel balances updated for both assets"

# Cleanup is handled by the trap
exit 0
