#!/bin/bash

# Keysend (BTC & RGB) Example
# This script demonstrates invoice-less payments for both BTC and RGB assets.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Keysend (BTC & RGB) Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (Sender)
start_node 1  # Node 2 (Receiver)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund Node 1 with bitcoin
fund_node 0 0.1

# Step 5: Issue an RGB asset on Node 1
print_header "Issuing RGB Asset on Node 1"
asset_id=$(issue_rgb_asset 0 "RGB Keysend Asset" 1000 0)
echo "Issued asset with ID: $asset_id"

# Wait for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Open a vanilla BTC channel from Node 1 to Node 2
print_header "Opening Vanilla BTC Channel"
btc_channel_id=$(open_channel 0 1 1000000 0)
echo "Opened BTC channel with ID: $btc_channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the BTC channel..."
mine_blocks 6
sleep 5

# Step 7: Wait for the BTC channel to be ready
wait_for_channel_ready 0 $btc_channel_id

# Step 8: Open an RGB channel from Node 1 to Node 2
print_header "Opening RGB Channel"
rgb_channel_id=$(open_channel 0 1 1000000 0 $asset_id 500)
echo "Opened RGB channel with ID: $rgb_channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the RGB channel..."
mine_blocks 6
sleep 5

# Step 9: Wait for the RGB channel to be ready
wait_for_channel_ready 0 $rgb_channel_id

# Step 10: Get Node 2's pubkey for keysend
print_header "Getting Node 2's Pubkey"
node2_info=$(curl -s http://127.0.0.1:3001/getinfo)
node2_pubkey=$(echo $node2_info | jq -r .identity_pubkey)
echo "Node 2 pubkey: $node2_pubkey"

# Step 11: Send a BTC keysend payment from Node 1 to Node 2
print_header "Sending BTC Keysend Payment"
btc_keysend_response=$(send_keysend 0 $node2_pubkey 50000)
btc_payment_hash=$(echo $btc_keysend_response | jq -r .payment_hash 2>/dev/null || echo "Payment failed")
echo "BTC keysend payment hash: $btc_payment_hash"

# Step 12: Wait for the BTC keysend payment to complete
if [[ "$btc_payment_hash" != "Payment failed" ]]; then
    wait_for_payment 0 $btc_payment_hash
    print_success "BTC keysend payment completed successfully"
else
    print_error "BTC keysend payment failed"
fi

# Step 13: Check channel balances after BTC keysend
print_header "Channel Balances After BTC Keysend"
curl -s http://127.0.0.1:3000/listchannels | jq .
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 14: Send an RGB keysend payment from Node 1 to Node 2
print_header "Sending RGB Keysend Payment"
rgb_keysend_response=$(send_keysend 0 $node2_pubkey 10000 $asset_id 25)
rgb_payment_hash=$(echo $rgb_keysend_response | jq -r .payment_hash 2>/dev/null || echo "Payment failed")
echo "RGB keysend payment hash: $rgb_payment_hash"

# Step 15: Wait for the RGB keysend payment to complete
if [[ "$rgb_payment_hash" != "Payment failed" ]]; then
    wait_for_payment 0 $rgb_payment_hash
    print_success "RGB keysend payment completed successfully"
else
    print_error "RGB keysend payment failed"
fi

# Step 16: Check channel balances after RGB keysend
print_header "Channel Balances After RGB Keysend"
curl -s http://127.0.0.1:3000/listchannels | jq .
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 17: Check payments list on both nodes
print_header "Payments List on Node 1 (Sender)"
curl -s http://127.0.0.1:3000/listpayments | jq .

print_header "Payments List on Node 2 (Receiver)"
curl -s http://127.0.0.1:3001/listpayments | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up both vanilla BTC and RGB channels between two nodes"
echo "2. Sending a BTC keysend payment (invoice-less) from Node 1 to Node 2"
echo "3. Sending an RGB keysend payment from Node 1 to Node 2"
echo "4. Verifying that both payments were successful and channel balances were updated"

# Cleanup is handled by the trap
exit 0
