#!/bin/bash

# Multi-Asset Channel Example
# This script demonstrates how to manage a channel with multiple RGB assets.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Multi-Asset Channel Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (Issuer of multiple assets)
start_node 1  # Node 2 (Recipient)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund Node 1 with bitcoin
fund_node 0 0.1

# Step 5: Issue first RGB asset on Node 1
print_header "Issuing First RGB Asset (Token A)"
asset_a_id=$(issue_rgb_asset 0 "RGB Token A" 1000 0)
echo "Issued Token A with ID: $asset_a_id"

# Wait for the asset to be confirmed
print_info "Waiting for Token A to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Issue second RGB asset on Node 1
print_header "Issuing Second RGB Asset (Token B)"
asset_b_id=$(issue_rgb_asset 0 "RGB Token B" 2000 0)
echo "Issued Token B with ID: $asset_b_id"

# Wait for the asset to be confirmed
print_info "Waiting for Token B to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 7: Issue third RGB asset on Node 1
print_header "Issuing Third RGB Asset (Token C)"
asset_c_id=$(issue_rgb_asset 0 "RGB Token C" 3000 0)
echo "Issued Token C with ID: $asset_c_id"

# Wait for the asset to be confirmed
print_info "Waiting for Token C to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 8: Check the asset balances on Node 1
print_header "Asset Balances on Node 1"
list_assets 0

# Step 9: Open a channel from Node 1 to Node 2 with the first asset
print_header "Opening Channel with Token A"
channel_id=$(open_channel 0 1 1000000 0 $asset_a_id 200)
echo "Opened channel with ID: $channel_id with Token A"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 10: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id

# Step 11: Add the second asset to the existing channel
print_header "Adding Token B to the Channel"
add_asset_response=$(curl -s -X POST http://127.0.0.1:3000/addasset \
    -H "Content-Type: application/json" \
    -d "{
        \"channel_id\": \"$channel_id\",
        \"asset_id\": \"$asset_b_id\",
        \"amount\": 300
    }")
echo "Added Token B to channel: $add_asset_response"

# Mine blocks to confirm the asset addition
print_info "Mining blocks to confirm the asset addition..."
mine_blocks 6
sleep 5

# Step 12: Add the third asset to the existing channel
print_header "Adding Token C to the Channel"
add_asset_response=$(curl -s -X POST http://127.0.0.1:3000/addasset \
    -H "Content-Type: application/json" \
    -d "{
        \"channel_id\": \"$channel_id\",
        \"asset_id\": \"$asset_c_id\",
        \"amount\": 400
    }")
echo "Added Token C to channel: $add_asset_response"

# Mine blocks to confirm the asset addition
print_info "Mining blocks to confirm the asset addition..."
mine_blocks 6
sleep 5

# Step 13: Check channel status to see all assets
print_header "Channel Status with Multiple Assets"
curl -s http://127.0.0.1:3000/listchannels | jq .

# Step 14: Make a payment with the first asset
print_header "Making Payment with Token A"
invoice_response=$(create_invoice 1 10000 $asset_a_id 50)
payment_request_a=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice for Token A: $payment_request_a"

payment_response=$(pay_invoice 0 $payment_request_a)
payment_hash_a=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash for Token A: $payment_hash_a"

# Step 15: Make a payment with the second asset
print_header "Making Payment with Token B"
invoice_response=$(create_invoice 1 10000 $asset_b_id 75)
payment_request_b=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice for Token B: $payment_request_b"

payment_response=$(pay_invoice 0 $payment_request_b)
payment_hash_b=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash for Token B: $payment_hash_b"

# Step 16: Make a payment with the third asset
print_header "Making Payment with Token C"
invoice_response=$(create_invoice 1 10000 $asset_c_id 100)
payment_request_c=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice for Token C: $payment_request_c"

payment_response=$(pay_invoice 0 $payment_request_c)
payment_hash_c=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash for Token C: $payment_hash_c"

# Step 17: Check channel status after payments
print_header "Channel Status After Payments"
curl -s http://127.0.0.1:3000/listchannels | jq .
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 18: Close the multi-asset channel
print_header "Closing Multi-Asset Channel"
close_response=$(close_channel 0 $channel_id false)
echo "Channel close initiated: $close_response"

# Mine blocks to confirm the channel close
print_info "Mining blocks to confirm the channel close..."
mine_blocks 6
sleep 5

# Step 19: Check on-chain balances after channel close
print_header "On-Chain Asset Balances After Channel Close"
print_header "Node 1 Assets"
list_assets 0

print_header "Node 2 Assets"
list_assets 1

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Issuing multiple RGB assets (Token A, Token B, Token C)"
echo "2. Opening a channel with one asset (Token A)"
echo "3. Adding additional assets to the existing channel (Token B, Token C)"
echo "4. Making payments with each asset type"
echo "5. Closing the multi-asset channel"
echo "6. Verifying that all assets are correctly settled on-chain after channel close"

# Cleanup is handled by the trap
exit 0
