#!/bin/bash

# Multi-hop Payment (RGB) Example
# This script demonstrates routing an RGB asset payment through an intermediary node.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Multi-hop Payment (RGB) Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start three nodes
start_node 0  # Node 1 (Sender/Issuer)
start_node 1  # Node 2 (Intermediary)
start_node 2  # Node 3 (Receiver)

# Step 3: Initialize and unlock all nodes
init_node 0
init_node 1
init_node 2
unlock_node 0
unlock_node 1
unlock_node 2

# Step 4: Fund all nodes with bitcoin
fund_node 0 0.1
fund_node 1 0.1
fund_node 2 0.1

# Step 5: Issue an RGB asset on Node 1
print_header "Issuing RGB Asset on Node 1"
asset_id=$(issue_rgb_asset 0 "RGB Multihop Asset" 1000 0)
echo "Issued asset with ID: $asset_id"

# Wait for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Check the asset balance on Node 1
print_header "Asset Balance on Node 1"
list_assets 0

# Step 7: Send some of the asset on-chain from Node 1 to Node 2
print_header "Sending Asset On-chain: Node 1 -> Node 2"
# Create RGB invoice on Node 2
rgb_invoice_response=$(create_rgb_invoice 1 $asset_id 300)
rgb_invoice=$(echo $rgb_invoice_response | jq -r .invoice)
echo "RGB invoice: $rgb_invoice"

# Send asset from Node 1 to Node 2
send_response=$(send_rgb_asset 0 $rgb_invoice)
echo "Asset sent: $send_response"

# Mine blocks to confirm the transfer
print_info "Mining blocks to confirm the transfer..."
mine_blocks 6
sleep 5

# Step 8: Check asset balances after on-chain transfer
print_header "Asset Balance on Node 1 After On-chain Transfer"
list_assets 0

print_header "Asset Balance on Node 2 After On-chain Transfer"
list_assets 1

# Step 9: Open an RGB channel from Node 1 to Node 2
print_header "Opening RGB Channel: Node 1 -> Node 2"
channel_id_1_2=$(open_channel 0 1 1000000 0 $asset_id 200)
echo "Opened RGB channel with ID: $channel_id_1_2"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 10: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id_1_2

# Step 11: Open an RGB channel from Node 2 to Node 3
print_header "Opening RGB Channel: Node 2 -> Node 3"
channel_id_2_3=$(open_channel 1 2 1000000 0 $asset_id 100)
echo "Opened RGB channel with ID: $channel_id_2_3"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 12: Wait for the channel to be ready
wait_for_channel_ready 1 $channel_id_2_3

# Step 13: Check channel status on all nodes
print_header "Channel Status on Node 1"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2"
curl -s http://127.0.0.1:3001/listchannels | jq .

print_header "Channel Status on Node 3"
curl -s http://127.0.0.1:3002/listchannels | jq .

# Step 14: Node 3 creates an RGB invoice for 50 units
print_header "Creating RGB Invoice on Node 3"
invoice_response=$(create_invoice 2 10000 $asset_id 50)
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created RGB invoice: $payment_request"

# Step 15: Node 1 pays the RGB invoice (routing through Node 2)
print_header "Node 1 Paying the RGB Invoice (routing through Node 2)"
payment_response=$(pay_invoice 0 $payment_request)
payment_hash=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash: $payment_hash"

# Step 16: Wait for the payment to complete
wait_for_payment 0 $payment_hash

# Step 17: Check channel status after payment
print_header "Channel Status on Node 1 After Payment"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 After Payment"
curl -s http://127.0.0.1:3001/listchannels | jq .

print_header "Channel Status on Node 3 After Payment"
curl -s http://127.0.0.1:3002/listchannels | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Issuing an RGB asset on Node 1"
echo "2. Sending some of the asset on-chain to Node 2"
echo "3. Setting up RGB channels: Node 1 -> Node 2 -> Node 3"
echo "4. Node 3 creating an RGB invoice for 50 units"
echo "5. Node 1 paying the invoice, routing through Node 2"
echo "6. Verifying that the payment was successful and RGB asset balances were updated across all nodes"

# Cleanup is handled by the trap
exit 0
