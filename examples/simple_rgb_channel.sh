#!/bin/bash

# Simple RGB Channel Workflow Example
# This script demonstrates the fundamental RGB-on-Lightning workflow:
# - Issuing an asset
# - Opening a channel with that asset
# - Making a payment
# - Closing the channel to settle the balance on-chain

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Simple RGB Channel Workflow Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1
start_node 1  # Node 2

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund Node 1 with bitcoin
fund_node 0 0.1

# Step 5: Issue a new RGB asset on Node 1
print_header "Issuing RGB Asset"
asset_id=$(issue_rgb_asset 0 "RGB Test Asset" 1000 0)
echo "Issued asset with ID: $asset_id"

# Wait a moment for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Check the asset balance on Node 1
print_header "Asset Balance on Node 1"
list_assets 0

# Step 7: Open an RGB channel from Node 1 to Node 2
print_header "Opening RGB Channel"
channel_id=$(open_channel 0 1 1000000 0 $asset_id 600)
echo "Opened channel with ID: $channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 8: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id

# Step 9: Check channel status on both nodes
print_header "Channel Status on Node 1"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 10: Node 2 creates an RGB invoice for 100 units
print_header "Creating RGB Invoice"
invoice_response=$(create_invoice 1 10000 $asset_id 100)
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice: $payment_request"

# Step 11: Node 1 pays the invoice
print_header "Paying the Invoice"
payment_response=$(pay_invoice 0 $payment_request)
payment_hash=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash: $payment_hash"

# Step 12: Wait for the payment to complete
wait_for_payment 0 $payment_hash

# Step 13: Check channel status after payment
print_header "Channel Status on Node 1 After Payment"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 After Payment"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 14: Close the channel cooperatively
print_header "Closing the Channel"
close_response=$(close_channel 0 $channel_id false)
echo "Channel close initiated: $close_response"

# Mine blocks to confirm the channel close
print_info "Mining blocks to confirm the channel close..."
mine_blocks 6
sleep 5

# Step 15: Check final asset balances
print_header "Final Asset Balance on Node 1"
list_assets 0

print_header "Final Asset Balance on Node 2"
list_assets 1

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Issuing an RGB asset (1000 units)"
echo "2. Opening a Lightning channel with 600 units of the RGB asset"
echo "3. Making a payment of 100 units from Node 1 to Node 2"
echo "4. Closing the channel and settling the balances on-chain"
echo "5. Final balances: Node 1 has 900 units, Node 2 has 100 units"

# Cleanup is handled by the trap
exit 0
