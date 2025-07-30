#!/bin/bash

# Failed Payment Example
# This script demonstrates how to handle and debug failed payments,
# showing various failure scenarios and how to interpret error messages.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Failed Payment Example"

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
asset_id=$(issue_rgb_asset 0 "RGB Test Asset" 1000 0)
echo "Issued asset with ID: $asset_id"

# Wait for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Open a small BTC channel from Node 1 to Node 2
print_header "Opening Small BTC Channel"
channel_id=$(open_channel 0 1 500000 0)  # Small capacity channel
echo "Opened channel with ID: $channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 7: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id

# Step 8: Check channel status
print_header "Channel Status on Node 1"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 9: Failure Scenario 1 - Payment amount exceeds channel capacity
print_header "Failure Scenario 1: Payment Amount Exceeds Channel Capacity"
# Node 2 creates a large BTC invoice
invoice_response=$(create_invoice 1 600000)  # More than channel capacity
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice for amount exceeding channel capacity: $payment_request"

# Node 1 attempts to pay the invoice
print_info "Attempting to pay invoice (should fail)..."
payment_response=$(pay_invoice 0 $payment_request 2>&1 || echo '{"error": "Payment failed as expected"}')
echo "Payment response: $payment_response"

# Step 10: Failure Scenario 2 - RGB payment without RGB channel
print_header "Failure Scenario 2: RGB Payment Without RGB Channel"
# Node 2 creates an RGB invoice
invoice_response=$(create_invoice 1 10000 $asset_id 10)
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created RGB invoice without RGB channel: $payment_request"

# Node 1 attempts to pay the RGB invoice
print_info "Attempting to pay RGB invoice without RGB channel (should fail)..."
payment_response=$(pay_invoice 0 $payment_request 2>&1 || echo '{"error": "Payment failed as expected"}')
echo "Payment response: $payment_response"

# Step 11: Failure Scenario 3 - Invalid payment request
print_header "Failure Scenario 3: Invalid Payment Request"
# Create an invalid payment request
invalid_request="lnbcrt1invalid0payment0request0000000000000000"

# Node 1 attempts to pay the invalid request
print_info "Attempting to pay invalid request (should fail)..."
payment_response=$(pay_invoice 0 $invalid_request 2>&1 || echo '{"error": "Payment failed as expected"}')
echo "Payment response: $payment_response"

# Step 12: Failure Scenario 4 - Expired invoice
print_header "Failure Scenario 4: Expired Invoice"
# Node 2 creates a short expiry invoice
invoice_response=$(curl -s -X POST http://127.0.0.1:3001/createinvoice \
    -H "Content-Type: application/json" \
    -d '{"amount_msat": 10000, "expiry": 5}')
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice with short expiry: $payment_request"

# Wait for the invoice to expire
print_info "Waiting for invoice to expire (5 seconds)..."
sleep 10

# Node 1 attempts to pay the expired invoice
print_info "Attempting to pay expired invoice (should fail)..."
payment_response=$(pay_invoice 0 $payment_request 2>&1 || echo '{"error": "Payment failed as expected"}')
echo "Payment response: $payment_response"

# Step 13: Failure Scenario 5 - Insufficient RGB balance
print_header "Failure Scenario 5: Insufficient RGB Balance"
# Open an RGB channel with small amount
rgb_channel_id=$(open_channel 0 1 1000000 0 $asset_id 10)
echo "Opened RGB channel with ID: $rgb_channel_id with only 10 RGB units"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the RGB channel..."
mine_blocks 6
sleep 5

# Wait for the channel to be ready
wait_for_channel_ready 0 $rgb_channel_id

# Node 2 creates an RGB invoice for more than available
invoice_response=$(create_invoice 1 10000 $asset_id 20)  # More than available
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created RGB invoice for more than available balance: $payment_request"

# Node 1 attempts to pay the invoice
print_info "Attempting to pay RGB invoice with insufficient balance (should fail)..."
payment_response=$(pay_invoice 0 $payment_request 2>&1 || echo '{"error": "Payment failed as expected"}')
echo "Payment response: $payment_response"

print_header "Example Completed Successfully"
echo "This example demonstrated various payment failure scenarios:"
echo "1. Payment amount exceeding channel capacity"
echo "2. RGB payment without an RGB channel"
echo "3. Invalid payment request format"
echo "4. Expired invoice"
echo "5. Insufficient RGB balance for payment"
echo "Each scenario showed appropriate error handling and diagnostic information."

# Cleanup is handled by the trap
exit 0
