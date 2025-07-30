#!/bin/bash

# Vanilla Channel Workflow Example
# This script demonstrates the fundamental Lightning use case without RGB assets:
# - Opening a standard BTC channel
# - Making a BTC payment
# - Closing the channel

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Vanilla Channel Workflow Example"

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

# Step 5: Open a standard BTC channel from Node 1 to Node 2
print_header "Opening BTC Channel"
channel_id=$(open_channel 0 1 1000000 0)
echo "Opened channel with ID: $channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 6: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id

# Step 7: Check channel status on both nodes
print_header "Channel Status on Node 1"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 8: Node 2 creates a standard BTC invoice for 50,000 msats
print_header "Creating BTC Invoice"
invoice_response=$(create_invoice 1 50000)
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice: $payment_request"

# Step 9: Node 1 pays the invoice
print_header "Paying the Invoice"
payment_response=$(pay_invoice 0 $payment_request)
payment_hash=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash: $payment_hash"

# Step 10: Wait for the payment to complete
wait_for_payment 0 $payment_hash

# Step 11: Check channel status after payment
print_header "Channel Status on Node 1 After Payment"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2 After Payment"
curl -s http://127.0.0.1:3001/listchannels | jq .

# Step 12: Close the channel cooperatively
print_header "Closing the Channel"
close_response=$(close_channel 0 $channel_id false)
echo "Channel close initiated: $close_response"

# Mine blocks to confirm the channel close
print_info "Mining blocks to confirm the channel close..."
mine_blocks 6
sleep 5

# Step 13: Check final BTC balances
print_header "Final BTC Balance on Node 1"
curl -s http://127.0.0.1:3000/btcbalance | jq .

print_header "Final BTC Balance on Node 2"
curl -s http://127.0.0.1:3001/btcbalance | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Opening a standard Lightning channel with 1,000,000 sats capacity"
echo "2. Making a payment of 50,000 msats from Node 1 to Node 2"
echo "3. Closing the channel and settling the balances on-chain"

# Cleanup is handled by the trap
exit 0
