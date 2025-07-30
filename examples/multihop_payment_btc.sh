#!/bin/bash

# Multi-hop Payment (BTC) Example
# This script demonstrates routing a standard BTC payment through an intermediary node.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Multi-hop Payment (BTC) Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start three nodes
start_node 0  # Node 1 (Sender)
start_node 1  # Node 2 (Intermediary)
start_node 2  # Node 3 (Receiver)

# Step 3: Initialize and unlock all nodes
init_node 0
init_node 1
init_node 2
unlock_node 0
unlock_node 1
unlock_node 2

# Step 4: Fund Node 1 and Node 2 with bitcoin
fund_node 0 0.1
fund_node 1 0.1

# Step 5: Open a channel from Node 1 to Node 2
print_header "Opening Channel: Node 1 -> Node 2"
channel_id_1_2=$(open_channel 0 1 1000000 0)
echo "Opened channel with ID: $channel_id_1_2"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 6: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id_1_2

# Step 7: Open a channel from Node 2 to Node 3
print_header "Opening Channel: Node 2 -> Node 3"
channel_id_2_3=$(open_channel 1 2 1000000 0)
echo "Opened channel with ID: $channel_id_2_3"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 8: Wait for the channel to be ready
wait_for_channel_ready 1 $channel_id_2_3

# Step 9: Check channel status on all nodes
print_header "Channel Status on Node 1"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Status on Node 2"
curl -s http://127.0.0.1:3001/listchannels | jq .

print_header "Channel Status on Node 3"
curl -s http://127.0.0.1:3002/listchannels | jq .

# Step 10: Node 3 creates a standard BTC invoice for 50,000 msats
print_header "Creating BTC Invoice on Node 3"
invoice_response=$(create_invoice 2 50000)
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice: $payment_request"

# Step 11: Node 1 pays the invoice (routing through Node 2)
print_header "Node 1 Paying the Invoice (routing through Node 2)"
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

print_header "Channel Status on Node 3 After Payment"
curl -s http://127.0.0.1:3002/listchannels | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up a three-node network with channels: Node 1 -> Node 2 -> Node 3"
echo "2. Node 3 creating a BTC invoice for 50,000 msats"
echo "3. Node 1 paying the invoice, routing through Node 2"
echo "4. Verifying that the payment was successful and channel balances were updated"
echo "5. Node 1's balance decreased, Node 3's increased, and Node 2 earned a small routing fee"

# Cleanup is handled by the trap
exit 0
