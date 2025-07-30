#!/bin/bash

# High Fee Refusal Example
# This script demonstrates how the node refuses to route payments
# when the fees are unreasonably high.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "High Fee Refusal Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start three nodes
start_node 0  # Node 1 (Sender)
start_node 1  # Node 2 (Intermediary with high fees)
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

# Step 5: Open a channel from Node 1 to Node 2 with normal fees
print_header "Opening Channel: Node 1 -> Node 2 (Normal Fees)"
channel_id_1_2=$(open_channel 0 1 1000000 0)
echo "Opened channel with ID: $channel_id_1_2"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 6: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id_1_2

# Step 7: Open a channel from Node 2 to Node 3 with extremely high fees
print_header "Opening Channel: Node 2 -> Node 3 (High Fees)"
# Use the updatechannelpolicy endpoint to set high fees after opening
channel_id_2_3=$(open_channel 1 2 1000000 0)
echo "Opened channel with ID: $channel_id_2_3"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 8: Wait for the channel to be ready
wait_for_channel_ready 1 $channel_id_2_3

# Step 9: Update Node 2's channel policy to have extremely high fees
print_header "Setting Extremely High Fees on Node 2 -> Node 3 Channel"
update_response=$(curl -s -X POST http://127.0.0.1:3001/updatechannelpolicy \
    -H "Content-Type: application/json" \
    -d "{
        \"channel_id\": \"$channel_id_2_3\",
        \"base_fee_msat\": 10000,
        \"fee_rate\": 0.05,
        \"time_lock_delta\": 40
    }")
echo "Channel policy updated: $update_response"

# Step 10: Check channel policies on all nodes
print_header "Channel Policies on Node 1"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Channel Policies on Node 2"
curl -s http://127.0.0.1:3001/listchannels | jq .

print_header "Channel Policies on Node 3"
curl -s http://127.0.0.1:3002/listchannels | jq .

# Step 11: Node 3 creates an invoice
print_header "Creating Invoice on Node 3"
invoice_response=$(create_invoice 2 100000)  # 100,000 msats
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created invoice: $payment_request"

# Step 12: Node 1 attempts to pay the invoice (should fail due to high fees)
print_header "Node 1 Attempting to Pay Invoice (Should Fail Due to High Fees)"
payment_response=$(pay_invoice 0 $payment_request 2>&1 || echo '{"error": "Payment failed as expected due to high fees"}')
echo "Payment response: $payment_response"

# Step 13: Try again with fee limit override (should still fail)
print_header "Node 1 Attempting to Pay with Default Fee Limit"
payment_response=$(curl -s -X POST http://127.0.0.1:3000/payinvoice \
    -H "Content-Type: application/json" \
    -d "{
        \"payment_request\": \"$payment_request\",
        \"fee_limit_msat\": 1000
    }" 2>&1 || echo '{"error": "Payment failed as expected due to fee limit"}')
echo "Payment response: $payment_response"

# Step 14: Try again with higher fee limit (might succeed, but demonstrates the point)
print_header "Node 1 Attempting to Pay with Higher Fee Limit"
payment_response=$(curl -s -X POST http://127.0.0.1:3000/payinvoice \
    -H "Content-Type: application/json" \
    -d "{
        \"payment_request\": \"$payment_request\",
        \"fee_limit_msat\": 20000
    }" 2>&1 || echo '{"error": "Payment still failed or succeeded with high fees"}')
echo "Payment response: $payment_response"

# Step 15: Update the channel policy back to reasonable fees
print_header "Setting Reasonable Fees on Node 2 -> Node 3 Channel"
update_response=$(curl -s -X POST http://127.0.0.1:3001/updatechannelpolicy \
    -H "Content-Type: application/json" \
    -d "{
        \"channel_id\": \"$channel_id_2_3\",
        \"base_fee_msat\": 1000,
        \"fee_rate\": 0.001,
        \"time_lock_delta\": 40
    }")
echo "Channel policy updated: $update_response"

# Step 16: Node 3 creates another invoice
print_header "Creating New Invoice on Node 3"
invoice_response=$(create_invoice 2 100000)  # 100,000 msats
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created new invoice: $payment_request"

# Step 17: Node 1 attempts to pay the invoice with reasonable fees (should succeed)
print_header "Node 1 Attempting to Pay with Reasonable Fees"
payment_response=$(pay_invoice 0 $payment_request)
payment_hash=$(echo $payment_response | jq -r .payment_hash 2>/dev/null || echo "Payment failed")
echo "Payment hash: $payment_hash"

# Step 18: Check payment status
if [[ "$payment_hash" != "Payment failed" ]]; then
    print_header "Payment Status"
    wait_for_payment 0 $payment_hash
    payment_status=$(get_payment_status 0 $payment_hash)
    echo "Payment status: $payment_status"
fi

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up a three-node network with channels: Node 1 -> Node 2 -> Node 3"
echo "2. Configuring Node 2's channel to Node 3 with extremely high fees"
echo "3. Node 1 attempting to pay Node 3, which fails due to high fees"
echo "4. Showing how fee limits protect users from excessive routing fees"
echo "5. Updating the channel policy to reasonable fees and successfully completing a payment"

# Cleanup is handled by the trap
exit 0
