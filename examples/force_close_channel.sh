#!/bin/bash

# Force Close Channel Example
# This script demonstrates how to handle a channel close when the counterparty is offline,
# showing the force-close mechanism and CSV delay.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Force Close Channel Example"

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

# Step 8: Simulate peer offline by stopping Node 2
print_header "Simulating Peer Offline (Stopping Node 2)"
stop_node 1
print_success "Node 2 stopped"

# Step 9: Force close the channel from Node 1
print_header "Force Closing the Channel"
close_response=$(close_channel 0 $channel_id true)
echo "Channel force close initiated: $close_response"

# Step 10: Mine blocks to wait out the CSV delay
print_header "Mining Blocks to Wait Out CSV Delay"
print_info "Mining 144 blocks to wait out the CSV delay..."
mine_blocks 144
sleep 5

# Step 11: Check Node 1's balance after force close
print_header "Node 1 BTC Balance After Force Close"
curl -s http://127.0.0.1:3000/btcbalance | jq .

# Step 12: Restart Node 2
print_header "Restarting Node 2"
start_node 1
unlock_node 1

# Step 13: Wait for Node 2 to detect the on-chain settlement
print_info "Waiting for Node 2 to detect the on-chain settlement..."
sleep 10

# Step 14: Check Node 2's balance
print_header "Node 2 BTC Balance After Force Close"
curl -s http://127.0.0.1:3001/btcbalance | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Opening a standard Lightning channel"
echo "2. Simulating a peer going offline"
echo "3. Force closing the channel"
echo "4. Mining blocks to wait out the CSV delay"
echo "5. Verifying that funds were swept back to the wallet"

# Cleanup is handled by the trap
exit 0
