#!/bin/bash

# Onion Messaging Example
# This script demonstrates how to send and receive private messages over the Lightning Network
# using onion routing for enhanced privacy.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Onion Messaging Example"

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

# Step 4: Fund all nodes with bitcoin
fund_node 0 0.1
fund_node 1 0.1
fund_node 2 0.1

# Step 5: Open channels to establish connectivity
print_header "Opening Channels for Network Connectivity"
channel_id_1_2=$(open_channel 0 1 1000000 0)
echo "Opened channel 1->2 with ID: $channel_id_1_2"

channel_id_2_3=$(open_channel 1 2 1000000 0)
echo "Opened channel 2->3 with ID: $channel_id_2_3"

# Mine blocks to confirm the channels
print_info "Mining blocks to confirm the channels..."
mine_blocks 6
sleep 5

# Step 6: Wait for the channels to be ready
wait_for_channel_ready 0 $channel_id_1_2
wait_for_channel_ready 1 $channel_id_2_3

# Step 7: Get pubkeys for all nodes
print_header "Getting Node Pubkeys"
node1_info=$(curl -s http://127.0.0.1:3000/getinfo)
node1_pubkey=$(echo $node1_info | jq -r .identity_pubkey)
echo "Node 1 pubkey: $node1_pubkey"

node2_info=$(curl -s http://127.0.0.1:3001/getinfo)
node2_pubkey=$(echo $node2_info | jq -r .identity_pubkey)
echo "Node 2 pubkey: $node2_pubkey"

node3_info=$(curl -s http://127.0.0.1:3002/getinfo)
node3_pubkey=$(echo $node3_info | jq -r .identity_pubkey)
echo "Node 3 pubkey: $node3_pubkey"

# Step 8: Setup message listeners on all nodes
print_header "Setting Up Message Listeners"
# In a real scenario, you would have these running in separate terminals
# For this example, we'll just demonstrate the API calls

# Node 1 subscribes to messages
print_info "Node 1 subscribing to messages..."
curl -s -N -X GET http://127.0.0.1:3000/subscribemessages > /dev/null 2>&1 &
node1_listener_pid=$!
echo "Node 1 listener started with PID: $node1_listener_pid"

# Node 2 subscribes to messages
print_info "Node 2 subscribing to messages..."
curl -s -N -X GET http://127.0.0.1:3001/subscribemessages > /dev/null 2>&1 &
node2_listener_pid=$!
echo "Node 2 listener started with PID: $node2_listener_pid"

# Node 3 subscribes to messages
print_info "Node 3 subscribing to messages..."
curl -s -N -X GET http://127.0.0.1:3002/subscribemessages > /dev/null 2>&1 &
node3_listener_pid=$!
echo "Node 3 listener started with PID: $node3_listener_pid"

# Give the listeners time to start
sleep 2

# Step 9: Send a direct message from Node 1 to Node 2
print_header "Sending Direct Message: Node 1 -> Node 2"
direct_message="Hello Node 2, this is a direct message from Node 1!"
send_onion_message 0 $node2_pubkey "$direct_message"
print_success "Direct message sent to Node 2"

# Step 10: Send a multi-hop message from Node 1 to Node 3 through Node 2
print_header "Sending Multi-hop Message: Node 1 -> Node 3 (through Node 2)"
multihop_message="Hello Node 3, this is a private message from Node 1 routed through Node 2!"

# Create the route for the multi-hop message
route="[{\"pubkey\": \"$node2_pubkey\"}, {\"pubkey\": \"$node3_pubkey\"}]"

# Send the multi-hop message
curl -s -X POST http://127.0.0.1:3000/sendmessage \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"$multihop_message\",
        \"route\": $route
    }"
print_success "Multi-hop message sent to Node 3 through Node 2"

# Step 11: Send a reply from Node 3 to Node 1
print_header "Sending Reply: Node 3 -> Node 1"
reply_message="Hello Node 1, this is a reply from Node 3!"
send_onion_message 2 $node1_pubkey "$reply_message"
print_success "Reply sent from Node 3 to Node 1"

# Step 12: Check received messages
# In a real scenario, you would see these in the subscriber output
# For this example, we'll simulate checking the message queue
print_header "Checking Message Queue"
print_info "In a real scenario, you would see the messages in the subscriber output"
print_info "For Node 1: Would receive the reply from Node 3"
print_info "For Node 2: Would receive the direct message from Node 1"
print_info "For Node 3: Would receive the multi-hop message from Node 1"

# Step 13: Kill the message listeners
print_header "Cleaning Up Message Listeners"
kill $node1_listener_pid 2>/dev/null || true
kill $node2_listener_pid 2>/dev/null || true
kill $node3_listener_pid 2>/dev/null || true
print_success "Message listeners cleaned up"

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up a three-node network with channels for connectivity"
echo "2. Subscribing to message events on all nodes"
echo "3. Sending a direct message from Node 1 to Node 2"
echo "4. Sending a multi-hop message from Node 1 to Node 3 through Node 2"
echo "5. Sending a reply from Node 3 back to Node 1"
echo "6. In a real scenario, you would see the messages in the subscriber output"

# Cleanup is handled by the trap
exit 0
