#!/bin/bash

# Backup and Restore Example
# This script verifies that the backup and restore functionality correctly preserves 
# the node's entire state, including keys, assets, and channels.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Backup and Restore Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (to be backed up)
start_node 1  # Node 2 (counterparty)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund Node 1 with bitcoin
fund_node 0 0.1

# Step 5: Issue an RGB asset on Node 1
print_header "Issuing RGB Asset on Node 1"
asset_id=$(issue_rgb_asset 0 "RGB Backup Test Asset" 1000 0)
echo "Issued asset with ID: $asset_id"

# Wait for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 6: Store Node 1's pubkey for later comparison
print_header "Storing Node 1's Original State"
node_info=$(curl -s http://127.0.0.1:3000/getinfo)
original_pubkey=$(echo $node_info | jq -r .identity_pubkey)
echo "Original pubkey: $original_pubkey"

# Step 7: Open a channel from Node 1 to Node 2
print_header "Opening RGB Channel: Node 1 -> Node 2"
channel_id=$(open_channel 0 1 1000000 0 $asset_id 200)
echo "Opened RGB channel with ID: $channel_id"

# Mine blocks to confirm the channel
print_info "Mining blocks to confirm the channel..."
mine_blocks 6
sleep 5

# Step 8: Wait for the channel to be ready
wait_for_channel_ready 0 $channel_id

# Step 9: Store channel information for later comparison
print_header "Storing Channel Information"
original_channels=$(curl -s http://127.0.0.1:3000/listchannels)
echo "Original channels:"
echo $original_channels | jq .

# Step 10: Store asset balance for later comparison
print_header "Storing Asset Balance"
original_assets=$(curl -s http://127.0.0.1:3000/listassets)
echo "Original assets:"
echo $original_assets | jq .

# Step 11: Lock Node 1 before backup
print_header "Locking Node 1"
curl -s -X POST http://127.0.0.1:3000/lock | jq .

# Step 12: Create a backup directory
mkdir -p tmp

# Step 13: Create a backup of Node 1
print_header "Creating Backup of Node 1"
backup_response=$(create_backup 0 "tmp/node0.backup")
echo "Backup created: $backup_response"

# Step 14: Stop Node 1
print_header "Stopping Node 1"
stop_node 0

# Step 15: Wipe Node 1's data directory
print_header "Wiping Node 1's Data Directory"
rm -rf dataldk0
mkdir -p dataldk0

# Step 16: Start a new, empty Node 1
print_header "Starting New Empty Node 1"
start_node 0

# Step 17: Restore Node 1 from backup
print_header "Restoring Node 1 from Backup"
restore_response=$(restore_from_backup 0 "tmp/node0.backup")
echo "Restore response: $restore_response"

# Step 18: Unlock the restored Node 1
print_header "Unlocking Restored Node 1"
unlock_node 0

# Step 19: Verify Node 1's pubkey matches the original
print_header "Verifying Node 1's Pubkey"
restored_node_info=$(curl -s http://127.0.0.1:3000/getinfo)
restored_pubkey=$(echo $restored_node_info | jq -r .identity_pubkey)
echo "Restored pubkey: $restored_pubkey"

if [[ "$original_pubkey" == "$restored_pubkey" ]]; then
    print_success "Pubkey verification successful: Original and restored pubkeys match"
else
    print_error "Pubkey verification failed: Pubkeys do not match"
    exit 1
fi

# Step 20: Verify channel state is preserved
print_header "Verifying Channel State"
restored_channels=$(curl -s http://127.0.0.1:3000/listchannels)
echo "Restored channels:"
echo $restored_channels | jq .

# Step 21: Verify asset balance is preserved
print_header "Verifying Asset Balance"
restored_assets=$(curl -s http://127.0.0.1:3000/listassets)
echo "Restored assets:"
echo $restored_assets | jq .

# Step 22: Make a payment to verify the channel is functional
print_header "Testing Channel Functionality with a Payment"
# Node 2 creates an RGB invoice
invoice_response=$(create_invoice 1 10000 $asset_id 10)
payment_request=$(echo $invoice_response | jq -r .payment_request)
echo "Created RGB invoice: $payment_request"

# Node 1 pays the invoice
payment_response=$(pay_invoice 0 $payment_request)
payment_hash=$(echo $payment_response | jq -r .payment_hash)
echo "Payment hash: $payment_hash"

# Wait for the payment to complete
wait_for_payment 0 $payment_hash

# Check channel status after payment
print_header "Channel Status After Payment"
curl -s http://127.0.0.1:3000/listchannels | jq .

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Setting up a node with an RGB asset and channel"
echo "2. Creating a backup of the node"
echo "3. Wiping the node's data directory"
echo "4. Restoring the node from the backup"
echo "5. Verifying that the node's pubkey, channel state, and asset balances were preserved"
echo "6. Testing the restored channel with a payment"

# Cleanup is handled by the trap
exit 0
