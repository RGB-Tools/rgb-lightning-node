#!/bin/bash

# Full Asset Lifecycle (UDA with Media) Example
# This script shows the complete process for a collectible asset:
# - Creating media
# - Issuing the asset with it
# - Sending it on-chain
# - Having the recipient retrieve the media

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Full Asset Lifecycle (UDA with Media) Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (Issuer)
start_node 1  # Node 2 (Recipient)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Fund Node 1 with bitcoin
fund_node 0 0.1

# Step 5: Create a media file
print_header "Creating Media File"
mkdir -p "$(dirname "$0")/media"
MEDIA_FILE="$(dirname "$0")/media/sample.txt"
echo "This is a sample media file for an RGB UDA asset. It could be any content, including images or other binary data." > "$MEDIA_FILE"
print_success "Created media file: $MEDIA_FILE"

# Step 6: Upload the media file from Node 1
print_header "Uploading Media File"
media_digest=$(upload_asset_media 0 "$MEDIA_FILE")
echo "Media uploaded with digest: $media_digest"

# Step 7: Issue a UDA (collectible) asset on Node 1 with the media
print_header "Issuing UDA Asset with Media"
asset_id=$(issue_rgb_uda 0 "RGB Collectible" "$media_digest")
echo "Issued UDA asset with ID: $asset_id"

# Wait for the asset to be confirmed
print_info "Waiting for asset to be confirmed..."
sleep 5
mine_blocks 6
sleep 5

# Step 8: Check the asset on Node 1
print_header "Asset on Node 1"
list_assets 0

# Step 9: Node 2 creates an RGB invoice for the UDA
print_header "Creating RGB Invoice on Node 2"
rgb_invoice_response=$(create_rgb_invoice 1 $asset_id 1)
rgb_invoice=$(echo $rgb_invoice_response | jq -r .invoice)
echo "RGB invoice: $rgb_invoice"

# Step 10: Node 1 sends the UDA to Node 2
print_header "Sending UDA Asset: Node 1 -> Node 2"
send_response=$(send_rgb_asset 0 $rgb_invoice)
echo "Asset sent: $send_response"

# Mine blocks to confirm the transfer
print_info "Mining blocks to confirm the transfer..."
mine_blocks 6
sleep 5

# Step 11: Check asset on Node 2 after transfer
print_header "Asset on Node 2 After Transfer"
list_assets 1

# Step 12: Node 2 retrieves the media content
print_header "Retrieving Media Content on Node 2"
RETRIEVED_MEDIA_FILE="$(dirname "$0")/media/retrieved.txt"
curl -s -X POST http://127.0.0.1:3001/getassetmedia \
    -H "Content-Type: application/json" \
    -d "{\"digest\": \"$media_digest\"}" \
    -o "$RETRIEVED_MEDIA_FILE"

print_success "Retrieved media saved to: $RETRIEVED_MEDIA_FILE"

# Step 13: Compare original and retrieved media
print_header "Comparing Original and Retrieved Media"
echo "Original media content:"
cat "$MEDIA_FILE"
echo -e "\nRetrieved media content:"
cat "$RETRIEVED_MEDIA_FILE"

# Check if the files are identical
if cmp -s "$MEDIA_FILE" "$RETRIEVED_MEDIA_FILE"; then
    print_success "Media verification successful: Original and retrieved files are identical"
else
    print_error "Media verification failed: Files differ"
fi

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Creating and uploading media content"
echo "2. Issuing a UDA (collectible) asset with the media"
echo "3. Transferring the UDA asset on-chain from Node 1 to Node 2"
echo "4. Node 2 retrieving and verifying the media content"

# Cleanup is handled by the trap
exit 0
