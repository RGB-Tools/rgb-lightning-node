#!/bin/bash

# RGB Lightning Node CLI Demo Script
# This script demonstrates common CLI operations

set -e

# Configuration
SERVER_URL="${RLN_SERVER_URL:-http://localhost:3001}"
AUTH_TOKEN="${RLN_AUTH_TOKEN:-}"
CLI="./target/release/rln-cli"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to print section headers
print_section() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

# Helper function to print commands
print_command() {
    echo -e "${GREEN}$ $1${NC}"
}

# Helper function to print info
print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if CLI binary exists
if [ ! -f "$CLI" ]; then
    print_info "CLI binary not found. Building..."
    cargo build --release --bin rln-cli
fi

# Export environment variables
export RLN_SERVER_URL="$SERVER_URL"
if [ -n "$AUTH_TOKEN" ]; then
    export RLN_AUTH_TOKEN="$AUTH_TOKEN"
fi

print_section "RGB Lightning Node CLI Demo"

# ============================
# Node Information
# ============================
print_section "1. Getting Node Information"

print_command "$CLI node info"
$CLI node info

print_command "$CLI node network-info"
$CLI node network-info

# ============================
# On-Chain Operations
# ============================
print_section "2. On-Chain Operations"

print_info "Getting a new Bitcoin address..."
print_command "$CLI onchain address"
ADDRESS_RESULT=$($CLI onchain address)
echo "$ADDRESS_RESULT"

print_info "Checking BTC balance..."
print_command "$CLI onchain btc-balance"
$CLI onchain btc-balance

print_info "Listing unspent outputs..."
print_command "$CLI onchain list-unspents"
$CLI onchain list-unspents

# ============================
# RGB Asset Operations
# ============================
print_section "3. RGB Asset Operations"

print_info "Listing all RGB assets..."
print_command "$CLI rgb list-assets"
ASSETS=$($CLI rgb list-assets)
echo "$ASSETS"

# Extract first asset ID if available
ASSET_ID=$(echo "$ASSETS" | jq -r '.nia[0].asset_id // .cfa[0].asset_id // .uda[0].asset_id // empty' 2>/dev/null || echo "")

if [ -n "$ASSET_ID" ]; then
    print_info "Found asset: $ASSET_ID"
    
    print_command "$CLI rgb asset-balance $ASSET_ID"
    $CLI rgb asset-balance "$ASSET_ID"
    
    print_command "$CLI rgb asset-metadata $ASSET_ID"
    $CLI rgb asset-metadata "$ASSET_ID"
    
    print_command "$CLI rgb list-transfers $ASSET_ID"
    $CLI rgb list-transfers "$ASSET_ID"
else
    print_info "No assets found. You can issue a new asset with:"
    echo "  $CLI rgb issue-nia --amounts 1000000 DEMO 'Demo Token' --precision 2"
fi

# ============================
# Lightning Network Operations
# ============================
print_section "4. Lightning Network Operations"

print_info "Listing connected peers..."
print_command "$CLI peer list"
$CLI peer list

print_info "Listing channels..."
print_command "$CLI channel list"
$CLI channel list

print_info "Listing payments..."
print_command "$CLI payment list"
$CLI payment list

# ============================
# Asset Swaps
# ============================
print_section "5. Asset Swap Operations"

print_info "Listing swaps..."
print_command "$CLI swap list"
$CLI swap list

# ============================
# Example Commands
# ============================
print_section "Example Commands Reference"

cat << 'EOF'
# Issue a new NIA asset (fungible token)
./target/release/rln-cli rgb issue-nia \
  --amounts 1000000 \
  DEMO \
  "Demo Token" \
  --precision 2

# Create UTXOs for RGB operations
./target/release/rln-cli rgb create-utxos 5 32500 5.0

# Get an RGB invoice to receive assets
./target/release/rln-cli rgb rgb-invoice \
  --min-confirmations 1 \
  rgb:YOUR_ASSET_ID \
  --amount 100 \
  --duration-seconds 86400

# Connect to a Lightning peer
./target/release/rln-cli peer connect \
  03pubkey@host:port

# Open a vanilla Lightning channel
./target/release/rln-cli channel open \
  03pubkey@host:port \
  30000 \
  --push-msat 1000000 \
  --public

# Open an RGB Lightning channel
./target/release/rln-cli channel open \
  03pubkey@host:port \
  30010 \
  --asset-amount 100 \
  --asset-id rgb:YOUR_ASSET_ID \
  --public

# Create a Lightning invoice
./target/release/rln-cli invoice ln-invoice \
  3000000 \
  --expiry-sec 420

# Send a Lightning payment
./target/release/rln-cli payment send lnbc...

# Send a keysend payment
./target/release/rln-cli payment keysend \
  03pubkey \
  3000000

# Initialize a maker swap
./target/release/rln-cli swap maker-init \
  30 \
  10 \
  rgb:FROM_ASSET \
  rgb:TO_ASSET \
  --timeout-sec 300

# Backup the node
./target/release/rln-cli node backup \
  /path/to/backup.zip \
  "password"

# Sign a message
./target/release/rln-cli node sign-message "Hello, RGB!"

# Estimate on-chain fee
./target/release/rln-cli onchain estimate-fee 6

# Send BTC on-chain
./target/release/rln-cli onchain send-btc \
  10000 \
  bcrt1qaddress... \
  5.0

EOF

print_section "Demo Complete!"
print_info "For more information, see CLI_README.md"
print_info "Run '$CLI --help' to see all available commands"

