#!/bin/bash

# RGB Lightning Node Examples - Helper Library
# This file contains common functions used by all example scripts

# Set bash to exit on any error
set -e

# Default ports and data directories
BTC_RPC_PORT=18443
ELECTRS_PORT=3002
PROXY_PORT=3003
LDK_PORT_BASE=9735
REST_PORT_BASE=3000
DATA_DIR_BASE="dataldk"

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print a colored header
print_header() {
    echo -e "\n${BLUE}========== $1 ==========${NC}\n"
}

# Print a success message
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Print an error message
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Print a warning/info message
print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Start Bitcoin, Electrs, and Proxy services using Docker
start_backend_services() {
    print_header "Starting Backend Services"
    
    # Check if Docker is running
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    # Start services with docker-compose
    docker-compose up -d bitcoind electrs proxy
    
    # Wait for bitcoind to be ready
    print_info "Waiting for bitcoind to be ready..."
    while ! curl -s --user bitcoin:bitcoin --data-binary '{"jsonrpc":"1.0","id":"curltext","method":"getblockchaininfo","params":[]}' -H 'content-type:text/plain;' http://127.0.0.1:$BTC_RPC_PORT/ > /dev/null; do
        sleep 1
    done
    print_success "Bitcoin Core is ready"
    
    # Wait for electrs to be ready
    print_info "Waiting for electrs to be ready..."
    while ! curl -s http://127.0.0.1:$ELECTRS_PORT/blocks/tip/height > /dev/null; do
        sleep 1
    done
    print_success "Electrs is ready"
    
    # Wait for proxy to be ready
    print_info "Waiting for proxy to be ready..."
    while ! curl -s http://127.0.0.1:$PROXY_PORT/blockchain_info > /dev/null; do
        sleep 1
    done
    print_success "Proxy is ready"
}

# Start an RGB Lightning Node
start_node() {
    local node_index=$1
    local ldk_port=$((LDK_PORT_BASE + node_index))
    local rest_port=$((REST_PORT_BASE + node_index))
    local data_dir="${DATA_DIR_BASE}${node_index}"
    
    print_header "Starting Node $node_index"
    
    # Create data directory if it doesn't exist
    mkdir -p $data_dir
    
    # Start the node
    rgb-lightning-node \
        --ldk-peer-port $ldk_port \
        --rest-api-port $rest_port \
        --data-dir $data_dir \
        --network regtest \
        --electrum-url http://127.0.0.1:$ELECTRS_PORT \
        --proxy-url http://127.0.0.1:$PROXY_PORT \
        --bitcoin-rpc-url http://bitcoin:bitcoin@127.0.0.1:$BTC_RPC_PORT \
        > ${data_dir}/node.log 2>&1 &
    
    # Store the PID
    echo $! > ${data_dir}/node.pid
    
    # Wait for the node to be ready
    print_info "Waiting for Node $node_index to be ready..."
    while ! curl -s http://127.0.0.1:$rest_port/health > /dev/null 2>&1; do
        sleep 1
    done
    print_success "Node $node_index is ready"
}

# Initialize a node
init_node() {
    local node_index=$1
    local rest_port=$((REST_PORT_BASE + node_index))
    local password=${2:-"password"}
    
    print_info "Initializing Node $node_index..."
    
    # Call the init API
    curl -s -X POST http://127.0.0.1:$rest_port/init \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"$password\"}" | jq .
    
    print_success "Node $node_index initialized"
}

# Unlock a node
unlock_node() {
    local node_index=$1
    local rest_port=$((REST_PORT_BASE + node_index))
    local password=${2:-"password"}
    
    print_info "Unlocking Node $node_index..."
    
    # Call the unlock API
    curl -s -X POST http://127.0.0.1:$rest_port/unlock \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"$password\"}" | jq .
    
    print_success "Node $node_index unlocked"
}

# Get node info
get_node_info() {
    local node_index=$1
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Getting info for Node $node_index..."
    
    # Call the getinfo API
    curl -s http://127.0.0.1:$rest_port/getinfo | jq .
}

# Fund a node with regtest bitcoins
fund_node() {
    local node_index=$1
    local amount=${2:-1}  # Default to 1 BTC
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Funding Node $node_index with $amount BTC..."
    
    # Get an address from the node
    local address=$(curl -s http://127.0.0.1:$rest_port/newaddress | jq -r .address)
    
    # Send bitcoins to the address
    docker-compose exec -T bitcoind bitcoin-cli -regtest sendtoaddress $address $amount
    
    # Mine 6 blocks to confirm the transaction
    docker-compose exec -T bitcoind bitcoin-cli -regtest -generate 6
    
    # Wait for the node to see the funds
    print_info "Waiting for funds to be confirmed..."
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        local balance=$(curl -s http://127.0.0.1:$rest_port/btcbalance | jq -r .confirmed_balance)
        if (( $(echo "$balance > 0" | bc -l) )); then
            print_success "Node $node_index funded with $balance BTC"
            return
        fi
        sleep 1
        ((attempts++))
    done
    
    print_error "Failed to fund Node $node_index"
    exit 1
}

# Issue an RGB NIA (fungible) asset
issue_rgb_asset() {
    local node_index=$1
    local name=${2:-"TestAsset"}
    local amount=${3:-1000}
    local precision=${4:-0}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index issuing RGB asset: $name (amount: $amount, precision: $precision)..."
    
    # Call the issueassetnia API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/issueassetnia \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$name\", \"amount\": $amount, \"precision\": $precision}")
    
    # Extract the asset ID
    local asset_id=$(echo $response | jq -r .asset_id)
    
    print_success "Asset issued with ID: $asset_id"
    echo $asset_id
}

# Issue an RGB UDA (non-fungible/collectible) asset
issue_rgb_uda() {
    local node_index=$1
    local name=${2:-"TestCollectible"}
    local media_digest=${3:-""}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index issuing RGB UDA: $name..."
    
    local payload="{\"name\": \"$name\"}"
    if [[ -n "$media_digest" ]]; then
        payload=$(echo $payload | jq --arg digest "$media_digest" '. + {media_digest: $digest}')
    fi
    
    # Call the issueassetuda API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/issueassetuda \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    # Extract the asset ID
    local asset_id=$(echo $response | jq -r .asset_id)
    
    print_success "UDA issued with ID: $asset_id"
    echo $asset_id
}

# Upload media for an RGB asset
upload_asset_media() {
    local node_index=$1
    local file_path=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index uploading media from $file_path..."
    
    # Call the postassetmedia API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/postassetmedia \
        -H "Content-Type: application/octet-stream" \
        --data-binary @$file_path)
    
    # Extract the media digest
    local digest=$(echo $response | jq -r .digest)
    
    print_success "Media uploaded with digest: $digest"
    echo $digest
}

# List assets on a node
list_assets() {
    local node_index=$1
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Listing assets on Node $node_index..."
    
    # Call the listassets API
    curl -s http://127.0.0.1:$rest_port/listassets | jq .
}

# Open a Lightning channel
open_channel() {
    local from_node=$1
    local to_node=$2
    local capacity_sat=${3:-1000000}  # Default to 0.01 BTC
    local push_msat=${4:-0}
    local asset_id=${5:-""}
    local asset_amount=${6:-0}
    local from_port=$((REST_PORT_BASE + from_node))
    local to_port=$((REST_PORT_BASE + to_node))
    
    print_info "Node $from_node opening channel to Node $to_node..."
    
    # Get the destination node's pubkey and connection info
    local to_info=$(curl -s http://127.0.0.1:$to_port/getinfo)
    local to_pubkey=$(echo $to_info | jq -r .identity_pubkey)
    local to_connection="127.0.0.1:$((LDK_PORT_BASE + to_node))"
    
    # Prepare the payload
    local payload="{\"pubkey\": \"$to_pubkey\", \"connection_string\": \"$to_connection\", \"capacity_sat\": $capacity_sat, \"push_msat\": $push_msat}"
    
    # Add RGB asset info if provided
    if [[ -n "$asset_id" && $asset_amount -gt 0 ]]; then
        payload=$(echo $payload | jq --arg id "$asset_id" --arg amt "$asset_amount" '. + {asset_id: $id, asset_amount: ($amt | tonumber)}')
    fi
    
    # Call the openchannel API
    local response=$(curl -s -X POST http://127.0.0.1:$from_port/openchannel \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    # Extract the channel ID
    local channel_id=$(echo $response | jq -r .channel_id)
    
    print_success "Channel opened with ID: $channel_id"
    echo $channel_id
}

# Wait for a channel to be ready
wait_for_channel_ready() {
    local node_index=$1
    local channel_id=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Waiting for channel $channel_id to be ready on Node $node_index..."
    
    local attempts=0
    while [[ $attempts -lt 60 ]]; do
        local channels=$(curl -s http://127.0.0.1:$rest_port/listchannels)
        local state=$(echo $channels | jq -r ".channels[] | select(.channel_id == \"$channel_id\") | .state")
        
        if [[ "$state" == "Usable" ]]; then
            print_success "Channel $channel_id is now ready"
            return
        fi
        
        sleep 1
        ((attempts++))
    done
    
    print_error "Timeout waiting for channel $channel_id to be ready"
    exit 1
}

# Create a Lightning invoice
create_invoice() {
    local node_index=$1
    local amount_msat=${2:-10000}  # Default to 10,000 msat
    local asset_id=${3:-""}
    local asset_amount=${4:-0}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index creating invoice for $amount_msat msat..."
    
    # Prepare the payload
    local payload="{\"amt_msat\": $amount_msat}"
    
    # Add RGB asset info if provided
    if [[ -n "$asset_id" && $asset_amount -gt 0 ]]; then
        payload=$(echo $payload | jq --arg id "$asset_id" --arg amt "$asset_amount" '. + {asset_id: $id, asset_amount: ($amt | tonumber)}')
    fi
    
    # Call the invoice API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/invoice \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    # Extract the payment request
    local payment_request=$(echo $response | jq -r .payment_request)
    
    print_success "Invoice created: $payment_request"
    echo $response
}

# Pay a Lightning invoice
pay_invoice() {
    local node_index=$1
    local payment_request=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index paying invoice: $payment_request..."
    
    # Call the pay API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/pay \
        -H "Content-Type: application/json" \
        -d "{\"payment_request\": \"$payment_request\"}")
    
    # Check if payment was successful
    local status=$(echo $response | jq -r .status)
    
    if [[ "$status" == "SUCCEEDED" ]]; then
        print_success "Payment successful"
    else
        print_error "Payment failed: $status"
        echo $response | jq .
        exit 1
    fi
    
    echo $response
}

# Wait for a payment to complete
wait_for_payment() {
    local node_index=$1
    local payment_hash=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Waiting for payment $payment_hash to complete on Node $node_index..."
    
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        local payments=$(curl -s http://127.0.0.1:$rest_port/listpayments)
        local status=$(echo $payments | jq -r ".payments[] | select(.payment_hash == \"$payment_hash\") | .status")
        
        if [[ "$status" == "SUCCEEDED" ]]; then
            print_success "Payment $payment_hash completed successfully"
            return
        elif [[ "$status" == "FAILED" ]]; then
            print_error "Payment $payment_hash failed"
            exit 1
        fi
        
        sleep 1
        ((attempts++))
    done
    
    print_error "Timeout waiting for payment $payment_hash to complete"
    exit 1
}

# Close a Lightning channel
close_channel() {
    local node_index=$1
    local channel_id=$2
    local force=${3:-false}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index closing channel $channel_id (force: $force)..."
    
    # Call the closechannel API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/closechannel \
        -H "Content-Type: application/json" \
        -d "{\"channel_id\": \"$channel_id\", \"force\": $force}")
    
    print_success "Channel close initiated"
    echo $response
}

# Create an RGB on-chain invoice
create_rgb_invoice() {
    local node_index=$1
    local asset_id=$2
    local amount=${3:-1}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index creating RGB invoice for $amount units of asset $asset_id..."
    
    # Call the rgbinvoice API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/rgbinvoice \
        -H "Content-Type: application/json" \
        -d "{\"asset_id\": \"$asset_id\", \"amount\": $amount}")
    
    # Extract the invoice
    local invoice=$(echo $response | jq -r .invoice)
    
    print_success "RGB invoice created: $invoice"
    echo $response
}

# Send an RGB asset on-chain
send_rgb_asset() {
    local node_index=$1
    local invoice=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index sending RGB asset to invoice: $invoice..."
    
    # Call the sendasset API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/sendasset \
        -H "Content-Type: application/json" \
        -d "{\"invoice\": \"$invoice\"}")
    
    print_success "Asset sent"
    echo $response
}

# Initialize a swap (maker)
maker_init_swap() {
    local node_index=$1
    local from_asset=$2
    local to_asset=$3
    local from_amount=$4
    local to_amount=$5
    local timeout_sec=${6:-600}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index (Maker) initializing swap..."
    
    # Prepare the payload
    local payload="{\"from_amount\": $from_amount, \"to_amount\": $to_amount, \"timeout_sec\": $timeout_sec}"
    
    # Add asset IDs
    if [[ "$from_asset" != "null" && -n "$from_asset" ]]; then
        payload=$(echo $payload | jq --arg id "$from_asset" '. + {from_asset: $id}')
    fi
    
    if [[ "$to_asset" != "null" && -n "$to_asset" ]]; then
        payload=$(echo $payload | jq --arg id "$to_asset" '. + {to_asset: $id}')
    fi
    
    # Call the makerinit API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/makerinit \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    # Extract the swapstring
    local swapstring=$(echo $response | jq -r .swapstring)
    
    print_success "Swap initialized with swapstring: $swapstring"
    echo $response
}

# Accept a swap (taker)
taker_accept_swap() {
    local node_index=$1
    local swapstring=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index (Taker) accepting swap: $swapstring..."
    
    # Call the taker API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/taker \
        -H "Content-Type: application/json" \
        -d "{\"swapstring\": \"$swapstring\"}")
    
    print_success "Swap accepted"
    echo $response
}

# Execute a swap (maker)
maker_execute_swap() {
    local node_index=$1
    local swapstring=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index (Maker) executing swap: $swapstring..."
    
    # Call the makerexecute API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/makerexecute \
        -H "Content-Type: application/json" \
        -d "{\"swapstring\": \"$swapstring\"}")
    
    print_success "Swap execution initiated"
    echo $response
}

# Get swap status
get_swap_status() {
    local node_index=$1
    local swapstring=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    # Call the swapstatus API
    curl -s -X POST http://127.0.0.1:$rest_port/swapstatus \
        -H "Content-Type: application/json" \
        -d "{\"swapstring\": \"$swapstring\"}" | jq .
}

# Wait for swap to complete
wait_for_swap() {
    local node_index=$1
    local swapstring=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Waiting for swap to complete on Node $node_index..."
    
    local attempts=0
    while [[ $attempts -lt 60 ]]; do
        local status=$(curl -s -X POST http://127.0.0.1:$rest_port/swapstatus \
            -H "Content-Type: application/json" \
            -d "{\"swapstring\": \"$swapstring\"}" | jq -r .status)
        
        if [[ "$status" == "Succeeded" ]]; then
            print_success "Swap completed successfully"
            return
        elif [[ "$status" == "Failed" || "$status" == "Expired" ]]; then
            print_error "Swap failed with status: $status"
            exit 1
        fi
        
        sleep 1
        ((attempts++))
    done
    
    print_error "Timeout waiting for swap to complete"
    exit 1
}

# Send a keysend payment
send_keysend() {
    local node_index=$1
    local dest_pubkey=$2
    local amount_msat=$3
    local asset_id=${4:-""}
    local asset_amount=${5:-0}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index sending keysend payment to $dest_pubkey..."
    
    # Prepare the payload
    local payload="{\"dest_pubkey\": \"$dest_pubkey\", \"amt_msat\": $amount_msat}"
    
    # Add RGB asset info if provided
    if [[ -n "$asset_id" && $asset_amount -gt 0 ]]; then
        payload=$(echo $payload | jq --arg id "$asset_id" --arg amt "$asset_amount" '. + {asset_id: $id, asset_amount: ($amt | tonumber)}')
    fi
    
    # Call the keysend API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/keysend \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    # Check if payment was successful
    local status=$(echo $response | jq -r .status)
    
    if [[ "$status" == "SUCCEEDED" ]]; then
        print_success "Keysend payment successful"
    else
        print_error "Keysend payment failed: $status"
        echo $response | jq .
        exit 1
    fi
    
    echo $response
}

# Sign a message
sign_message() {
    local node_index=$1
    local message=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index signing message: \"$message\"..."
    
    # Call the signmessage API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/signmessage \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"$message\"}")
    
    # Extract the signature
    local signature=$(echo $response | jq -r .signature)
    
    print_success "Message signed: $signature"
    echo $response
}

# Send an onion message
send_onion_message() {
    local node_index=$1
    local path_pubkeys=$2  # JSON array of pubkeys
    local tlv_type=$3
    local data=$4
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Node $node_index sending onion message..."
    
    # Call the sendonionmessage API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/sendonionmessage \
        -H "Content-Type: application/json" \
        -d "{\"path_pubkeys\": $path_pubkeys, \"tlv_type\": $tlv_type, \"data\": \"$data\"}")
    
    print_success "Onion message sent"
    echo $response
}

# Create a backup
create_backup() {
    local node_index=$1
    local backup_path=${2:-"tmp/node${node_index}.backup"}
    local rest_port=$((REST_PORT_BASE + node_index))
    
    # Ensure the directory exists
    mkdir -p $(dirname $backup_path)
    
    print_info "Creating backup for Node $node_index to $backup_path..."
    
    # Call the backup API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/backup \
        -H "Content-Type: application/json" \
        -d "{\"path\": \"$backup_path\"}")
    
    print_success "Backup created at $backup_path"
    echo $response
}

# Restore from backup
restore_from_backup() {
    local node_index=$1
    local backup_path=$2
    local rest_port=$((REST_PORT_BASE + node_index))
    
    print_info "Restoring Node $node_index from backup $backup_path..."
    
    # Call the restore API
    local response=$(curl -s -X POST http://127.0.0.1:$rest_port/restore \
        -H "Content-Type: application/json" \
        -d "{\"path\": \"$backup_path\"}")
    
    print_success "Node restored from backup"
    echo $response
}

# Stop a node
stop_node() {
    local node_index=$1
    local data_dir="${DATA_DIR_BASE}${node_index}"
    
    if [[ -f "${data_dir}/node.pid" ]]; then
        local pid=$(cat "${data_dir}/node.pid")
        print_info "Stopping Node $node_index (PID: $pid)..."
        kill $pid 2>/dev/null || true
        rm -f "${data_dir}/node.pid"
        print_success "Node $node_index stopped"
    fi
}

# Stop all backend services
stop_backend_services() {
    print_header "Stopping Backend Services"
    docker-compose down
    print_success "All backend services stopped"
}

# Clean up all data
cleanup() {
    print_header "Cleaning Up"
    
    # Stop all nodes
    for i in {0..9}; do
        if [[ -d "${DATA_DIR_BASE}${i}" ]]; then
            stop_node $i
        fi
    done
    
    # Stop backend services
    stop_backend_services
    
    # Remove data directories
    rm -rf ${DATA_DIR_BASE}*
    
    print_success "Cleanup complete"
}

# Mine blocks
mine_blocks() {
    local count=${1:-1}
    
    print_info "Mining $count blocks..."
    docker-compose exec -T bitcoind bitcoin-cli -regtest -generate $count
    print_success "$count blocks mined"
}

# Setup trap to ensure cleanup on exit
setup_cleanup_trap() {
    trap cleanup EXIT
}
