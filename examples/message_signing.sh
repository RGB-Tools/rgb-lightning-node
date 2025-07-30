#!/bin/bash

# Message Signing Example
# This script demonstrates how to sign and verify messages using RGB Lightning Node.

# Source the helper library
source "$(dirname "$0")/lib.sh"

# Setup cleanup trap
setup_cleanup_trap

print_header "Message Signing Example"

# Step 1: Start backend services
start_backend_services

# Step 2: Start two nodes
start_node 0  # Node 1 (Signer)
start_node 1  # Node 2 (Verifier)

# Step 3: Initialize and unlock both nodes
init_node 0
init_node 1
unlock_node 0
unlock_node 1

# Step 4: Get Node 1's pubkey
print_header "Getting Node 1's Pubkey"
node1_info=$(curl -s http://127.0.0.1:3000/getinfo)
node1_pubkey=$(echo $node1_info | jq -r .identity_pubkey)
echo "Node 1 pubkey: $node1_pubkey"

# Step 5: Sign a message with Node 1
print_header "Signing Message with Node 1"
message="This is a test message from RGB Lightning Node"
sign_response=$(sign_message 0 "$message")
signature=$(echo $sign_response | jq -r .signature)
echo "Message: $message"
echo "Signature: $signature"

# Step 6: Verify the message with Node 2
print_header "Verifying Message with Node 2"
verify_response=$(curl -s -X POST http://127.0.0.1:3001/verifymessage \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"$message\",
        \"signature\": \"$signature\",
        \"pubkey\": \"$node1_pubkey\"
    }")
valid=$(echo $verify_response | jq -r .valid)
echo "Verification result: $verify_response"

if [[ "$valid" == "true" ]]; then
    print_success "Message verification successful"
else
    print_error "Message verification failed"
fi

# Step 7: Try to verify with an altered message
print_header "Verifying Altered Message (Should Fail)"
altered_message="This is an altered test message"
verify_altered_response=$(curl -s -X POST http://127.0.0.1:3001/verifymessage \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"$altered_message\",
        \"signature\": \"$signature\",
        \"pubkey\": \"$node1_pubkey\"
    }")
altered_valid=$(echo $verify_altered_response | jq -r .valid)
echo "Altered message verification result: $verify_altered_response"

if [[ "$altered_valid" == "false" ]]; then
    print_success "Altered message correctly failed verification"
else
    print_error "Altered message unexpectedly passed verification"
fi

# Step 8: Sign a message with custom key
print_header "Signing Message with Custom Key"
custom_message="This message is signed with a custom key"
custom_key="custom-key-1"
custom_sign_response=$(curl -s -X POST http://127.0.0.1:3000/signmessage \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"$custom_message\",
        \"key_loc\": {
            \"key_family\": 0,
            \"key_index\": 1
        }
    }")
custom_signature=$(echo $custom_sign_response | jq -r .signature)
custom_pubkey=$(echo $custom_sign_response | jq -r .pubkey)
echo "Custom message: $custom_message"
echo "Custom signature: $custom_signature"
echo "Custom pubkey: $custom_pubkey"

# Step 9: Verify the custom signed message
print_header "Verifying Custom Signed Message"
custom_verify_response=$(curl -s -X POST http://127.0.0.1:3001/verifymessage \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"$custom_message\",
        \"signature\": \"$custom_signature\",
        \"pubkey\": \"$custom_pubkey\"
    }")
custom_valid=$(echo $custom_verify_response | jq -r .valid)
echo "Custom verification result: $custom_verify_response"

if [[ "$custom_valid" == "true" ]]; then
    print_success "Custom message verification successful"
else
    print_error "Custom message verification failed"
fi

print_header "Example Completed Successfully"
echo "This example demonstrated:"
echo "1. Signing a message with Node 1's identity key"
echo "2. Verifying the signature with Node 2"
echo "3. Attempting to verify with an altered message (which correctly fails)"
echo "4. Signing a message with a custom key derivation path"
echo "5. Verifying the custom-signed message"

# Cleanup is handled by the trap
exit 0
