//! Protobuf signer wire helpers for integration tests (`lib_sdk` external-signer host mocks).
//! Same envelope as production ([`crate::signer::proto`] / UniFFI transport).
//! Compiled only with `uniffi` + `test-utils` (see `lib_sdk` `required-features`).

pub use signer_external::contract::{
    BootstrapData, ChannelOp, ChannelPublicKeys, ChannelRequest, ChannelResponse,
    DerivedAddressMatch, NodeRequest, NodeResponse, SignerIdentity, SignerRequest, SignerResponse,
    SpendableDescriptorKind, SpendableOutputSignInput, WalletDerivationMatch, WalletInputMetadata,
};

use crate::signer::proto::{decode_signer_request, encode_signer_response};

pub fn decode_signer_request_wire(wire: &[u8]) -> Result<SignerRequest, String> {
    decode_signer_request(wire).map_err(|e| e.to_string())
}

pub fn encode_signer_response_wire(response: &SignerResponse) -> Result<Vec<u8>, String> {
    encode_signer_response(response).map_err(|e| e.to_string())
}
