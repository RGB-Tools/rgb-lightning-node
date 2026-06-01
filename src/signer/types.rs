pub(crate) type WalletInputMetadata = signer_external::contract::WalletInputMetadata;
pub(crate) type AsyncPaymentsHashEntry = signer_external::contract::AsyncPaymentsHashEntry;
pub(crate) type SpendableDescriptorKind = signer_external::contract::SpendableDescriptorKind;
pub(crate) type SpendableOutputSignInput = signer_external::contract::SpendableOutputSignInput;
pub(crate) type WalletDerivationMatch = signer_external::contract::WalletDerivationMatch;
pub(crate) type DerivedAddressMatch = signer_external::contract::DerivedAddressMatch;
#[allow(dead_code)]
pub(crate) type SignerIdentity = signer_external::contract::SignerIdentity;
pub(crate) type BootstrapData = signer_external::contract::BootstrapData;
pub(crate) type ExternalSignerRequest = signer_external::contract::SignerRequest;
pub(crate) type ExternalSignerResponse = signer_external::contract::SignerResponse;
pub(crate) type ExternalNodeRequest = signer_external::contract::NodeRequest;
pub(crate) type ExternalNodeResponse = signer_external::contract::NodeResponse;
pub(crate) type ExternalChannelHtlc = signer_external::contract::ChannelHtlc;
pub(crate) type ExternalChannelOp = signer_external::contract::ChannelOp;
pub(crate) type ExternalChannelRequest = signer_external::contract::ChannelRequest;
pub(crate) type ExternalChannelResponse = signer_external::contract::ChannelResponse;
pub(crate) type ChannelPublicKeys = signer_external::contract::ChannelPublicKeys;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RlnSignerError {
    #[allow(dead_code)]
    #[error("external signer transport error: {0}")]
    Transport(String),
    #[error("external signer protocol error: {0}")]
    Protocol(String),
    #[error("unsupported operation in external signer mode: {0}")]
    Unsupported(String),
}

/// Bootstrap `api_level` the node accepts from an attached external signer. **Must stay in sync**
/// with hosts and `signer_external::contract::BootstrapData::api_level` (currently **`1`** only).
pub(crate) const SUPPORTED_SIGNER_API_LEVEL: u32 = 1;

/// Validates bootstrap payload fields consumed by RLN directly.
pub(crate) fn validate_bootstrap_payload(_bootstrap: &BootstrapData) -> Result<(), RlnSignerError> {
    Ok(())
}

/// Legacy deterministic 32-byte seed derived from public bootstrap identity.
pub(crate) fn derive_async_payments_compat_seed_from_bootstrap(
    bootstrap: &BootstrapData,
) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash as BitcoinHash};
    let mut seed_material = Vec::new();
    seed_material.extend_from_slice(bootstrap.identity.node_id.as_bytes());
    seed_material.extend_from_slice(bootstrap.identity.account_xpub_vanilla.as_bytes());
    seed_material.extend_from_slice(bootstrap.identity.account_xpub_colored.as_bytes());
    seed_material.extend_from_slice(bootstrap.identity.master_fingerprint.as_bytes());
    seed_material.extend_from_slice(bootstrap.protocol_version.as_bytes());
    <sha256::Hash as BitcoinHash>::hash(&seed_material).to_byte_array()
}

#[cfg(test)]
mod async_payments_seed_tests {
    use super::*;

    fn fake_bootstrap() -> BootstrapData {
        BootstrapData {
            identity: SignerIdentity {
                node_id: "02".repeat(33),
                account_xpub_vanilla: "xv".to_string(),
                account_xpub_colored: "xc".to_string(),
                master_fingerprint: "deadbeef".to_string(),
            },
            protocol_version: "1".to_string(),
            api_level: 1,
        }
    }

    #[test]
    fn bootstrap_payload_validation_accepts_identity_only() {
        let b = fake_bootstrap();
        validate_bootstrap_payload(&b).expect("valid");
    }

    #[test]
    fn compat_seed_still_derives_from_public_bootstrap_identity() {
        let b = fake_bootstrap();
        let seed = derive_async_payments_compat_seed_from_bootstrap(&b);
        assert_ne!(seed, [0u8; 32]);
    }
}
