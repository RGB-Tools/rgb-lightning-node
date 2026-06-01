use prost::Message;
use signer_external::contract::{
    AsyncPaymentsHashEntry, BootstrapData, ChannelHtlc, ChannelOp, ChannelPublicKeys,
    ChannelRequest, ChannelResponse, DerivedAddressMatch, NodeRequest, NodeResponse,
    SignerIdentity, SignerRequest, SignerResponse, SpendableDescriptorKind,
    SpendableOutputSignInput, WalletDerivationMatch, WalletInputMetadata,
};

use super::types::RlnSignerError;

const ENVELOPE_VERSION_V1: u32 = 1;
const ENCODING_PROTOBUF_V1: u32 = 2;

#[derive(Clone, PartialEq, Message)]
struct SignerEnvelope {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(uint32, tag = "2")]
    pub payload_encoding: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct EmptyV1 {}

#[derive(Clone, PartialEq, Message)]
struct SignerIdentityV1 {
    #[prost(string, tag = "1")]
    pub node_id: String,
    #[prost(string, tag = "2")]
    pub account_xpub_vanilla: String,
    #[prost(string, tag = "3")]
    pub account_xpub_colored: String,
    #[prost(string, tag = "4")]
    pub master_fingerprint: String,
}

#[derive(Clone, PartialEq, Message)]
struct BootstrapDataV1 {
    #[prost(message, optional, tag = "1")]
    pub identity: Option<SignerIdentityV1>,
    #[prost(string, tag = "2")]
    pub protocol_version: String,
    #[prost(uint32, tag = "3")]
    pub api_level: u32,
}

#[derive(Clone, PartialEq, Message)]
struct WalletInputMetadataV1 {
    #[prost(uint32, tag = "1")]
    pub keyindex: u32,
    #[prost(uint64, tag = "2")]
    pub amount_sat: u64,
    #[prost(string, tag = "3")]
    pub script_pubkey_hex: String,
    #[prost(bool, tag = "4")]
    pub is_p2sh: bool,
}

#[derive(Clone, PartialEq, Message)]
struct DerivedAddressMatchV1 {
    #[prost(uint32, tag = "1")]
    pub keyindex: u32,
    #[prost(string, tag = "2")]
    pub address: String,
    #[prost(string, tag = "3")]
    pub derivation: String,
    #[prost(string, tag = "4")]
    pub account: String,
}

#[derive(Clone, PartialEq, Message)]
struct GetNodeIdV1 {
    #[prost(string, tag = "1")]
    pub recipient: String,
}

#[derive(Clone, PartialEq, Message)]
struct GetDestinationScriptV1 {
    #[prost(string, tag = "1")]
    pub channel_keys_id_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct EcdhV1 {
    #[prost(string, tag = "1")]
    pub recipient: String,
    #[prost(string, tag = "2")]
    pub other_key: String,
    #[prost(string, optional, tag = "3")]
    pub tweak: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct CryptForOfferV1 {
    #[prost(string, tag = "1")]
    pub bytes_hex: String,
    #[prost(string, tag = "2")]
    pub nonce_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct BlindedMessagePayloadV1 {
    #[prost(string, tag = "1")]
    pub bytes_hex: String,
    #[prost(string, tag = "2")]
    pub rho_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct PeerStoragePayloadV1 {
    #[prost(string, tag = "1")]
    pub bytes_hex: String,
    #[prost(string, optional, tag = "2")]
    pub random_bytes_hex: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct CreateInboundPaymentV1 {
    #[prost(uint64, optional, tag = "1")]
    pub min_value_msat: Option<u64>,
    #[prost(uint32, tag = "2")]
    pub invoice_expiry_delta_secs: u32,
    #[prost(string, tag = "3")]
    pub random_bytes_hex: String,
    #[prost(uint64, tag = "4")]
    pub current_time: u64,
    #[prost(uint32, optional, tag = "5")]
    pub min_final_cltv_expiry_delta: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct CreateInboundPaymentForHashV1 {
    #[prost(string, tag = "1")]
    pub payment_hash_hex: String,
    #[prost(uint64, optional, tag = "2")]
    pub min_value_msat: Option<u64>,
    #[prost(uint32, tag = "3")]
    pub invoice_expiry_delta_secs: u32,
    #[prost(uint64, tag = "4")]
    pub current_time: u64,
    #[prost(uint32, optional, tag = "5")]
    pub min_final_cltv_expiry_delta: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct CreateSpontaneousPaymentSecretV1 {
    #[prost(uint64, optional, tag = "1")]
    pub min_value_msat: Option<u64>,
    #[prost(uint32, tag = "2")]
    pub invoice_expiry_delta_secs: u32,
    #[prost(uint64, tag = "3")]
    pub current_time: u64,
    #[prost(uint32, optional, tag = "4")]
    pub min_final_cltv_expiry_delta: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct VerifyInboundPaymentV1 {
    #[prost(string, tag = "1")]
    pub payment_hash_hex: String,
    #[prost(string, tag = "2")]
    pub payment_secret_hex: String,
    #[prost(uint64, tag = "3")]
    pub total_msat: u64,
    #[prost(uint64, tag = "4")]
    pub highest_seen_timestamp: u64,
}

#[derive(Clone, PartialEq, Message)]
struct GetPaymentPreimageV1 {
    #[prost(string, tag = "1")]
    pub payment_hash_hex: String,
    #[prost(string, tag = "2")]
    pub payment_secret_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct PrepareAsyncPaymentsHashesV1 {
    #[prost(string, tag = "1")]
    pub host_node_id_hex: String,
    #[prost(uint64, tag = "2")]
    pub start_index: u64,
    #[prost(uint32, tag = "3")]
    pub batch_size: u32,
}

#[derive(Clone, PartialEq, Message)]
struct AsyncPaymentsHashEntryV1 {
    #[prost(uint64, tag = "1")]
    pub hash_index: u64,
    #[prost(string, tag = "2")]
    pub payment_hash_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignInvoiceV1 {
    #[prost(string, tag = "1")]
    pub hrp: String,
    #[prost(string, tag = "2")]
    pub u5bytes_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignBolt12InvoiceV1 {
    #[prost(string, tag = "1")]
    pub invoice: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignGossipMessageV1 {
    #[prost(string, tag = "1")]
    pub message_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignMessageV1 {
    #[prost(string, tag = "1")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
struct NodeRequestV1 {
    #[prost(
        oneof = "node_request_v1::Kind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24"
    )]
    pub kind: Option<node_request_v1::Kind>,
}

mod node_request_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        GetNodeId(GetNodeIdV1),
        #[prost(message, tag = "2")]
        GetDestinationScript(GetDestinationScriptV1),
        #[prost(message, tag = "3")]
        GetShutdownScriptpubkey(EmptyV1),
        #[prost(message, tag = "4")]
        GetSecureRandomBytes(EmptyV1),
        #[prost(message, tag = "23")]
        EncryptPeerStoragePayload(PeerStoragePayloadV1),
        #[prost(message, tag = "24")]
        DecryptPeerStoragePayload(PeerStoragePayloadV1),
        #[prost(message, tag = "21")]
        EncryptBlindedMessagePayload(BlindedMessagePayloadV1),
        #[prost(message, tag = "22")]
        DecryptBlindedMessagePayload(BlindedMessagePayloadV1),
        #[prost(message, tag = "10")]
        GetHmacForOfferKey(EmptyV1),
        #[prost(message, tag = "11")]
        CryptForOffer(CryptForOfferV1),
        #[prost(message, tag = "15")]
        PrepareAsyncPaymentsHashes(PrepareAsyncPaymentsHashesV1),
        #[prost(message, tag = "16")]
        CreateInboundPayment(CreateInboundPaymentV1),
        #[prost(message, tag = "17")]
        CreateInboundPaymentForHash(CreateInboundPaymentForHashV1),
        #[prost(message, tag = "18")]
        CreateSpontaneousPaymentSecret(CreateSpontaneousPaymentSecretV1),
        #[prost(message, tag = "19")]
        VerifyInboundPayment(VerifyInboundPaymentV1),
        #[prost(message, tag = "20")]
        GetPaymentPreimage(GetPaymentPreimageV1),
        #[prost(message, tag = "5")]
        Ecdh(EcdhV1),
        #[prost(message, tag = "6")]
        SignInvoice(SignInvoiceV1),
        #[prost(message, tag = "7")]
        SignBolt12Invoice(SignBolt12InvoiceV1),
        #[prost(message, tag = "8")]
        SignGossipMessage(SignGossipMessageV1),
        #[prost(message, tag = "9")]
        SignMessage(SignMessageV1),
    }
}

#[derive(Clone, PartialEq, Message)]
struct NodeIdV1 {
    #[prost(string, tag = "1")]
    pub node_id_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct ScriptV1 {
    #[prost(string, tag = "1")]
    pub script_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct RandomBytesV1 {
    #[prost(string, tag = "1")]
    pub bytes_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct HmacForOfferKeyV1 {
    #[prost(string, tag = "1")]
    pub key_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct CryptForOfferResponseV1 {
    #[prost(string, tag = "1")]
    pub bytes_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct DecryptedBlindedMessagePayloadResponseV1 {
    #[prost(string, tag = "1")]
    pub bytes_hex: String,
    #[prost(bool, tag = "2")]
    pub used_aad: bool,
}

#[derive(Clone, PartialEq, Message)]
struct EcdhResponseV1 {
    #[prost(string, tag = "1")]
    pub shared_secret_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct RecoverableSignatureV1 {
    #[prost(string, tag = "1")]
    pub signature_hex: String,
    #[prost(uint32, tag = "2")]
    pub recovery_id: u32,
}

#[derive(Clone, PartialEq, Message)]
struct SignatureV1 {
    #[prost(string, tag = "1")]
    pub signature_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct NodeResponseV1 {
    #[prost(
        oneof = "node_response_v1::Kind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18"
    )]
    pub kind: Option<node_response_v1::Kind>,
}

mod node_response_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        NodeId(NodeIdV1),
        #[prost(message, tag = "2")]
        Script(ScriptV1),
        #[prost(message, tag = "3")]
        RandomBytes(RandomBytesV1),
        #[prost(message, tag = "17")]
        PeerStoragePayload(RandomBytesV1),
        #[prost(message, tag = "18")]
        DecryptedPeerStoragePayload(RandomBytesV1),
        #[prost(message, tag = "15")]
        BlindedMessagePayload(RandomBytesV1),
        #[prost(message, tag = "16")]
        DecryptedBlindedMessagePayload(DecryptedBlindedMessagePayloadResponseV1),
        #[prost(message, tag = "7")]
        HmacForOfferKey(HmacForOfferKeyV1),
        #[prost(message, tag = "8")]
        CryptForOffer(CryptForOfferResponseV1),
        #[prost(message, tag = "10")]
        AsyncPaymentsHashes(AsyncPaymentsHashesV1),
        #[prost(message, tag = "11")]
        PaymentHashAndSecret(PaymentHashAndSecretV1),
        #[prost(message, tag = "12")]
        PaymentSecret(PaymentSecretV1),
        #[prost(message, tag = "13")]
        VerifyInboundPayment(VerifyInboundPaymentResponseV1),
        #[prost(message, tag = "14")]
        PaymentPreimage(PaymentPreimageV1),
        #[prost(message, tag = "4")]
        Ecdh(EcdhResponseV1),
        #[prost(message, tag = "5")]
        RecoverableSignature(RecoverableSignatureV1),
        #[prost(message, tag = "6")]
        Signature(SignatureV1),
    }
}

#[derive(Clone, PartialEq, Message)]
struct AsyncPaymentsHashesV1 {
    #[prost(message, repeated, tag = "1")]
    pub hashes: Vec<AsyncPaymentsHashEntryV1>,
}

#[derive(Clone, PartialEq, Message)]
struct PaymentHashAndSecretV1 {
    #[prost(string, tag = "1")]
    pub payment_hash_hex: String,
    #[prost(string, tag = "2")]
    pub payment_secret_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct PaymentSecretV1 {
    #[prost(string, tag = "1")]
    pub payment_secret_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct VerifyInboundPaymentResponseV1 {
    #[prost(string, optional, tag = "1")]
    pub payment_preimage_hex: Option<String>,
    #[prost(uint32, optional, tag = "2")]
    pub min_final_cltv_expiry_delta: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct PaymentPreimageV1 {
    #[prost(string, tag = "1")]
    pub payment_preimage_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct ChannelPublicKeysV1 {
    #[prost(string, tag = "1")]
    pub funding_pubkey_hex: String,
    #[prost(string, tag = "2")]
    pub revocation_basepoint_hex: String,
    #[prost(string, tag = "3")]
    pub payment_point_hex: String,
    #[prost(string, tag = "4")]
    pub delayed_payment_basepoint_hex: String,
    #[prost(string, tag = "5")]
    pub htlc_basepoint_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct ChannelHtlcV1 {
    #[prost(uint32, tag = "1")]
    pub side: u32,
    #[prost(uint64, tag = "2")]
    pub amount_msat: u64,
    #[prost(string, tag = "3")]
    pub payment_hash_hex: String,
    #[prost(uint32, tag = "4")]
    pub cltv_expiry: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GenerateChannelKeysIdV1 {
    #[prost(bool, tag = "1")]
    pub inbound: bool,
    #[prost(uint64, tag = "2")]
    pub channel_value_satoshis: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub user_channel_id_be: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct DeriveChannelSignerV1 {
    #[prost(uint64, tag = "1")]
    pub channel_value_satoshis: u64,
    #[prost(string, tag = "2")]
    pub channel_keys_id_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct ReadChannelSignerV1 {
    #[prost(string, tag = "1")]
    pub channel_signer_state_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SetupChannelV1 {
    #[prost(bool, tag = "1")]
    pub is_outbound: bool,
    #[prost(uint64, tag = "2")]
    pub channel_value_satoshis: u64,
    #[prost(uint64, tag = "3")]
    pub push_value_msat: u64,
    #[prost(string, tag = "4")]
    pub funding_txid_hex: String,
    #[prost(uint32, tag = "5")]
    pub funding_vout: u32,
    #[prost(uint32, tag = "6")]
    pub holder_selected_contest_delay: u32,
    #[prost(message, optional, tag = "7")]
    pub counterparty_pubkeys: Option<ChannelPublicKeysV1>,
    #[prost(uint32, tag = "8")]
    pub counterparty_selected_contest_delay: u32,
    #[prost(uint32, tag = "9")]
    pub channel_type_kind: u32,
}

#[derive(Clone, PartialEq, Message)]
struct ChannelIndexV1 {
    #[prost(uint64, tag = "1")]
    pub idx: u64,
}

/// Protobuf encoding of the `ValidateHolderCommitment` channel op (see `signer_external::contract`).
/// Field **8** is the consensus-serialized unsigned holder commitment tx (hex) for the RGB / full-tx VLS path.
/// Field **9** is witness redeem scripts (hex), one per output, for PSBT `witness_script` (VLS decode).
#[derive(Clone, PartialEq, Message)]
struct ValidateHolderCommitmentV1 {
    #[prost(uint64, tag = "1")]
    pub commitment_number: u64,
    #[prost(uint32, tag = "2")]
    pub feerate_sat_per_kw: u32,
    #[prost(uint64, tag = "3")]
    pub to_local_value_sat: u64,
    #[prost(uint64, tag = "4")]
    pub to_remote_value_sat: u64,
    #[prost(message, repeated, tag = "5")]
    pub htlcs: Vec<ChannelHtlcV1>,
    #[prost(string, tag = "6")]
    pub counterparty_signature_hex: String,
    #[prost(string, repeated, tag = "7")]
    pub counterparty_htlc_signatures_hex: Vec<String>,
    /// Consensus-serialized holder commitment tx (hex). Non-empty enables RGB / full-tx VLS path.
    #[prost(string, tag = "8")]
    pub commitment_unsigned_tx_hex: String,
    #[prost(string, repeated, tag = "9")]
    pub commitment_psbt_output_witness_scripts_hex: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct SignHolderCommitmentV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint64, tag = "2")]
    pub commitment_number: u64,
}

#[derive(Clone, PartialEq, Message)]
struct SignCounterpartyCommitmentV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(string, tag = "2")]
    pub remote_per_commitment_point_hex: String,
    #[prost(uint64, tag = "3")]
    pub commitment_number: u64,
    #[prost(uint32, tag = "4")]
    pub feerate_sat_per_kw: u32,
    #[prost(uint64, tag = "5")]
    pub to_local_value_sat: u64,
    #[prost(uint64, tag = "6")]
    pub to_remote_value_sat: u64,
    #[prost(message, repeated, tag = "7")]
    pub htlcs: Vec<ChannelHtlcV1>,
    #[prost(string, repeated, tag = "8")]
    pub preimages_hex: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    pub commitment_psbt_output_witness_scripts_hex: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct SignClosingTransactionV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignJusticeRevokedOutputV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(uint64, tag = "3")]
    pub amount_sat: u64,
    #[prost(string, tag = "4")]
    pub per_commitment_key_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignJusticeRevokedHtlcV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(uint64, tag = "3")]
    pub amount_sat: u64,
    #[prost(string, tag = "4")]
    pub per_commitment_key_hex: String,
    #[prost(string, tag = "5")]
    pub htlc_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignHolderHtlcTransactionV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(string, tag = "3")]
    pub htlc_descriptor_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignCounterpartyHtlcTransactionV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(uint64, tag = "3")]
    pub amount_sat: u64,
    #[prost(string, tag = "4")]
    pub per_commitment_point_hex: String,
    #[prost(string, tag = "5")]
    pub htlc_descriptor_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignDynamicP2wshInputV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(string, tag = "3")]
    pub descriptor_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignCounterpartyPaymentInputV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(string, tag = "3")]
    pub descriptor_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignSplicingFundingInputV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(string, tag = "3")]
    pub txin_descriptor_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignHolderAnchorInputV1 {
    #[prost(string, tag = "1")]
    pub tx_hex: String,
    #[prost(uint32, tag = "2")]
    pub input: u32,
    #[prost(string, tag = "3")]
    pub descriptor_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignChannelAnnouncementWithFundingKeyV1 {
    #[prost(string, tag = "1")]
    pub msg_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct ChannelOpV1 {
    #[prost(
        oneof = "channel_op_v1::Kind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16"
    )]
    pub kind: Option<channel_op_v1::Kind>,
}

mod channel_op_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        SetupChannel(SetupChannelV1),
        #[prost(message, tag = "2")]
        GetPerCommitmentPoint(ChannelIndexV1),
        #[prost(message, tag = "3")]
        ReleaseCommitmentSecret(ChannelIndexV1),
        #[prost(message, tag = "4")]
        ValidateHolderCommitment(ValidateHolderCommitmentV1),
        #[prost(message, tag = "5")]
        SignHolderCommitment(SignHolderCommitmentV1),
        #[prost(message, tag = "6")]
        SignCounterpartyCommitment(SignCounterpartyCommitmentV1),
        #[prost(message, tag = "7")]
        SignClosingTransaction(SignClosingTransactionV1),
        #[prost(message, tag = "8")]
        SignJusticeRevokedOutput(SignJusticeRevokedOutputV1),
        #[prost(message, tag = "9")]
        SignJusticeRevokedHtlc(SignJusticeRevokedHtlcV1),
        #[prost(message, tag = "10")]
        SignHolderHtlcTransaction(SignHolderHtlcTransactionV1),
        #[prost(message, tag = "11")]
        SignCounterpartyHtlcTransaction(SignCounterpartyHtlcTransactionV1),
        #[prost(message, tag = "12")]
        SignDynamicP2wshInput(SignDynamicP2wshInputV1),
        #[prost(message, tag = "13")]
        SignCounterpartyPaymentInput(SignCounterpartyPaymentInputV1),
        #[prost(message, tag = "14")]
        SignSplicingFundingInput(SignSplicingFundingInputV1),
        #[prost(message, tag = "15")]
        SignHolderAnchorInput(SignHolderAnchorInputV1),
        #[prost(message, tag = "16")]
        SignChannelAnnouncementWithFundingKey(SignChannelAnnouncementWithFundingKeyV1),
    }
}

#[derive(Clone, PartialEq, Message)]
struct ChannelRequestV1 {
    #[prost(oneof = "channel_request_v1::Kind", tags = "1, 2, 3, 4")]
    pub kind: Option<channel_request_v1::Kind>,
}

mod channel_request_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        GenerateChannelKeysId(GenerateChannelKeysIdV1),
        #[prost(message, tag = "2")]
        DeriveChannelSigner(DeriveChannelSignerV1),
        #[prost(message, tag = "3")]
        ReadChannelSigner(ReadChannelSignerV1),
        #[prost(message, tag = "4")]
        Op(ChannelOpRequestV1),
    }
}

#[derive(Clone, PartialEq, Message)]
struct ChannelOpRequestV1 {
    #[prost(string, tag = "1")]
    pub channel_keys_id_hex: String,
    #[prost(message, optional, tag = "2")]
    pub op: Option<ChannelOpV1>,
}

#[derive(Clone, PartialEq, Message)]
struct GeneratedChannelKeysIdV1 {
    #[prost(string, tag = "1")]
    pub channel_keys_id_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct ChannelSignerDataV1 {
    #[prost(string, tag = "1")]
    pub channel_signer_state_hex: String,
    #[prost(message, optional, tag = "2")]
    pub channel_pubkeys: Option<ChannelPublicKeysV1>,
}

#[derive(Clone, PartialEq, Message)]
struct PerCommitmentPointV1 {
    #[prost(string, tag = "1")]
    pub point_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct CommitmentSecretV1 {
    #[prost(string, tag = "1")]
    pub secret_hex: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignatureWithHtlcsV1 {
    #[prost(string, tag = "1")]
    pub signature_hex: String,
    #[prost(string, repeated, tag = "2")]
    pub htlc_signatures_hex: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct ChannelResponseV1 {
    #[prost(oneof = "channel_response_v1::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub kind: Option<channel_response_v1::Kind>,
}

mod channel_response_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        GeneratedChannelKeysId(GeneratedChannelKeysIdV1),
        #[prost(message, tag = "2")]
        SetupComplete(EmptyV1),
        #[prost(message, tag = "3")]
        ValidationComplete(EmptyV1),
        #[prost(message, tag = "4")]
        ChannelSignerData(ChannelSignerDataV1),
        #[prost(message, tag = "5")]
        PerCommitmentPoint(PerCommitmentPointV1),
        #[prost(message, tag = "6")]
        CommitmentSecret(CommitmentSecretV1),
        #[prost(message, tag = "7")]
        Signature(SignatureV1),
        #[prost(message, tag = "8")]
        SignatureWithHtlcs(SignatureWithHtlcsV1),
    }
}

#[derive(Clone, PartialEq, Message)]
struct WalletDerivationMatchV1 {
    #[prost(string, tag = "1")]
    pub account_name: String,
    #[prost(uint32, tag = "2")]
    pub keyindex: u32,
    #[prost(string, tag = "3")]
    pub derivation_path: String,
}

impl From<WalletDerivationMatch> for WalletDerivationMatchV1 {
    fn from(value: WalletDerivationMatch) -> Self {
        Self {
            account_name: value.account_name,
            keyindex: value.keyindex,
            derivation_path: value.derivation_path,
        }
    }
}

impl From<WalletDerivationMatchV1> for WalletDerivationMatch {
    fn from(value: WalletDerivationMatchV1) -> Self {
        Self {
            account_name: value.account_name,
            keyindex: value.keyindex,
            derivation_path: value.derivation_path,
        }
    }
}

#[derive(Clone, PartialEq, Message)]
struct SpendableOutputSignInputV1 {
    #[prost(int32, tag = "1")]
    pub descriptor_kind: i32,
    #[prost(string, tag = "2")]
    pub txid_hex: String,
    #[prost(uint32, tag = "3")]
    pub vout: u32,
    #[prost(uint64, tag = "4")]
    pub amount_sat: u64,
    #[prost(string, tag = "5")]
    pub script_pubkey_hex: String,
    #[prost(string, optional, tag = "6")]
    pub channel_keys_id_hex: Option<String>,
    #[prost(message, optional, tag = "7")]
    pub wallet_derivation_match: Option<WalletDerivationMatchV1>,
    #[prost(string, optional, tag = "8")]
    pub witness_script_hex: Option<String>,
    #[prost(string, optional, tag = "9")]
    pub redeem_script_hex: Option<String>,
    #[prost(string, optional, tag = "10")]
    pub per_commitment_point_hex: Option<String>,
    #[prost(uint32, optional, tag = "11")]
    pub to_self_delay: Option<u32>,
}

impl From<SpendableOutputSignInput> for SpendableOutputSignInputV1 {
    fn from(value: SpendableOutputSignInput) -> Self {
        let descriptor_kind = match value.descriptor_kind {
            SpendableDescriptorKind::StaticOutput => 0,
            SpendableDescriptorKind::StaticPaymentOutput => 1,
            SpendableDescriptorKind::DelayedPaymentOutput => 2,
        };
        Self {
            descriptor_kind,
            txid_hex: value.txid_hex,
            vout: value.vout,
            amount_sat: value.amount_sat,
            script_pubkey_hex: value.script_pubkey_hex,
            channel_keys_id_hex: value.channel_keys_id_hex,
            wallet_derivation_match: value.wallet_derivation_match.map(Into::into),
            witness_script_hex: value.witness_script_hex,
            redeem_script_hex: value.redeem_script_hex,
            per_commitment_point_hex: value.per_commitment_point_hex,
            to_self_delay: value.to_self_delay.map(|v| v as u32),
        }
    }
}

impl TryFrom<SpendableOutputSignInputV1> for SpendableOutputSignInput {
    type Error = RlnSignerError;
    fn try_from(value: SpendableOutputSignInputV1) -> Result<Self, Self::Error> {
        let descriptor_kind = match value.descriptor_kind {
            0 => SpendableDescriptorKind::StaticOutput,
            1 => SpendableDescriptorKind::StaticPaymentOutput,
            2 => SpendableDescriptorKind::DelayedPaymentOutput,
            other => {
                return Err(RlnSignerError::Protocol(format!(
                    "invalid spendable descriptor kind: {other}"
                )))
            }
        };
        Ok(Self {
            descriptor_kind,
            txid_hex: value.txid_hex,
            vout: value.vout,
            amount_sat: value.amount_sat,
            script_pubkey_hex: value.script_pubkey_hex,
            channel_keys_id_hex: value.channel_keys_id_hex,
            wallet_derivation_match: value.wallet_derivation_match.map(Into::into),
            witness_script_hex: value.witness_script_hex,
            redeem_script_hex: value.redeem_script_hex,
            per_commitment_point_hex: value.per_commitment_point_hex,
            to_self_delay: value.to_self_delay.map(|v| v as u16),
        })
    }
}

#[derive(Clone, PartialEq, Message)]
struct SignSpendableOutputsPsbtRequestV1 {
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<SpendableOutputSignInputV1>,
    #[prost(string, tag = "2")]
    pub psbt: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignPsbtRequestV1 {
    #[prost(string, repeated, tag = "1")]
    pub descriptors: Vec<String>,
    #[prost(string, tag = "2")]
    pub psbt: String,
}

#[derive(Clone, PartialEq, Message)]
struct SignedPsbtV1 {
    #[prost(string, tag = "1")]
    pub psbt: String,
}

#[derive(Clone, PartialEq, Message)]
struct GetWalletInputMetadataRequestV1 {
    #[prost(string, tag = "1")]
    pub txid_hex: String,
    #[prost(uint32, tag = "2")]
    pub vout: u32,
    #[prost(string, optional, tag = "3")]
    pub script_pubkey_hex: Option<String>,
    #[prost(uint64, optional, tag = "4")]
    pub amount_sat: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct WalletInputMetadataResponseV1 {
    #[prost(message, optional, tag = "1")]
    pub metadata: Option<WalletInputMetadataV1>,
}

#[derive(Clone, PartialEq, Message)]
struct FindDerivationMatchesRequestV1 {
    #[prost(string, tag = "1")]
    pub script_pubkey_hex: String,
    #[prost(uint32, tag = "2")]
    pub max_index: u32,
}

#[derive(Clone, PartialEq, Message)]
struct FindDerivationMatchesResponseV1 {
    #[prost(message, repeated, tag = "1")]
    pub matches: Vec<DerivedAddressMatchV1>,
}

#[derive(Clone, PartialEq, Message)]
struct SignerRequestV1 {
    #[prost(oneof = "signer_request_v1::Kind", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub kind: Option<signer_request_v1::Kind>,
}

mod signer_request_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Bootstrap(EmptyV1),
        #[prost(message, tag = "2")]
        Node(NodeRequestV1),
        #[prost(message, tag = "3")]
        Channel(ChannelRequestV1),
        #[prost(message, tag = "4")]
        SignSpendableOutputsPsbt(SignSpendableOutputsPsbtRequestV1),
        #[prost(message, tag = "5")]
        SignRgbPsbt(SignPsbtRequestV1),
        #[prost(message, tag = "6")]
        GetWalletInputMetadata(GetWalletInputMetadataRequestV1),
        #[prost(message, tag = "7")]
        FindDerivationMatches(FindDerivationMatchesRequestV1),
    }
}

#[derive(Clone, PartialEq, Message)]
struct SignerResponseV1 {
    #[prost(oneof = "signer_response_v1::Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: Option<signer_response_v1::Kind>,
}

mod signer_response_v1 {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Bootstrap(BootstrapDataV1),
        #[prost(message, tag = "2")]
        Node(NodeResponseV1),
        #[prost(message, tag = "3")]
        Channel(ChannelResponseV1),
        #[prost(message, tag = "4")]
        SignedPsbt(SignedPsbtV1),
        #[prost(message, tag = "5")]
        WalletInputMetadata(WalletInputMetadataResponseV1),
        #[prost(message, tag = "6")]
        FindDerivationMatches(FindDerivationMatchesResponseV1),
    }
}

fn proto_err(ctx: &str) -> impl FnOnce(&str) -> RlnSignerError + '_ {
    move |msg| RlnSignerError::Protocol(format!("{ctx}: {msg}"))
}

fn encode_u128_be(value: u128) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn decode_u128_be(bytes: &[u8]) -> Result<u128, RlnSignerError> {
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| proto_err("invalid u128 field")("expected 16 bytes"))?;
    Ok(u128::from_be_bytes(arr))
}

impl From<SignerIdentity> for SignerIdentityV1 {
    fn from(value: SignerIdentity) -> Self {
        Self {
            node_id: value.node_id,
            account_xpub_vanilla: value.account_xpub_vanilla,
            account_xpub_colored: value.account_xpub_colored,
            master_fingerprint: value.master_fingerprint,
        }
    }
}

impl From<SignerIdentityV1> for SignerIdentity {
    fn from(value: SignerIdentityV1) -> Self {
        Self {
            node_id: value.node_id,
            account_xpub_vanilla: value.account_xpub_vanilla,
            account_xpub_colored: value.account_xpub_colored,
            master_fingerprint: value.master_fingerprint,
        }
    }
}

impl From<BootstrapData> for BootstrapDataV1 {
    fn from(value: BootstrapData) -> Self {
        Self {
            identity: Some(value.identity.into()),
            protocol_version: value.protocol_version,
            api_level: value.api_level,
        }
    }
}

impl TryFrom<BootstrapDataV1> for BootstrapData {
    type Error = RlnSignerError;
    fn try_from(value: BootstrapDataV1) -> Result<Self, Self::Error> {
        // Protobuf omits default numerics: treat `0` as unspecified and align with
        // [`crate::signer::SUPPORTED_SIGNER_API_LEVEL`] (`1`).
        let api_level = if value.api_level == 0 {
            crate::signer::SUPPORTED_SIGNER_API_LEVEL
        } else {
            value.api_level
        };
        Ok(Self {
            identity: value
                .identity
                .ok_or_else(|| proto_err("bootstrap")("missing identity"))?
                .into(),
            protocol_version: value.protocol_version,
            api_level,
        })
    }
}

impl From<AsyncPaymentsHashEntry> for AsyncPaymentsHashEntryV1 {
    fn from(value: AsyncPaymentsHashEntry) -> Self {
        Self {
            hash_index: value.hash_index,
            payment_hash_hex: value.payment_hash_hex,
        }
    }
}

impl From<AsyncPaymentsHashEntryV1> for AsyncPaymentsHashEntry {
    fn from(value: AsyncPaymentsHashEntryV1) -> Self {
        Self {
            hash_index: value.hash_index,
            payment_hash_hex: value.payment_hash_hex,
        }
    }
}

impl From<WalletInputMetadata> for WalletInputMetadataV1 {
    fn from(value: WalletInputMetadata) -> Self {
        Self {
            keyindex: value.keyindex,
            amount_sat: value.amount_sat,
            script_pubkey_hex: value.script_pubkey_hex,
            is_p2sh: value.is_p2sh,
        }
    }
}

impl From<WalletInputMetadataV1> for WalletInputMetadata {
    fn from(value: WalletInputMetadataV1) -> Self {
        Self {
            keyindex: value.keyindex,
            amount_sat: value.amount_sat,
            script_pubkey_hex: value.script_pubkey_hex,
            is_p2sh: value.is_p2sh,
        }
    }
}

impl From<DerivedAddressMatch> for DerivedAddressMatchV1 {
    fn from(value: DerivedAddressMatch) -> Self {
        Self {
            keyindex: value.keyindex,
            address: value.address,
            derivation: value.derivation_path,
            account: value.account_name,
        }
    }
}

impl From<DerivedAddressMatchV1> for DerivedAddressMatch {
    fn from(value: DerivedAddressMatchV1) -> Self {
        Self {
            keyindex: value.keyindex,
            address: value.address,
            derivation_path: value.derivation,
            account_name: value.account,
        }
    }
}

impl From<NodeRequest> for NodeRequestV1 {
    fn from(value: NodeRequest) -> Self {
        let kind = match value {
            NodeRequest::GetNodeId { recipient } => {
                node_request_v1::Kind::GetNodeId(GetNodeIdV1 { recipient })
            }
            NodeRequest::GetDestinationScript {
                channel_keys_id_hex,
            } => node_request_v1::Kind::GetDestinationScript(GetDestinationScriptV1 {
                channel_keys_id_hex,
            }),
            NodeRequest::GetShutdownScriptpubkey => {
                node_request_v1::Kind::GetShutdownScriptpubkey(EmptyV1 {})
            }
            NodeRequest::GetSecureRandomBytes => {
                node_request_v1::Kind::GetSecureRandomBytes(EmptyV1 {})
            }
            NodeRequest::EncryptPeerStoragePayload {
                plaintext_hex,
                random_bytes_hex,
            } => node_request_v1::Kind::EncryptPeerStoragePayload(PeerStoragePayloadV1 {
                bytes_hex: plaintext_hex,
                random_bytes_hex: Some(random_bytes_hex),
            }),
            NodeRequest::DecryptPeerStoragePayload { ciphertext_hex } => {
                node_request_v1::Kind::DecryptPeerStoragePayload(PeerStoragePayloadV1 {
                    bytes_hex: ciphertext_hex,
                    random_bytes_hex: None,
                })
            }
            NodeRequest::EncryptBlindedMessagePayload {
                plaintext_hex,
                rho_hex,
            } => node_request_v1::Kind::EncryptBlindedMessagePayload(BlindedMessagePayloadV1 {
                bytes_hex: plaintext_hex,
                rho_hex,
            }),
            NodeRequest::DecryptBlindedMessagePayload {
                ciphertext_hex,
                rho_hex,
            } => node_request_v1::Kind::DecryptBlindedMessagePayload(BlindedMessagePayloadV1 {
                bytes_hex: ciphertext_hex,
                rho_hex,
            }),
            NodeRequest::GetHmacForOfferKey => {
                node_request_v1::Kind::GetHmacForOfferKey(EmptyV1 {})
            }
            NodeRequest::CryptForOffer {
                bytes_hex,
                nonce_hex,
            } => node_request_v1::Kind::CryptForOffer(CryptForOfferV1 {
                bytes_hex,
                nonce_hex,
            }),
            NodeRequest::PrepareAsyncPaymentsHashes {
                host_node_id_hex,
                start_index,
                batch_size,
            } => node_request_v1::Kind::PrepareAsyncPaymentsHashes(PrepareAsyncPaymentsHashesV1 {
                host_node_id_hex,
                start_index,
                batch_size,
            }),
            NodeRequest::CreateInboundPayment {
                min_value_msat,
                invoice_expiry_delta_secs,
                random_bytes_hex,
                current_time,
                min_final_cltv_expiry_delta,
            } => node_request_v1::Kind::CreateInboundPayment(CreateInboundPaymentV1 {
                min_value_msat,
                invoice_expiry_delta_secs,
                random_bytes_hex,
                current_time,
                min_final_cltv_expiry_delta: min_final_cltv_expiry_delta.map(|v| v as u32),
            }),
            NodeRequest::CreateInboundPaymentForHash {
                payment_hash_hex,
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            } => {
                node_request_v1::Kind::CreateInboundPaymentForHash(CreateInboundPaymentForHashV1 {
                    payment_hash_hex,
                    min_value_msat,
                    invoice_expiry_delta_secs,
                    current_time,
                    min_final_cltv_expiry_delta: min_final_cltv_expiry_delta.map(|v| v as u32),
                })
            }
            NodeRequest::CreateSpontaneousPaymentSecret {
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            } => node_request_v1::Kind::CreateSpontaneousPaymentSecret(
                CreateSpontaneousPaymentSecretV1 {
                    min_value_msat,
                    invoice_expiry_delta_secs,
                    current_time,
                    min_final_cltv_expiry_delta: min_final_cltv_expiry_delta.map(|v| v as u32),
                },
            ),
            NodeRequest::VerifyInboundPayment {
                payment_hash_hex,
                payment_secret_hex,
                total_msat,
                highest_seen_timestamp,
            } => node_request_v1::Kind::VerifyInboundPayment(VerifyInboundPaymentV1 {
                payment_hash_hex,
                payment_secret_hex,
                total_msat,
                highest_seen_timestamp,
            }),
            NodeRequest::GetPaymentPreimage {
                payment_hash_hex,
                payment_secret_hex,
            } => node_request_v1::Kind::GetPaymentPreimage(GetPaymentPreimageV1 {
                payment_hash_hex,
                payment_secret_hex,
            }),
            NodeRequest::Ecdh {
                recipient,
                other_key,
                tweak,
            } => node_request_v1::Kind::Ecdh(EcdhV1 {
                recipient,
                other_key,
                tweak,
            }),
            NodeRequest::SignInvoice { hrp, u5bytes_hex } => {
                node_request_v1::Kind::SignInvoice(SignInvoiceV1 { hrp, u5bytes_hex })
            }
            NodeRequest::SignBolt12Invoice { invoice } => {
                node_request_v1::Kind::SignBolt12Invoice(SignBolt12InvoiceV1 { invoice })
            }
            NodeRequest::SignGossipMessage { message_hex } => {
                node_request_v1::Kind::SignGossipMessage(SignGossipMessageV1 { message_hex })
            }
            NodeRequest::SignMessage { message } => {
                node_request_v1::Kind::SignMessage(SignMessageV1 { message })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<NodeRequestV1> for NodeRequest {
    type Error = RlnSignerError;
    fn try_from(value: NodeRequestV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("node request")("missing kind"))?
        {
            node_request_v1::Kind::GetNodeId(v) => Ok(Self::GetNodeId {
                recipient: v.recipient,
            }),
            node_request_v1::Kind::GetDestinationScript(v) => Ok(Self::GetDestinationScript {
                channel_keys_id_hex: v.channel_keys_id_hex,
            }),
            node_request_v1::Kind::GetShutdownScriptpubkey(_) => Ok(Self::GetShutdownScriptpubkey),
            node_request_v1::Kind::GetSecureRandomBytes(_) => Ok(Self::GetSecureRandomBytes),
            node_request_v1::Kind::EncryptPeerStoragePayload(v) => {
                Ok(Self::EncryptPeerStoragePayload {
                    plaintext_hex: v.bytes_hex,
                    random_bytes_hex: v.random_bytes_hex.ok_or_else(|| {
                        proto_err("node request")(
                            "missing random_bytes_hex for EncryptPeerStoragePayload",
                        )
                    })?,
                })
            }
            node_request_v1::Kind::DecryptPeerStoragePayload(v) => {
                Ok(Self::DecryptPeerStoragePayload {
                    ciphertext_hex: v.bytes_hex,
                })
            }
            node_request_v1::Kind::EncryptBlindedMessagePayload(v) => {
                Ok(Self::EncryptBlindedMessagePayload {
                    plaintext_hex: v.bytes_hex,
                    rho_hex: v.rho_hex,
                })
            }
            node_request_v1::Kind::DecryptBlindedMessagePayload(v) => {
                Ok(Self::DecryptBlindedMessagePayload {
                    ciphertext_hex: v.bytes_hex,
                    rho_hex: v.rho_hex,
                })
            }
            node_request_v1::Kind::GetHmacForOfferKey(_) => Ok(Self::GetHmacForOfferKey),
            node_request_v1::Kind::CryptForOffer(v) => Ok(Self::CryptForOffer {
                bytes_hex: v.bytes_hex,
                nonce_hex: v.nonce_hex,
            }),
            node_request_v1::Kind::PrepareAsyncPaymentsHashes(v) => {
                Ok(Self::PrepareAsyncPaymentsHashes {
                    host_node_id_hex: v.host_node_id_hex,
                    start_index: v.start_index,
                    batch_size: v.batch_size,
                })
            }
            node_request_v1::Kind::CreateInboundPayment(v) => Ok(Self::CreateInboundPayment {
                min_value_msat: v.min_value_msat,
                invoice_expiry_delta_secs: v.invoice_expiry_delta_secs,
                random_bytes_hex: v.random_bytes_hex,
                current_time: v.current_time,
                min_final_cltv_expiry_delta: v.min_final_cltv_expiry_delta.map(|vv| vv as u16),
            }),
            node_request_v1::Kind::CreateInboundPaymentForHash(v) => {
                Ok(Self::CreateInboundPaymentForHash {
                    payment_hash_hex: v.payment_hash_hex,
                    min_value_msat: v.min_value_msat,
                    invoice_expiry_delta_secs: v.invoice_expiry_delta_secs,
                    current_time: v.current_time,
                    min_final_cltv_expiry_delta: v.min_final_cltv_expiry_delta.map(|vv| vv as u16),
                })
            }
            node_request_v1::Kind::CreateSpontaneousPaymentSecret(v) => {
                Ok(Self::CreateSpontaneousPaymentSecret {
                    min_value_msat: v.min_value_msat,
                    invoice_expiry_delta_secs: v.invoice_expiry_delta_secs,
                    current_time: v.current_time,
                    min_final_cltv_expiry_delta: v.min_final_cltv_expiry_delta.map(|vv| vv as u16),
                })
            }
            node_request_v1::Kind::VerifyInboundPayment(v) => Ok(Self::VerifyInboundPayment {
                payment_hash_hex: v.payment_hash_hex,
                payment_secret_hex: v.payment_secret_hex,
                total_msat: v.total_msat,
                highest_seen_timestamp: v.highest_seen_timestamp,
            }),
            node_request_v1::Kind::GetPaymentPreimage(v) => Ok(Self::GetPaymentPreimage {
                payment_hash_hex: v.payment_hash_hex,
                payment_secret_hex: v.payment_secret_hex,
            }),
            node_request_v1::Kind::Ecdh(v) => Ok(Self::Ecdh {
                recipient: v.recipient,
                other_key: v.other_key,
                tweak: v.tweak,
            }),
            node_request_v1::Kind::SignInvoice(v) => Ok(Self::SignInvoice {
                hrp: v.hrp,
                u5bytes_hex: v.u5bytes_hex,
            }),
            node_request_v1::Kind::SignBolt12Invoice(v) => {
                Ok(Self::SignBolt12Invoice { invoice: v.invoice })
            }
            node_request_v1::Kind::SignGossipMessage(v) => Ok(Self::SignGossipMessage {
                message_hex: v.message_hex,
            }),
            node_request_v1::Kind::SignMessage(v) => Ok(Self::SignMessage { message: v.message }),
        }
    }
}

impl From<NodeResponse> for NodeResponseV1 {
    fn from(value: NodeResponse) -> Self {
        let kind = match value {
            NodeResponse::NodeId { node_id_hex } => {
                node_response_v1::Kind::NodeId(NodeIdV1 { node_id_hex })
            }
            NodeResponse::Script { script_hex } => {
                node_response_v1::Kind::Script(ScriptV1 { script_hex })
            }
            NodeResponse::RandomBytes { bytes_hex } => {
                node_response_v1::Kind::RandomBytes(RandomBytesV1 { bytes_hex })
            }
            NodeResponse::PeerStoragePayload { bytes_hex } => {
                node_response_v1::Kind::PeerStoragePayload(RandomBytesV1 { bytes_hex })
            }
            NodeResponse::DecryptedPeerStoragePayload { bytes_hex } => {
                node_response_v1::Kind::DecryptedPeerStoragePayload(RandomBytesV1 { bytes_hex })
            }
            NodeResponse::BlindedMessagePayload { bytes_hex } => {
                node_response_v1::Kind::BlindedMessagePayload(RandomBytesV1 { bytes_hex })
            }
            NodeResponse::DecryptedBlindedMessagePayload {
                bytes_hex,
                used_aad,
            } => node_response_v1::Kind::DecryptedBlindedMessagePayload(
                DecryptedBlindedMessagePayloadResponseV1 {
                    bytes_hex,
                    used_aad,
                },
            ),
            NodeResponse::HmacForOfferKey { key_hex } => {
                node_response_v1::Kind::HmacForOfferKey(HmacForOfferKeyV1 { key_hex })
            }
            NodeResponse::CryptForOffer { bytes_hex } => {
                node_response_v1::Kind::CryptForOffer(CryptForOfferResponseV1 { bytes_hex })
            }
            NodeResponse::AsyncPaymentsHashes { hashes } => {
                node_response_v1::Kind::AsyncPaymentsHashes(AsyncPaymentsHashesV1 {
                    hashes: hashes.into_iter().map(Into::into).collect(),
                })
            }
            NodeResponse::PaymentHashAndSecret {
                payment_hash_hex,
                payment_secret_hex,
            } => node_response_v1::Kind::PaymentHashAndSecret(PaymentHashAndSecretV1 {
                payment_hash_hex,
                payment_secret_hex,
            }),
            NodeResponse::PaymentSecret { payment_secret_hex } => {
                node_response_v1::Kind::PaymentSecret(PaymentSecretV1 { payment_secret_hex })
            }
            NodeResponse::VerifyInboundPayment {
                payment_preimage_hex,
                min_final_cltv_expiry_delta,
            } => node_response_v1::Kind::VerifyInboundPayment(VerifyInboundPaymentResponseV1 {
                payment_preimage_hex,
                min_final_cltv_expiry_delta: min_final_cltv_expiry_delta.map(|v| v as u32),
            }),
            NodeResponse::PaymentPreimage {
                payment_preimage_hex,
            } => node_response_v1::Kind::PaymentPreimage(PaymentPreimageV1 {
                payment_preimage_hex,
            }),
            NodeResponse::Ecdh { shared_secret_hex } => {
                node_response_v1::Kind::Ecdh(EcdhResponseV1 { shared_secret_hex })
            }
            NodeResponse::RecoverableSignature {
                signature_hex,
                recovery_id,
            } => node_response_v1::Kind::RecoverableSignature(RecoverableSignatureV1 {
                signature_hex,
                recovery_id: recovery_id as u32,
            }),
            NodeResponse::Signature { signature_hex } => {
                node_response_v1::Kind::Signature(SignatureV1 { signature_hex })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<NodeResponseV1> for NodeResponse {
    type Error = RlnSignerError;
    fn try_from(value: NodeResponseV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("node response")("missing kind"))?
        {
            node_response_v1::Kind::NodeId(v) => Ok(Self::NodeId {
                node_id_hex: v.node_id_hex,
            }),
            node_response_v1::Kind::Script(v) => Ok(Self::Script {
                script_hex: v.script_hex,
            }),
            node_response_v1::Kind::RandomBytes(v) => Ok(Self::RandomBytes {
                bytes_hex: v.bytes_hex,
            }),
            node_response_v1::Kind::PeerStoragePayload(v) => Ok(Self::PeerStoragePayload {
                bytes_hex: v.bytes_hex,
            }),
            node_response_v1::Kind::DecryptedPeerStoragePayload(v) => {
                Ok(Self::DecryptedPeerStoragePayload {
                    bytes_hex: v.bytes_hex,
                })
            }
            node_response_v1::Kind::BlindedMessagePayload(v) => Ok(Self::BlindedMessagePayload {
                bytes_hex: v.bytes_hex,
            }),
            node_response_v1::Kind::DecryptedBlindedMessagePayload(v) => {
                Ok(Self::DecryptedBlindedMessagePayload {
                    bytes_hex: v.bytes_hex,
                    used_aad: v.used_aad,
                })
            }
            node_response_v1::Kind::HmacForOfferKey(v) => {
                Ok(Self::HmacForOfferKey { key_hex: v.key_hex })
            }
            node_response_v1::Kind::CryptForOffer(v) => Ok(Self::CryptForOffer {
                bytes_hex: v.bytes_hex,
            }),
            node_response_v1::Kind::AsyncPaymentsHashes(v) => Ok(Self::AsyncPaymentsHashes {
                hashes: v.hashes.into_iter().map(Into::into).collect(),
            }),
            node_response_v1::Kind::PaymentHashAndSecret(v) => Ok(Self::PaymentHashAndSecret {
                payment_hash_hex: v.payment_hash_hex,
                payment_secret_hex: v.payment_secret_hex,
            }),
            node_response_v1::Kind::PaymentSecret(v) => Ok(Self::PaymentSecret {
                payment_secret_hex: v.payment_secret_hex,
            }),
            node_response_v1::Kind::VerifyInboundPayment(v) => Ok(Self::VerifyInboundPayment {
                payment_preimage_hex: v.payment_preimage_hex,
                min_final_cltv_expiry_delta: v.min_final_cltv_expiry_delta.map(|vv| vv as u16),
            }),
            node_response_v1::Kind::PaymentPreimage(v) => Ok(Self::PaymentPreimage {
                payment_preimage_hex: v.payment_preimage_hex,
            }),
            node_response_v1::Kind::Ecdh(v) => Ok(Self::Ecdh {
                shared_secret_hex: v.shared_secret_hex,
            }),
            node_response_v1::Kind::RecoverableSignature(v) => Ok(Self::RecoverableSignature {
                signature_hex: v.signature_hex,
                recovery_id: v.recovery_id as u8,
            }),
            node_response_v1::Kind::Signature(v) => Ok(Self::Signature {
                signature_hex: v.signature_hex,
            }),
        }
    }
}

impl From<ChannelPublicKeys> for ChannelPublicKeysV1 {
    fn from(value: ChannelPublicKeys) -> Self {
        Self {
            funding_pubkey_hex: value.funding_pubkey_hex,
            revocation_basepoint_hex: value.revocation_basepoint_hex,
            payment_point_hex: value.payment_point_hex,
            delayed_payment_basepoint_hex: value.delayed_payment_basepoint_hex,
            htlc_basepoint_hex: value.htlc_basepoint_hex,
        }
    }
}

impl From<ChannelPublicKeysV1> for ChannelPublicKeys {
    fn from(value: ChannelPublicKeysV1) -> Self {
        Self {
            funding_pubkey_hex: value.funding_pubkey_hex,
            revocation_basepoint_hex: value.revocation_basepoint_hex,
            payment_point_hex: value.payment_point_hex,
            delayed_payment_basepoint_hex: value.delayed_payment_basepoint_hex,
            htlc_basepoint_hex: value.htlc_basepoint_hex,
        }
    }
}

impl From<ChannelHtlc> for ChannelHtlcV1 {
    fn from(value: ChannelHtlc) -> Self {
        Self {
            side: value.side as u32,
            amount_msat: value.amount_msat,
            payment_hash_hex: value.payment_hash_hex,
            cltv_expiry: value.cltv_expiry,
        }
    }
}

impl From<ChannelHtlcV1> for ChannelHtlc {
    fn from(value: ChannelHtlcV1) -> Self {
        Self {
            side: value.side as u8,
            amount_msat: value.amount_msat,
            payment_hash_hex: value.payment_hash_hex,
            cltv_expiry: value.cltv_expiry,
        }
    }
}

impl From<ChannelOp> for ChannelOpV1 {
    fn from(value: ChannelOp) -> Self {
        let kind = match value {
            ChannelOp::SetupChannel {
                is_outbound,
                channel_value_satoshis,
                push_value_msat,
                funding_txid_hex,
                funding_vout,
                holder_selected_contest_delay,
                counterparty_pubkeys,
                counterparty_selected_contest_delay,
                channel_type_kind,
            } => channel_op_v1::Kind::SetupChannel(SetupChannelV1 {
                is_outbound,
                channel_value_satoshis,
                push_value_msat,
                funding_txid_hex,
                funding_vout: funding_vout as u32,
                holder_selected_contest_delay: holder_selected_contest_delay as u32,
                counterparty_pubkeys: Some(counterparty_pubkeys.into()),
                counterparty_selected_contest_delay: counterparty_selected_contest_delay as u32,
                channel_type_kind: channel_type_kind as u32,
            }),
            ChannelOp::GetPerCommitmentPoint { idx } => {
                channel_op_v1::Kind::GetPerCommitmentPoint(ChannelIndexV1 { idx })
            }
            ChannelOp::ReleaseCommitmentSecret { idx } => {
                channel_op_v1::Kind::ReleaseCommitmentSecret(ChannelIndexV1 { idx })
            }
            ChannelOp::ValidateHolderCommitment {
                commitment_number,
                feerate_sat_per_kw,
                to_local_value_sat,
                to_remote_value_sat,
                htlcs,
                counterparty_signature_hex,
                counterparty_htlc_signatures_hex,
                commitment_unsigned_tx_hex,
                commitment_psbt_output_witness_scripts_hex,
            } => channel_op_v1::Kind::ValidateHolderCommitment(ValidateHolderCommitmentV1 {
                commitment_number,
                feerate_sat_per_kw,
                to_local_value_sat,
                to_remote_value_sat,
                htlcs: htlcs.into_iter().map(Into::into).collect(),
                counterparty_signature_hex,
                counterparty_htlc_signatures_hex,
                commitment_unsigned_tx_hex: commitment_unsigned_tx_hex.unwrap_or_default(),
                commitment_psbt_output_witness_scripts_hex:
                    commitment_psbt_output_witness_scripts_hex.unwrap_or_default(),
            }),
            ChannelOp::SignHolderCommitment {
                tx_hex,
                commitment_number,
            } => channel_op_v1::Kind::SignHolderCommitment(SignHolderCommitmentV1 {
                tx_hex,
                commitment_number,
            }),
            ChannelOp::SignCounterpartyCommitment {
                tx_hex,
                remote_per_commitment_point_hex,
                commitment_number,
                feerate_sat_per_kw,
                to_local_value_sat,
                to_remote_value_sat,
                htlcs,
                preimages_hex,
                commitment_psbt_output_witness_scripts_hex,
            } => channel_op_v1::Kind::SignCounterpartyCommitment(SignCounterpartyCommitmentV1 {
                tx_hex,
                remote_per_commitment_point_hex,
                commitment_number,
                feerate_sat_per_kw,
                to_local_value_sat,
                to_remote_value_sat,
                htlcs: htlcs.into_iter().map(Into::into).collect(),
                preimages_hex,
                commitment_psbt_output_witness_scripts_hex:
                    commitment_psbt_output_witness_scripts_hex.unwrap_or_default(),
            }),
            ChannelOp::SignClosingTransaction { tx_hex } => {
                channel_op_v1::Kind::SignClosingTransaction(SignClosingTransactionV1 { tx_hex })
            }
            ChannelOp::SignJusticeRevokedOutput {
                tx_hex,
                input,
                amount_sat,
                per_commitment_key_hex,
            } => channel_op_v1::Kind::SignJusticeRevokedOutput(SignJusticeRevokedOutputV1 {
                tx_hex,
                input,
                amount_sat,
                per_commitment_key_hex,
            }),
            ChannelOp::SignJusticeRevokedHtlc {
                tx_hex,
                input,
                amount_sat,
                per_commitment_key_hex,
                htlc_hex,
            } => channel_op_v1::Kind::SignJusticeRevokedHtlc(SignJusticeRevokedHtlcV1 {
                tx_hex,
                input,
                amount_sat,
                per_commitment_key_hex,
                htlc_hex,
            }),
            ChannelOp::SignHolderHtlcTransaction {
                tx_hex,
                input,
                htlc_descriptor_hex,
            } => channel_op_v1::Kind::SignHolderHtlcTransaction(SignHolderHtlcTransactionV1 {
                tx_hex,
                input,
                htlc_descriptor_hex,
            }),
            ChannelOp::SignCounterpartyHtlcTransaction {
                tx_hex,
                input,
                amount_sat,
                per_commitment_point_hex,
                htlc_descriptor_hex,
            } => channel_op_v1::Kind::SignCounterpartyHtlcTransaction(
                SignCounterpartyHtlcTransactionV1 {
                    tx_hex,
                    input,
                    amount_sat,
                    per_commitment_point_hex,
                    htlc_descriptor_hex,
                },
            ),
            ChannelOp::SignDynamicP2wshInput {
                tx_hex,
                input,
                descriptor_hex,
            } => channel_op_v1::Kind::SignDynamicP2wshInput(SignDynamicP2wshInputV1 {
                tx_hex,
                input,
                descriptor_hex,
            }),
            ChannelOp::SignCounterpartyPaymentInput {
                tx_hex,
                input,
                descriptor_hex,
            } => {
                channel_op_v1::Kind::SignCounterpartyPaymentInput(SignCounterpartyPaymentInputV1 {
                    tx_hex,
                    input,
                    descriptor_hex,
                })
            }
            ChannelOp::SignSplicingFundingInput {
                tx_hex,
                input,
                txin_descriptor_hex,
            } => channel_op_v1::Kind::SignSplicingFundingInput(SignSplicingFundingInputV1 {
                tx_hex,
                input,
                txin_descriptor_hex,
            }),
            ChannelOp::SignHolderAnchorInput {
                tx_hex,
                input,
                descriptor_hex,
            } => channel_op_v1::Kind::SignHolderAnchorInput(SignHolderAnchorInputV1 {
                tx_hex,
                input,
                descriptor_hex,
            }),
            ChannelOp::SignChannelAnnouncementWithFundingKey { msg_hex } => {
                channel_op_v1::Kind::SignChannelAnnouncementWithFundingKey(
                    SignChannelAnnouncementWithFundingKeyV1 { msg_hex },
                )
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<ChannelOpV1> for ChannelOp {
    type Error = RlnSignerError;
    fn try_from(value: ChannelOpV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("channel op")("missing kind"))?
        {
            channel_op_v1::Kind::SetupChannel(v) => Ok(Self::SetupChannel {
                is_outbound: v.is_outbound,
                channel_value_satoshis: v.channel_value_satoshis,
                push_value_msat: v.push_value_msat,
                funding_txid_hex: v.funding_txid_hex,
                funding_vout: v.funding_vout as u16,
                holder_selected_contest_delay: v.holder_selected_contest_delay as u16,
                counterparty_pubkeys: v
                    .counterparty_pubkeys
                    .ok_or_else(|| proto_err("setup_channel")("missing counterparty_pubkeys"))?
                    .into(),
                counterparty_selected_contest_delay: v.counterparty_selected_contest_delay as u16,
                channel_type_kind: v.channel_type_kind as u8,
            }),
            channel_op_v1::Kind::GetPerCommitmentPoint(v) => {
                Ok(Self::GetPerCommitmentPoint { idx: v.idx })
            }
            channel_op_v1::Kind::ReleaseCommitmentSecret(v) => {
                Ok(Self::ReleaseCommitmentSecret { idx: v.idx })
            }
            channel_op_v1::Kind::ValidateHolderCommitment(v) => {
                let commitment_unsigned_tx_hex = if v.commitment_unsigned_tx_hex.is_empty() {
                    None
                } else {
                    Some(v.commitment_unsigned_tx_hex)
                };
                let commitment_psbt_output_witness_scripts_hex =
                    if v.commitment_psbt_output_witness_scripts_hex.is_empty() {
                        None
                    } else {
                        Some(v.commitment_psbt_output_witness_scripts_hex)
                    };
                Ok(Self::ValidateHolderCommitment {
                    commitment_number: v.commitment_number,
                    feerate_sat_per_kw: v.feerate_sat_per_kw,
                    to_local_value_sat: v.to_local_value_sat,
                    to_remote_value_sat: v.to_remote_value_sat,
                    htlcs: v.htlcs.into_iter().map(Into::into).collect(),
                    counterparty_signature_hex: v.counterparty_signature_hex,
                    counterparty_htlc_signatures_hex: v.counterparty_htlc_signatures_hex,
                    commitment_unsigned_tx_hex,
                    commitment_psbt_output_witness_scripts_hex,
                })
            }
            channel_op_v1::Kind::SignHolderCommitment(v) => Ok(Self::SignHolderCommitment {
                tx_hex: v.tx_hex,
                commitment_number: v.commitment_number,
            }),
            channel_op_v1::Kind::SignCounterpartyCommitment(v) => {
                Ok(Self::SignCounterpartyCommitment {
                    tx_hex: v.tx_hex,
                    remote_per_commitment_point_hex: v.remote_per_commitment_point_hex,
                    commitment_number: v.commitment_number,
                    feerate_sat_per_kw: v.feerate_sat_per_kw,
                    to_local_value_sat: v.to_local_value_sat,
                    to_remote_value_sat: v.to_remote_value_sat,
                    htlcs: v.htlcs.into_iter().map(Into::into).collect(),
                    preimages_hex: v.preimages_hex,
                    commitment_psbt_output_witness_scripts_hex: if v
                        .commitment_psbt_output_witness_scripts_hex
                        .is_empty()
                    {
                        None
                    } else {
                        Some(v.commitment_psbt_output_witness_scripts_hex)
                    },
                })
            }
            channel_op_v1::Kind::SignClosingTransaction(v) => {
                Ok(Self::SignClosingTransaction { tx_hex: v.tx_hex })
            }
            channel_op_v1::Kind::SignJusticeRevokedOutput(v) => {
                Ok(Self::SignJusticeRevokedOutput {
                    tx_hex: v.tx_hex,
                    input: v.input,
                    amount_sat: v.amount_sat,
                    per_commitment_key_hex: v.per_commitment_key_hex,
                })
            }
            channel_op_v1::Kind::SignJusticeRevokedHtlc(v) => Ok(Self::SignJusticeRevokedHtlc {
                tx_hex: v.tx_hex,
                input: v.input,
                amount_sat: v.amount_sat,
                per_commitment_key_hex: v.per_commitment_key_hex,
                htlc_hex: v.htlc_hex,
            }),
            channel_op_v1::Kind::SignHolderHtlcTransaction(v) => {
                Ok(Self::SignHolderHtlcTransaction {
                    tx_hex: v.tx_hex,
                    input: v.input,
                    htlc_descriptor_hex: v.htlc_descriptor_hex,
                })
            }
            channel_op_v1::Kind::SignCounterpartyHtlcTransaction(v) => {
                Ok(Self::SignCounterpartyHtlcTransaction {
                    tx_hex: v.tx_hex,
                    input: v.input,
                    amount_sat: v.amount_sat,
                    per_commitment_point_hex: v.per_commitment_point_hex,
                    htlc_descriptor_hex: v.htlc_descriptor_hex,
                })
            }
            channel_op_v1::Kind::SignDynamicP2wshInput(v) => Ok(Self::SignDynamicP2wshInput {
                tx_hex: v.tx_hex,
                input: v.input,
                descriptor_hex: v.descriptor_hex,
            }),
            channel_op_v1::Kind::SignCounterpartyPaymentInput(v) => {
                Ok(Self::SignCounterpartyPaymentInput {
                    tx_hex: v.tx_hex,
                    input: v.input,
                    descriptor_hex: v.descriptor_hex,
                })
            }
            channel_op_v1::Kind::SignSplicingFundingInput(v) => {
                Ok(Self::SignSplicingFundingInput {
                    tx_hex: v.tx_hex,
                    input: v.input,
                    txin_descriptor_hex: v.txin_descriptor_hex,
                })
            }
            channel_op_v1::Kind::SignHolderAnchorInput(v) => Ok(Self::SignHolderAnchorInput {
                tx_hex: v.tx_hex,
                input: v.input,
                descriptor_hex: v.descriptor_hex,
            }),
            channel_op_v1::Kind::SignChannelAnnouncementWithFundingKey(v) => {
                Ok(Self::SignChannelAnnouncementWithFundingKey { msg_hex: v.msg_hex })
            }
        }
    }
}

impl From<ChannelRequest> for ChannelRequestV1 {
    fn from(value: ChannelRequest) -> Self {
        let kind = match value {
            ChannelRequest::GenerateChannelKeysId {
                inbound,
                channel_value_satoshis,
                user_channel_id,
            } => channel_request_v1::Kind::GenerateChannelKeysId(GenerateChannelKeysIdV1 {
                inbound,
                channel_value_satoshis,
                user_channel_id_be: encode_u128_be(user_channel_id),
            }),
            ChannelRequest::DeriveChannelSigner {
                channel_value_satoshis,
                channel_keys_id_hex,
            } => channel_request_v1::Kind::DeriveChannelSigner(DeriveChannelSignerV1 {
                channel_value_satoshis,
                channel_keys_id_hex,
            }),
            ChannelRequest::ReadChannelSigner {
                channel_signer_state_hex,
            } => channel_request_v1::Kind::ReadChannelSigner(ReadChannelSignerV1 {
                channel_signer_state_hex,
            }),
            ChannelRequest::Op {
                channel_keys_id_hex,
                op,
            } => channel_request_v1::Kind::Op(ChannelOpRequestV1 {
                channel_keys_id_hex,
                op: Some(op.into()),
            }),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<ChannelRequestV1> for ChannelRequest {
    type Error = RlnSignerError;
    fn try_from(value: ChannelRequestV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("channel request")("missing kind"))?
        {
            channel_request_v1::Kind::GenerateChannelKeysId(v) => Ok(Self::GenerateChannelKeysId {
                inbound: v.inbound,
                channel_value_satoshis: v.channel_value_satoshis,
                user_channel_id: decode_u128_be(&v.user_channel_id_be)?,
            }),
            channel_request_v1::Kind::DeriveChannelSigner(v) => Ok(Self::DeriveChannelSigner {
                channel_value_satoshis: v.channel_value_satoshis,
                channel_keys_id_hex: v.channel_keys_id_hex,
            }),
            channel_request_v1::Kind::ReadChannelSigner(v) => Ok(Self::ReadChannelSigner {
                channel_signer_state_hex: v.channel_signer_state_hex,
            }),
            channel_request_v1::Kind::Op(v) => Ok(Self::Op {
                channel_keys_id_hex: v.channel_keys_id_hex,
                op: v
                    .op
                    .ok_or_else(|| proto_err("channel op request")("missing op"))?
                    .try_into()?,
            }),
        }
    }
}

impl From<ChannelResponse> for ChannelResponseV1 {
    fn from(value: ChannelResponse) -> Self {
        let kind = match value {
            ChannelResponse::GeneratedChannelKeysId {
                channel_keys_id_hex,
            } => channel_response_v1::Kind::GeneratedChannelKeysId(GeneratedChannelKeysIdV1 {
                channel_keys_id_hex,
            }),
            ChannelResponse::SetupComplete => channel_response_v1::Kind::SetupComplete(EmptyV1 {}),
            ChannelResponse::ValidationComplete => {
                channel_response_v1::Kind::ValidationComplete(EmptyV1 {})
            }
            ChannelResponse::ChannelSignerData {
                channel_signer_state_hex,
                channel_pubkeys,
            } => channel_response_v1::Kind::ChannelSignerData(ChannelSignerDataV1 {
                channel_signer_state_hex,
                channel_pubkeys: Some(channel_pubkeys.into()),
            }),
            ChannelResponse::PerCommitmentPoint { point_hex } => {
                channel_response_v1::Kind::PerCommitmentPoint(PerCommitmentPointV1 { point_hex })
            }
            ChannelResponse::CommitmentSecret { secret_hex } => {
                channel_response_v1::Kind::CommitmentSecret(CommitmentSecretV1 { secret_hex })
            }
            ChannelResponse::Signature { signature_hex } => {
                channel_response_v1::Kind::Signature(SignatureV1 { signature_hex })
            }
            ChannelResponse::SignatureWithHtlcs {
                signature_hex,
                htlc_signatures_hex,
            } => channel_response_v1::Kind::SignatureWithHtlcs(SignatureWithHtlcsV1 {
                signature_hex,
                htlc_signatures_hex,
            }),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<ChannelResponseV1> for ChannelResponse {
    type Error = RlnSignerError;
    fn try_from(value: ChannelResponseV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("channel response")("missing kind"))?
        {
            channel_response_v1::Kind::GeneratedChannelKeysId(v) => {
                Ok(Self::GeneratedChannelKeysId {
                    channel_keys_id_hex: v.channel_keys_id_hex,
                })
            }
            channel_response_v1::Kind::SetupComplete(_) => Ok(Self::SetupComplete),
            channel_response_v1::Kind::ValidationComplete(_) => Ok(Self::ValidationComplete),
            channel_response_v1::Kind::ChannelSignerData(v) => Ok(Self::ChannelSignerData {
                channel_signer_state_hex: v.channel_signer_state_hex,
                channel_pubkeys: v
                    .channel_pubkeys
                    .ok_or_else(|| proto_err("channel signer data")("missing channel_pubkeys"))?
                    .into(),
            }),
            channel_response_v1::Kind::PerCommitmentPoint(v) => Ok(Self::PerCommitmentPoint {
                point_hex: v.point_hex,
            }),
            channel_response_v1::Kind::CommitmentSecret(v) => Ok(Self::CommitmentSecret {
                secret_hex: v.secret_hex,
            }),
            channel_response_v1::Kind::Signature(v) => Ok(Self::Signature {
                signature_hex: v.signature_hex,
            }),
            channel_response_v1::Kind::SignatureWithHtlcs(v) => Ok(Self::SignatureWithHtlcs {
                signature_hex: v.signature_hex,
                htlc_signatures_hex: v.htlc_signatures_hex,
            }),
        }
    }
}

impl From<SignerRequest> for SignerRequestV1 {
    fn from(value: SignerRequest) -> Self {
        let kind = match value {
            SignerRequest::Bootstrap => signer_request_v1::Kind::Bootstrap(EmptyV1 {}),
            SignerRequest::Node(v) => signer_request_v1::Kind::Node(v.into()),
            SignerRequest::Channel(v) => signer_request_v1::Kind::Channel(v.into()),
            SignerRequest::SignSpendableOutputsPsbt { inputs, psbt } => {
                signer_request_v1::Kind::SignSpendableOutputsPsbt(
                    SignSpendableOutputsPsbtRequestV1 {
                        inputs: inputs.into_iter().map(Into::into).collect(),
                        psbt,
                    },
                )
            }
            SignerRequest::SignRgbPsbt { descriptors, psbt } => {
                signer_request_v1::Kind::SignRgbPsbt(SignPsbtRequestV1 { descriptors, psbt })
            }
            SignerRequest::GetWalletInputMetadata {
                txid_hex,
                vout,
                script_pubkey_hex,
                amount_sat,
            } => signer_request_v1::Kind::GetWalletInputMetadata(GetWalletInputMetadataRequestV1 {
                txid_hex,
                vout,
                script_pubkey_hex,
                amount_sat,
            }),
            SignerRequest::FindDerivationMatches {
                script_pubkey_hex,
                max_index,
            } => signer_request_v1::Kind::FindDerivationMatches(FindDerivationMatchesRequestV1 {
                script_pubkey_hex,
                max_index,
            }),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<SignerRequestV1> for SignerRequest {
    type Error = RlnSignerError;
    fn try_from(value: SignerRequestV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("signer request")("missing kind"))?
        {
            signer_request_v1::Kind::Bootstrap(_) => Ok(Self::Bootstrap),
            signer_request_v1::Kind::Node(v) => Ok(Self::Node(v.try_into()?)),
            signer_request_v1::Kind::Channel(v) => Ok(Self::Channel(v.try_into()?)),
            signer_request_v1::Kind::SignSpendableOutputsPsbt(v) => {
                Ok(Self::SignSpendableOutputsPsbt {
                    inputs: v
                        .inputs
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()?,
                    psbt: v.psbt,
                })
            }
            signer_request_v1::Kind::SignRgbPsbt(v) => Ok(Self::SignRgbPsbt {
                descriptors: v.descriptors,
                psbt: v.psbt,
            }),
            signer_request_v1::Kind::GetWalletInputMetadata(v) => {
                Ok(Self::GetWalletInputMetadata {
                    txid_hex: v.txid_hex,
                    vout: v.vout,
                    script_pubkey_hex: v.script_pubkey_hex,
                    amount_sat: v.amount_sat,
                })
            }
            signer_request_v1::Kind::FindDerivationMatches(v) => Ok(Self::FindDerivationMatches {
                script_pubkey_hex: v.script_pubkey_hex,
                max_index: v.max_index,
            }),
        }
    }
}

impl From<SignerResponse> for SignerResponseV1 {
    fn from(value: SignerResponse) -> Self {
        let kind = match value {
            SignerResponse::Bootstrap(v) => signer_response_v1::Kind::Bootstrap(v.into()),
            SignerResponse::Node(v) => signer_response_v1::Kind::Node(v.into()),
            SignerResponse::Channel(v) => signer_response_v1::Kind::Channel(v.into()),
            SignerResponse::SignedPsbt { psbt } => {
                signer_response_v1::Kind::SignedPsbt(SignedPsbtV1 { psbt })
            }
            SignerResponse::WalletInputMetadata { metadata } => {
                signer_response_v1::Kind::WalletInputMetadata(WalletInputMetadataResponseV1 {
                    metadata: metadata.map(Into::into),
                })
            }
            SignerResponse::FindDerivationMatches { matches } => {
                signer_response_v1::Kind::FindDerivationMatches(FindDerivationMatchesResponseV1 {
                    matches: matches.into_iter().map(Into::into).collect(),
                })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<SignerResponseV1> for SignerResponse {
    type Error = RlnSignerError;
    fn try_from(value: SignerResponseV1) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| proto_err("signer response")("missing kind"))?
        {
            signer_response_v1::Kind::Bootstrap(v) => Ok(Self::Bootstrap(v.try_into()?)),
            signer_response_v1::Kind::Node(v) => Ok(Self::Node(v.try_into()?)),
            signer_response_v1::Kind::Channel(v) => Ok(Self::Channel(v.try_into()?)),
            signer_response_v1::Kind::SignedPsbt(v) => Ok(Self::SignedPsbt { psbt: v.psbt }),
            signer_response_v1::Kind::WalletInputMetadata(v) => Ok(Self::WalletInputMetadata {
                metadata: v.metadata.map(Into::into),
            }),
            signer_response_v1::Kind::FindDerivationMatches(v) => Ok(Self::FindDerivationMatches {
                matches: v.matches.into_iter().map(Into::into).collect(),
            }),
        }
    }
}

fn encode_envelope<M: Message>(payload: &M) -> Result<Vec<u8>, RlnSignerError> {
    let mut inner = Vec::with_capacity(payload.encoded_len());
    payload
        .encode(&mut inner)
        .map_err(|e| RlnSignerError::Protocol(format!("encode protobuf payload failed: {e}")))?;
    let envelope = SignerEnvelope {
        version: ENVELOPE_VERSION_V1,
        payload_encoding: ENCODING_PROTOBUF_V1,
        payload: inner,
    };
    let mut out = Vec::with_capacity(envelope.encoded_len());
    envelope
        .encode(&mut out)
        .map_err(|e| RlnSignerError::Protocol(format!("encode protobuf envelope failed: {e}")))?;
    Ok(out)
}

fn decode_envelope<M: Message + Default>(wire_payload: &[u8]) -> Result<M, RlnSignerError> {
    let envelope = SignerEnvelope::decode(wire_payload)
        .map_err(|e| RlnSignerError::Protocol(format!("decode protobuf envelope failed: {e}")))?;
    if envelope.version != ENVELOPE_VERSION_V1 {
        return Err(RlnSignerError::Protocol(format!(
            "unsupported signer envelope version: {}",
            envelope.version
        )));
    }
    if envelope.payload_encoding != ENCODING_PROTOBUF_V1 {
        return Err(RlnSignerError::Protocol(format!(
            "unsupported signer payload encoding: {}",
            envelope.payload_encoding
        )));
    }
    M::decode(envelope.payload.as_slice())
        .map_err(|e| RlnSignerError::Protocol(format!("decode protobuf payload failed: {e}")))
}

pub(crate) fn encode_signer_request(request: &SignerRequest) -> Result<Vec<u8>, RlnSignerError> {
    encode_envelope(&SignerRequestV1::from(request.clone()))
}

#[allow(dead_code)]
pub(crate) fn decode_signer_request(wire_payload: &[u8]) -> Result<SignerRequest, RlnSignerError> {
    let payload: SignerRequestV1 = decode_envelope(wire_payload)?;
    payload.try_into()
}

#[allow(dead_code)]
pub(crate) fn encode_signer_response(response: &SignerResponse) -> Result<Vec<u8>, RlnSignerError> {
    encode_envelope(&SignerResponseV1::from(response.clone()))
}

pub(crate) fn decode_signer_response(
    wire_payload: &[u8],
) -> Result<SignerResponse, RlnSignerError> {
    let payload: SignerResponseV1 = decode_envelope(wire_payload)?;
    payload.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let request = SignerRequest::Node(NodeRequest::SignMessage {
            message: "hello".to_string(),
        });
        let wire = encode_signer_request(&request).expect("encode");
        let decoded = decode_signer_request(&wire).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn response_roundtrip() {
        let response = SignerResponse::Bootstrap(BootstrapData {
            identity: SignerIdentity {
                node_id: "02".repeat(33),
                account_xpub_vanilla: "xpub-v".to_string(),
                account_xpub_colored: "xpub-c".to_string(),
                master_fingerprint: "deadbeef".to_string(),
            },
            protocol_version: "1".to_string(),
            api_level: 1,
        });
        let wire = encode_signer_response(&response).expect("encode");
        let decoded = decode_signer_response(&wire).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn channel_op_validate_holder_commitment_with_wire_tx_roundtrip() {
        let request = SignerRequest::Channel(ChannelRequest::Op {
            channel_keys_id_hex: "11".repeat(32),
            op: ChannelOp::ValidateHolderCommitment {
                commitment_number: 42,
                feerate_sat_per_kw: 253,
                to_local_value_sat: 100_000,
                to_remote_value_sat: 200_000,
                htlcs: vec![],
                counterparty_signature_hex: "ab".repeat(64),
                counterparty_htlc_signatures_hex: vec![],
                commitment_unsigned_tx_hex: Some("01000000000100".to_string()),
                commitment_psbt_output_witness_scripts_hex: None,
            },
        });
        let wire = encode_signer_request(&request).expect("encode");
        let decoded = decode_signer_request(&wire).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn channel_op_sign_channel_announcement_roundtrip() {
        let request = SignerRequest::Channel(ChannelRequest::Op {
            channel_keys_id_hex: "11".repeat(32),
            op: ChannelOp::SignChannelAnnouncementWithFundingKey {
                msg_hex: "aa55".repeat(16),
            },
        });
        let wire = encode_signer_request(&request).expect("encode");
        let decoded = decode_signer_request(&wire).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn channel_response_signature_with_htlcs_roundtrip() {
        let response = SignerResponse::Channel(ChannelResponse::SignatureWithHtlcs {
            signature_hex: "30".repeat(64),
            htlc_signatures_hex: vec!["31".repeat(64), "32".repeat(64)],
        });
        let wire = encode_signer_response(&response).expect("encode");
        let decoded = decode_signer_response(&wire).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn sign_spendable_outputs_psbt_roundtrip() {
        let request = SignerRequest::SignSpendableOutputsPsbt {
            inputs: vec![SpendableOutputSignInput {
                descriptor_kind: SpendableDescriptorKind::StaticOutput,
                txid_hex: "aa".repeat(32),
                vout: 1,
                amount_sat: 50_000,
                script_pubkey_hex: String::new(),
                channel_keys_id_hex: None,
                wallet_derivation_match: Some(WalletDerivationMatch {
                    account_name: "vanilla".to_string(),
                    keyindex: 0,
                    derivation_path: "0/0".to_string(),
                }),
                witness_script_hex: None,
                redeem_script_hex: None,
                per_commitment_point_hex: None,
                to_self_delay: None,
            }],
            psbt: "psbt-here".to_string(),
        };
        let wire = encode_signer_request(&request).expect("encode");
        let decoded = decode_signer_request(&wire).expect("decode");
        assert_eq!(decoded, request);
    }
}
