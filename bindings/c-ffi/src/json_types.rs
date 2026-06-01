//! JSON-friendly mirror types for the FFI boundary.
//!
//! UniFFI request/response types in [`rgb_lightning_node::uniffi_api::types`]
//! use opaque wrappers (`PublicKey`, `Txid`, `ContractId`, `ChannelId`,
//! `PaymentHash`, `Bolt11Invoice`) that don't implement
//! `serde::{Serialize,Deserialize}`. To keep the c-ffi self-contained without
//! requiring upstream serde derives, we define mirror types here that use
//! `String` (hex / bech32 / typed string forms) for those fields, plus
//! `TryFrom`/`From` conversions that parse and unparse via the types' own
//! `FromStr` / `Display` impls.

use std::str::FromStr;

use hex::DisplayHex;
use hex::FromHex;
use rgb_lightning_node::{
    AddressInfo, AssetBalanceInfo, AssetCfa, AssetIfa, AssetMediaResponse, AssetMetadataInfo,
    AssetNia, AssetUda, AssignmentKind, BlockTime, BtcBalance, BtcBalanceInfo,
    CancelHodlInvoiceRequest, Channel, ChannelId, ChannelStatus, CheckIndexerUrlResponse,
    ClaimHodlInvoiceRequest, ClaimHodlInvoiceResponse, ContractId, DecodeLnInvoiceResponse,
    DecodeRgbInvoiceResponse, EmbeddedMedia, EstimateFeeResponse, HtlcStatus, InflateRequest,
    InflateResponse, InvoiceStatus, ListAssetsResponse, LnInvoiceRequest, LnInvoiceResponse, Media,
    MediaAttachment, NetworkInfo, NodeInfo, Payment, PaymentHash, PaymentType, Peer, ProofOfReserves,
    PublicKey, RecipientId, RgbAllocation, SdkCloseChannelRequest, SdkCreateUtxosRequest,
    SdkDisconnectPeerRequest, SdkFailTransfersRequest, SdkFailTransfersResponse, SdkInitRequest,
    SdkIssueAssetCfaRequest, SdkIssueAssetIfaRequest, SdkIssueAssetNiaRequest,
    SdkIssueAssetUdaRequest, SdkKeysendRequest, SdkKeysendResponse, SdkMakerExecuteRequest,
    SdkMakerInitRequest, SdkMakerInitResponse, SdkOpenChannelRequest, SdkOpenChannelResponse,
    SdkPostAssetMediaRequest, SdkPostAssetMediaResponse, SdkRefreshTransfersRequest,
    SdkRgbInvoiceRequest, SdkRgbInvoiceResponse, SdkSendBtcRequest, SdkSendBtcResponse,
    SdkExternalSignerBootstrap, SdkSendOnionMessageRequest, SdkSendPaymentRequest,
    SdkSendPaymentResponse, SdkTakerRequest, SdkUnlockRequest, SendRgbRequest, SendRgbResponse,
    AssetRecipients, RgbRecipient,
    SignMessageResponse, Swap, SwapList, SwapStatus, Token, TokenLight, Transaction,
    TransactionType, Transfer, TransferTransportEndpoint, TransportEndpoint, Txid, Unspent, Utxo,
    WitnessData,
};
use serde::{Deserialize, Serialize};

use crate::utils::Error;

// ---------------------------------------------------------------------------
// String-parse helpers
// ---------------------------------------------------------------------------

fn parse_pubkey(s: &str) -> Result<PublicKey, Error> {
    PublicKey::from_str(s).map_err(|e| Error::StringParse(format!("invalid pubkey: {e}")))
}

fn parse_contract_id(s: &str) -> Result<ContractId, Error> {
    ContractId::from_str(s).map_err(|e| Error::StringParse(format!("invalid contract id: {e}")))
}

fn parse_32_hex(s: &str) -> Result<[u8; 32], Error> {
    let bytes =
        Vec::<u8>::from_hex(s).map_err(|e| Error::HexConversion(format!("not hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::HexConversion(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_channel_id(s: &str) -> Result<ChannelId, Error> {
    Ok(lightning::ln::types::ChannelId(parse_32_hex(s)?))
}

fn parse_payment_hash(s: &str) -> Result<PaymentHash, Error> {
    Ok(lightning::types::payment::PaymentHash(parse_32_hex(s)?))
}

fn fmt_channel_id(c: &ChannelId) -> String {
    c.0.as_hex().to_string()
}

fn fmt_payment_hash(h: &PaymentHash) -> String {
    h.0.as_hex().to_string()
}

fn fmt_pubkey(p: &PublicKey) -> String {
    p.to_string()
}

fn fmt_txid(t: &Txid) -> String {
    t.to_string()
}

fn fmt_contract_id(c: &ContractId) -> String {
    c.to_string()
}

fn parse_assignment_kind(s: &str) -> Result<AssignmentKind, Error> {
    match s {
        "Fungible" | "fungible" => Ok(AssignmentKind::Fungible),
        "NonFungible" | "non_fungible" | "nonFungible" => Ok(AssignmentKind::NonFungible),
        "InflationRight" | "inflation_right" | "inflationRight" => {
            Ok(AssignmentKind::InflationRight)
        }
        "ReplaceRight" | "replace_right" | "replaceRight" => Ok(AssignmentKind::ReplaceRight),
        "Any" | "any" => Ok(AssignmentKind::Any),
        _ => Err(Error::StringParse(format!("invalid assignment kind: {s}"))),
    }
}

// ---------------------------------------------------------------------------
// Init / Unlock requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonSdkInitRequest {
    pub storage_dir_path: String,
    pub daemon_listening_port: u16,
    pub ldk_peer_listening_port: u16,
    pub network: String,
    pub max_media_upload_size_mb: u16,
    #[serde(default)]
    pub enable_virtual_channels_v0: Option<bool>,
    #[serde(default)]
    pub virtual_peer_pubkeys: Option<Vec<String>>,
    #[serde(default)]
    pub lsp_base_url: Option<String>,
    #[serde(default)]
    pub lsp_bearer_token: Option<String>,
}

impl TryFrom<JsonSdkInitRequest> for SdkInitRequest {
    type Error = Error;
    fn try_from(j: JsonSdkInitRequest) -> Result<Self, Self::Error> {
        let virtual_peer_pubkeys = j
            .virtual_peer_pubkeys
            .map(|v| v.iter().map(|s| parse_pubkey(s)).collect::<Result<Vec<_>, _>>())
            .transpose()?;
        Ok(SdkInitRequest {
            storage_dir_path: j.storage_dir_path,
            daemon_listening_port: j.daemon_listening_port,
            ldk_peer_listening_port: j.ldk_peer_listening_port,
            network: j.network,
            max_media_upload_size_mb: j.max_media_upload_size_mb,
            enable_virtual_channels_v0: j.enable_virtual_channels_v0,
            virtual_peer_pubkeys,
            lsp_base_url: j.lsp_base_url,
            lsp_bearer_token: j.lsp_bearer_token,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonSdkUnlockRequest {
    pub password: String,
    pub bitcoind_rpc_username: String,
    pub bitcoind_rpc_password: String,
    pub bitcoind_rpc_host: String,
    pub bitcoind_rpc_port: u16,
    #[serde(default)]
    pub indexer_url: Option<String>,
    #[serde(default)]
    pub proxy_endpoint: Option<String>,
    #[serde(default)]
    pub announce_addresses: Vec<String>,
    #[serde(default)]
    pub announce_alias: Option<String>,
}

impl From<JsonSdkUnlockRequest> for SdkUnlockRequest {
    fn from(j: JsonSdkUnlockRequest) -> Self {
        SdkUnlockRequest {
            password: j.password,
            bitcoind_rpc_username: j.bitcoind_rpc_username,
            bitcoind_rpc_password: j.bitcoind_rpc_password,
            bitcoind_rpc_host: j.bitcoind_rpc_host,
            bitcoind_rpc_port: j.bitcoind_rpc_port,
            indexer_url: j.indexer_url,
            proxy_endpoint: j.proxy_endpoint,
            announce_addresses: j.announce_addresses,
            announce_alias: j.announce_alias,
        }
    }
}

// External-signer mode has no password: the seed never reaches RLN.
#[derive(Debug, Deserialize)]
pub(crate) struct JsonSdkExternalUnlockRequest {
    pub bitcoind_rpc_username: String,
    pub bitcoind_rpc_password: String,
    pub bitcoind_rpc_host: String,
    pub bitcoind_rpc_port: u16,
    #[serde(default)]
    pub indexer_url: Option<String>,
    #[serde(default)]
    pub proxy_endpoint: Option<String>,
    #[serde(default)]
    pub announce_addresses: Vec<String>,
    #[serde(default)]
    pub announce_alias: Option<String>,
}

// Bidirectional: Serialize for native-signer output, Deserialize for a host
// passing a raw bootstrap dict into `init_with_external_signer`.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonSdkExternalSignerBootstrap {
    pub node_id: String,
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub master_fingerprint: String,
    pub protocol_version: String,
    pub api_level: u32,
}

impl From<SdkExternalSignerBootstrap> for JsonSdkExternalSignerBootstrap {
    fn from(b: SdkExternalSignerBootstrap) -> Self {
        Self {
            node_id: b.node_id,
            account_xpub_vanilla: b.account_xpub_vanilla,
            account_xpub_colored: b.account_xpub_colored,
            master_fingerprint: b.master_fingerprint,
            protocol_version: b.protocol_version,
            api_level: b.api_level,
        }
    }
}

impl From<JsonSdkExternalSignerBootstrap> for SdkExternalSignerBootstrap {
    fn from(j: JsonSdkExternalSignerBootstrap) -> Self {
        Self {
            node_id: j.node_id,
            account_xpub_vanilla: j.account_xpub_vanilla,
            account_xpub_colored: j.account_xpub_colored,
            master_fingerprint: j.master_fingerprint,
            protocol_version: j.protocol_version,
            api_level: j.api_level,
        }
    }
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonOpenChannelRequest {
    pub peer_pubkey_and_opt_addr: String,
    pub capacity_sat: u64,
    pub push_msat: u64,
    pub public: bool,
    pub with_anchors: bool,
    #[serde(default)]
    pub fee_base_msat: Option<u32>,
    #[serde(default)]
    pub fee_proportional_millionths: Option<u32>,
    #[serde(default)]
    pub temporary_channel_id: Option<String>,
    #[serde(default)]
    pub asset_id: Option<String>,
    #[serde(default)]
    pub asset_amount: Option<u64>,
    #[serde(default)]
    pub push_asset_amount: Option<u64>,
    #[serde(default)]
    pub virtual_open_mode: Option<String>,
}

impl TryFrom<JsonOpenChannelRequest> for SdkOpenChannelRequest {
    type Error = Error;
    fn try_from(j: JsonOpenChannelRequest) -> Result<Self, Self::Error> {
        Ok(SdkOpenChannelRequest {
            peer_pubkey_and_opt_addr: j.peer_pubkey_and_opt_addr,
            capacity_sat: j.capacity_sat,
            push_msat: j.push_msat,
            public: j.public,
            with_anchors: j.with_anchors,
            fee_base_msat: j.fee_base_msat,
            fee_proportional_millionths: j.fee_proportional_millionths,
            temporary_channel_id: j
                .temporary_channel_id
                .map(|s| parse_channel_id(&s))
                .transpose()?,
            asset_id: j.asset_id.map(|s| parse_contract_id(&s)).transpose()?,
            asset_amount: j.asset_amount,
            push_asset_amount: j.push_asset_amount,
            virtual_open_mode: j.virtual_open_mode,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonOpenChannelResponse {
    pub temporary_channel_id: String,
}

impl From<SdkOpenChannelResponse> for JsonOpenChannelResponse {
    fn from(r: SdkOpenChannelResponse) -> Self {
        JsonOpenChannelResponse {
            temporary_channel_id: fmt_channel_id(&r.temporary_channel_id),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonCloseChannelRequest {
    pub channel_id: String,
    pub peer_pubkey: String,
    pub force: bool,
}

impl TryFrom<JsonCloseChannelRequest> for SdkCloseChannelRequest {
    type Error = Error;
    fn try_from(j: JsonCloseChannelRequest) -> Result<Self, Self::Error> {
        Ok(SdkCloseChannelRequest {
            channel_id: parse_channel_id(&j.channel_id)?,
            peer_pubkey: parse_pubkey(&j.peer_pubkey)?,
            force: j.force,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonDisconnectPeerRequest {
    pub peer_pubkey: String,
}

impl TryFrom<JsonDisconnectPeerRequest> for SdkDisconnectPeerRequest {
    type Error = Error;
    fn try_from(j: JsonDisconnectPeerRequest) -> Result<Self, Self::Error> {
        Ok(SdkDisconnectPeerRequest {
            peer_pubkey: parse_pubkey(&j.peer_pubkey)?,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonChannel {
    pub channel_id: String,
    pub peer_pubkey: String,
    pub status: ChannelStatusStr,
    pub ready: bool,
    pub capacity_sat: u64,
    pub local_balance_sat: u64,
    pub outbound_balance_msat: u64,
    pub inbound_balance_msat: u64,
    pub next_outbound_htlc_limit_msat: u64,
    pub next_outbound_htlc_minimum_msat: u64,
    pub is_usable: bool,
    pub public: bool,
    pub funding_txid: Option<String>,
    pub peer_alias: Option<String>,
    pub short_channel_id: Option<u64>,
    pub asset_id: Option<String>,
    pub asset_local_amount: Option<u64>,
    pub asset_remote_amount: Option<u64>,
    pub virtual_open_mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) enum ChannelStatusStr {
    Opening,
    Opened,
    Closing,
}

impl From<ChannelStatus> for ChannelStatusStr {
    fn from(s: ChannelStatus) -> Self {
        match s {
            ChannelStatus::Opening => ChannelStatusStr::Opening,
            ChannelStatus::Opened => ChannelStatusStr::Opened,
            ChannelStatus::Closing => ChannelStatusStr::Closing,
        }
    }
}

impl From<Channel> for JsonChannel {
    fn from(c: Channel) -> Self {
        JsonChannel {
            channel_id: fmt_channel_id(&c.channel_id),
            peer_pubkey: fmt_pubkey(&c.peer_pubkey),
            status: c.status.into(),
            ready: c.ready,
            capacity_sat: c.capacity_sat,
            local_balance_sat: c.local_balance_sat,
            outbound_balance_msat: c.outbound_balance_msat,
            inbound_balance_msat: c.inbound_balance_msat,
            next_outbound_htlc_limit_msat: c.next_outbound_htlc_limit_msat,
            next_outbound_htlc_minimum_msat: c.next_outbound_htlc_minimum_msat,
            is_usable: c.is_usable,
            public: c.public,
            funding_txid: c.funding_txid.as_ref().map(fmt_txid),
            peer_alias: c.peer_alias,
            short_channel_id: c.short_channel_id,
            asset_id: c.asset_id.as_ref().map(fmt_contract_id),
            asset_local_amount: c.asset_local_amount,
            asset_remote_amount: c.asset_remote_amount,
            virtual_open_mode: c.virtual_open_mode,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonPeer {
    pub pubkey: String,
}

impl From<Peer> for JsonPeer {
    fn from(p: Peer) -> Self {
        JsonPeer {
            pubkey: fmt_pubkey(&p.pubkey),
        }
    }
}

// ---------------------------------------------------------------------------
// Payments / invoices
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonSendPaymentRequest {
    pub invoice: String,
    #[serde(default)]
    pub amt_msat: Option<u64>,
    #[serde(default)]
    pub asset_id: Option<String>,
    #[serde(default)]
    pub asset_amount: Option<u64>,
}

impl TryFrom<JsonSendPaymentRequest> for SdkSendPaymentRequest {
    type Error = Error;
    fn try_from(j: JsonSendPaymentRequest) -> Result<Self, Self::Error> {
        Ok(SdkSendPaymentRequest {
            invoice: j.invoice,
            amt_msat: j.amt_msat,
            asset_id: j.asset_id.map(|s| parse_contract_id(&s)).transpose()?,
            asset_amount: j.asset_amount,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonSendPaymentResponse {
    pub payment_id: String,
    pub payment_hash: Option<String>,
    pub payment_secret: Option<String>,
    pub status: HtlcStatusStr,
}

impl From<SdkSendPaymentResponse> for JsonSendPaymentResponse {
    fn from(r: SdkSendPaymentResponse) -> Self {
        JsonSendPaymentResponse {
            payment_id: r.payment_id,
            payment_hash: r.payment_hash.as_ref().map(fmt_payment_hash),
            payment_secret: r.payment_secret,
            status: r.status.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonKeysendRequest {
    pub dest_pubkey: String,
    pub amt_msat: u64,
    #[serde(default)]
    pub asset_id: Option<String>,
    #[serde(default)]
    pub asset_amount: Option<u64>,
}

impl TryFrom<JsonKeysendRequest> for SdkKeysendRequest {
    type Error = Error;
    fn try_from(j: JsonKeysendRequest) -> Result<Self, Self::Error> {
        Ok(SdkKeysendRequest {
            dest_pubkey: parse_pubkey(&j.dest_pubkey)?,
            amt_msat: j.amt_msat,
            asset_id: j.asset_id.map(|s| parse_contract_id(&s)).transpose()?,
            asset_amount: j.asset_amount,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonKeysendResponse {
    pub payment_hash: String,
    pub payment_preimage: String,
    pub status: HtlcStatusStr,
}

impl From<SdkKeysendResponse> for JsonKeysendResponse {
    fn from(r: SdkKeysendResponse) -> Self {
        JsonKeysendResponse {
            payment_hash: fmt_payment_hash(&r.payment_hash),
            payment_preimage: r.payment_preimage,
            status: r.status.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) enum HtlcStatusStr {
    Pending,
    Claimable,
    Claiming,
    Succeeded,
    Cancelled,
    Failed,
}

impl From<HtlcStatus> for HtlcStatusStr {
    fn from(s: HtlcStatus) -> Self {
        match s {
            HtlcStatus::Pending => HtlcStatusStr::Pending,
            HtlcStatus::Claimable => HtlcStatusStr::Claimable,
            HtlcStatus::Claiming => HtlcStatusStr::Claiming,
            HtlcStatus::Succeeded => HtlcStatusStr::Succeeded,
            HtlcStatus::Cancelled => HtlcStatusStr::Cancelled,
            HtlcStatus::Failed => HtlcStatusStr::Failed,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum PaymentTypeStr {
    Outbound,
    InboundAutoClaim,
    InboundHodl,
}

impl From<PaymentTypeStr> for PaymentType {
    fn from(s: PaymentTypeStr) -> Self {
        match s {
            PaymentTypeStr::Outbound => PaymentType::Outbound,
            PaymentTypeStr::InboundAutoClaim => PaymentType::InboundAutoClaim,
            PaymentTypeStr::InboundHodl => PaymentType::InboundHodl,
        }
    }
}

impl From<PaymentType> for PaymentTypeStr {
    fn from(s: PaymentType) -> Self {
        match s {
            PaymentType::Outbound => PaymentTypeStr::Outbound,
            PaymentType::InboundAutoClaim => PaymentTypeStr::InboundAutoClaim,
            PaymentType::InboundHodl => PaymentTypeStr::InboundHodl,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonPayment {
    pub amt_msat: Option<u64>,
    pub asset_amount: Option<u64>,
    pub asset_id: Option<String>,
    pub payment_hash: String,
    pub payment_type: PaymentTypeStr,
    pub status: HtlcStatusStr,
    pub created_at: u64,
    pub updated_at: u64,
    pub payee_pubkey: String,
    pub preimage: Option<String>,
}

impl From<Payment> for JsonPayment {
    fn from(p: Payment) -> Self {
        JsonPayment {
            amt_msat: p.amt_msat,
            asset_amount: p.asset_amount,
            asset_id: p.asset_id.as_ref().map(fmt_contract_id),
            payment_hash: fmt_payment_hash(&p.payment_hash),
            payment_type: p.payment_type.into(),
            status: p.status.into(),
            created_at: p.created_at,
            updated_at: p.updated_at,
            payee_pubkey: fmt_pubkey(&p.payee_pubkey),
            preimage: p.preimage,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonLnInvoiceRequest {
    #[serde(default)]
    pub amt_msat: Option<u64>,
    pub expiry_sec: u32,
    #[serde(default)]
    pub asset_id: Option<String>,
    #[serde(default)]
    pub asset_amount: Option<u64>,
    #[serde(default)]
    pub payment_hash: Option<String>,
    #[serde(default)]
    pub description_hash: Option<String>,
}

impl TryFrom<JsonLnInvoiceRequest> for LnInvoiceRequest {
    type Error = Error;
    fn try_from(j: JsonLnInvoiceRequest) -> Result<Self, Self::Error> {
        Ok(LnInvoiceRequest {
            amt_msat: j.amt_msat,
            expiry_sec: j.expiry_sec,
            asset_id: j.asset_id.map(|s| parse_contract_id(&s)).transpose()?,
            asset_amount: j.asset_amount,
            payment_hash: j.payment_hash.map(|s| parse_payment_hash(&s)).transpose()?,
            description_hash: j.description_hash,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonLnInvoiceResponse {
    pub invoice: String,
}

impl From<LnInvoiceResponse> for JsonLnInvoiceResponse {
    fn from(r: LnInvoiceResponse) -> Self {
        JsonLnInvoiceResponse {
            invoice: r.invoice.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonCancelHodlInvoiceRequest {
    pub payment_hash: String,
}

impl TryFrom<JsonCancelHodlInvoiceRequest> for CancelHodlInvoiceRequest {
    type Error = Error;
    fn try_from(j: JsonCancelHodlInvoiceRequest) -> Result<Self, Self::Error> {
        Ok(CancelHodlInvoiceRequest {
            payment_hash: parse_payment_hash(&j.payment_hash)?,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonClaimHodlInvoiceRequest {
    pub payment_hash: String,
    pub payment_preimage: String,
}

impl TryFrom<JsonClaimHodlInvoiceRequest> for ClaimHodlInvoiceRequest {
    type Error = Error;
    fn try_from(j: JsonClaimHodlInvoiceRequest) -> Result<Self, Self::Error> {
        Ok(ClaimHodlInvoiceRequest {
            payment_hash: parse_payment_hash(&j.payment_hash)?,
            payment_preimage: j.payment_preimage,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonClaimHodlInvoiceResponse {
    pub changed: bool,
}

impl From<ClaimHodlInvoiceResponse> for JsonClaimHodlInvoiceResponse {
    fn from(r: ClaimHodlInvoiceResponse) -> Self {
        JsonClaimHodlInvoiceResponse { changed: r.changed }
    }
}

#[derive(Debug, Serialize)]
pub(crate) enum InvoiceStatusStr {
    Pending,
    Claimable,
    Claiming,
    Succeeded,
    Cancelled,
    Failed,
    Expired,
}

impl From<InvoiceStatus> for InvoiceStatusStr {
    fn from(s: InvoiceStatus) -> Self {
        match s {
            InvoiceStatus::Pending => InvoiceStatusStr::Pending,
            InvoiceStatus::Claimable => InvoiceStatusStr::Claimable,
            InvoiceStatus::Claiming => InvoiceStatusStr::Claiming,
            InvoiceStatus::Succeeded => InvoiceStatusStr::Succeeded,
            InvoiceStatus::Cancelled => InvoiceStatusStr::Cancelled,
            InvoiceStatus::Failed => InvoiceStatusStr::Failed,
            InvoiceStatus::Expired => InvoiceStatusStr::Expired,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonInvoiceStatus {
    pub status: InvoiceStatusStr,
}

impl From<InvoiceStatus> for JsonInvoiceStatus {
    fn from(s: InvoiceStatus) -> Self {
        JsonInvoiceStatus { status: s.into() }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonDecodeLnInvoiceResponse {
    pub amt_msat: Option<u64>,
    pub expiry_sec: u64,
    pub timestamp: u64,
    pub asset_id: Option<String>,
    pub asset_amount: Option<u64>,
    pub payment_hash: String,
    pub payment_secret: String,
    pub payee_pubkey: Option<String>,
    pub network: String,
}

impl From<DecodeLnInvoiceResponse> for JsonDecodeLnInvoiceResponse {
    fn from(r: DecodeLnInvoiceResponse) -> Self {
        JsonDecodeLnInvoiceResponse {
            amt_msat: r.amt_msat,
            expiry_sec: r.expiry_sec,
            timestamp: r.timestamp,
            asset_id: r.asset_id.as_ref().map(fmt_contract_id),
            asset_amount: r.asset_amount,
            payment_hash: fmt_payment_hash(&r.payment_hash),
            payment_secret: r.payment_secret,
            payee_pubkey: r.payee_pubkey.as_ref().map(fmt_pubkey),
            network: r.network,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonDecodeRgbInvoiceResponse {
    pub recipient_id: String,
    pub recipient_type: String,
    pub asset_schema: Option<String>,
    pub asset_id: Option<String>,
    pub assignment: String,
    pub network: String,
    pub expiration_timestamp: Option<i64>,
    pub transport_endpoints: Vec<String>,
}

impl From<DecodeRgbInvoiceResponse> for JsonDecodeRgbInvoiceResponse {
    fn from(r: DecodeRgbInvoiceResponse) -> Self {
        JsonDecodeRgbInvoiceResponse {
            recipient_id: r.recipient_id,
            recipient_type: r.recipient_type,
            asset_schema: r.asset_schema,
            asset_id: r.asset_id.as_ref().map(fmt_contract_id),
            assignment: r.assignment,
            network: r.network,
            expiration_timestamp: r.expiration_timestamp,
            transport_endpoints: r.transport_endpoints,
        }
    }
}

// ---------------------------------------------------------------------------
// RGB
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRgbInvoiceRequest {
    #[serde(default)]
    pub asset_id: Option<String>,
    #[serde(default)]
    pub assignment_kind: Option<String>,
    #[serde(default)]
    pub assignment_amount: Option<u64>,
    #[serde(default)]
    pub duration_seconds: Option<u32>,
    pub min_confirmations: u8,
    pub witness: bool,
}

impl TryFrom<JsonRgbInvoiceRequest> for SdkRgbInvoiceRequest {
    type Error = Error;
    fn try_from(j: JsonRgbInvoiceRequest) -> Result<Self, Self::Error> {
        Ok(SdkRgbInvoiceRequest {
            asset_id: j.asset_id.map(|s| parse_contract_id(&s)).transpose()?,
            assignment_kind: j
                .assignment_kind
                .map(|s| parse_assignment_kind(&s))
                .transpose()?,
            assignment_amount: j.assignment_amount,
            duration_seconds: j.duration_seconds,
            min_confirmations: j.min_confirmations,
            witness: j.witness,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRgbInvoiceResponse {
    pub recipient_id: String,
    pub invoice: String,
    pub expiration_timestamp: Option<i64>,
    pub batch_transfer_idx: i32,
}

impl From<SdkRgbInvoiceResponse> for JsonRgbInvoiceResponse {
    fn from(r: SdkRgbInvoiceResponse) -> Self {
        JsonRgbInvoiceResponse {
            recipient_id: r.recipient_id.0,
            invoice: r.invoice,
            expiration_timestamp: r.expiration_timestamp,
            batch_transfer_idx: r.batch_transfer_idx,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonWitnessData {
    pub amount_sat: u64,
    #[serde(default)]
    pub blinding: Option<u64>,
}

impl From<JsonWitnessData> for WitnessData {
    fn from(w: JsonWitnessData) -> Self {
        WitnessData {
            amount_sat: w.amount_sat,
            blinding: w.blinding,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRgbRecipient {
    pub recipient_id: String,
    #[serde(default)]
    pub witness_data: Option<JsonWitnessData>,
    pub assignment_kind: String,
    #[serde(default)]
    pub assignment_amount: Option<u64>,
    pub transport_endpoints: Vec<String>,
}

impl TryFrom<JsonRgbRecipient> for RgbRecipient {
    type Error = Error;
    fn try_from(j: JsonRgbRecipient) -> Result<Self, Self::Error> {
        Ok(RgbRecipient {
            recipient_id: RecipientId(j.recipient_id),
            witness_data: j.witness_data.map(WitnessData::from),
            assignment_kind: parse_assignment_kind(&j.assignment_kind)?,
            assignment_amount: j.assignment_amount,
            transport_endpoints: j
                .transport_endpoints
                .into_iter()
                .map(TransportEndpoint)
                .collect(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonAssetRecipients {
    pub asset_id: String,
    pub recipients: Vec<JsonRgbRecipient>,
}

impl TryFrom<JsonAssetRecipients> for AssetRecipients {
    type Error = Error;
    fn try_from(j: JsonAssetRecipients) -> Result<Self, Self::Error> {
        Ok(AssetRecipients {
            asset_id: parse_contract_id(&j.asset_id)?,
            recipients: j
                .recipients
                .into_iter()
                .map(RgbRecipient::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonSendRgbRequest {
    pub donation: bool,
    pub fee_rate: u64,
    pub min_confirmations: u8,
    pub skip_sync: bool,
    pub recipient_groups: Vec<JsonAssetRecipients>,
}

impl TryFrom<JsonSendRgbRequest> for SendRgbRequest {
    type Error = Error;
    fn try_from(j: JsonSendRgbRequest) -> Result<Self, Self::Error> {
        Ok(SendRgbRequest {
            donation: j.donation,
            fee_rate: j.fee_rate,
            min_confirmations: j.min_confirmations,
            skip_sync: j.skip_sync,
            recipient_groups: j
                .recipient_groups
                .into_iter()
                .map(AssetRecipients::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonSendRgbResponse {
    pub txid: String,
    pub batch_transfer_idx: i32,
}

impl From<SendRgbResponse> for JsonSendRgbResponse {
    fn from(r: SendRgbResponse) -> Self {
        JsonSendRgbResponse {
            txid: fmt_txid(&r.txid),
            batch_transfer_idx: r.batch_transfer_idx,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRefreshTransfersRequest {
    pub skip_sync: bool,
}

impl From<JsonRefreshTransfersRequest> for SdkRefreshTransfersRequest {
    fn from(j: JsonRefreshTransfersRequest) -> Self {
        SdkRefreshTransfersRequest {
            skip_sync: j.skip_sync,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonFailTransfersRequest {
    #[serde(default)]
    pub batch_transfer_idx: Option<i32>,
    pub no_asset_only: bool,
    pub skip_sync: bool,
}

impl From<JsonFailTransfersRequest> for SdkFailTransfersRequest {
    fn from(j: JsonFailTransfersRequest) -> Self {
        SdkFailTransfersRequest {
            batch_transfer_idx: j.batch_transfer_idx,
            no_asset_only: j.no_asset_only,
            skip_sync: j.skip_sync,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonFailTransfersResponse {
    pub transfers_changed: bool,
}

impl From<SdkFailTransfersResponse> for JsonFailTransfersResponse {
    fn from(r: SdkFailTransfersResponse) -> Self {
        JsonFailTransfersResponse {
            transfers_changed: r.transfers_changed,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonInflateRequest {
    pub asset_id: String,
    pub inflation_amounts: Vec<u64>,
    pub fee_rate: u64,
    pub min_confirmations: u8,
}

impl TryFrom<JsonInflateRequest> for InflateRequest {
    type Error = Error;
    fn try_from(j: JsonInflateRequest) -> Result<Self, Self::Error> {
        Ok(InflateRequest {
            asset_id: parse_contract_id(&j.asset_id)?,
            inflation_amounts: j.inflation_amounts,
            fee_rate: j.fee_rate,
            min_confirmations: j.min_confirmations,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonInflateResponse {
    pub txid: String,
}

impl From<InflateResponse> for JsonInflateResponse {
    fn from(r: InflateResponse) -> Self {
        JsonInflateResponse {
            txid: fmt_txid(&r.txid),
        }
    }
}

// ---------------------------------------------------------------------------
// Asset issuance
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonIssueAssetNiaRequest {
    pub amounts: Vec<u64>,
    pub ticker: String,
    pub name: String,
    pub precision: u8,
}

impl From<JsonIssueAssetNiaRequest> for SdkIssueAssetNiaRequest {
    fn from(j: JsonIssueAssetNiaRequest) -> Self {
        SdkIssueAssetNiaRequest {
            amounts: j.amounts,
            ticker: j.ticker,
            name: j.name,
            precision: j.precision,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonIssueAssetCfaRequest {
    pub amounts: Vec<u64>,
    pub name: String,
    #[serde(default)]
    pub details: Option<String>,
    pub precision: u8,
    #[serde(default)]
    pub file_digest: Option<String>,
}

impl From<JsonIssueAssetCfaRequest> for SdkIssueAssetCfaRequest {
    fn from(j: JsonIssueAssetCfaRequest) -> Self {
        SdkIssueAssetCfaRequest {
            amounts: j.amounts,
            name: j.name,
            details: j.details,
            precision: j.precision,
            file_digest: j.file_digest,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonIssueAssetIfaRequest {
    pub amounts: Vec<u64>,
    pub inflation_amounts: Vec<u64>,
    pub ticker: String,
    pub name: String,
    pub precision: u8,
    #[serde(default)]
    pub reject_list_url: Option<String>,
}

impl From<JsonIssueAssetIfaRequest> for SdkIssueAssetIfaRequest {
    fn from(j: JsonIssueAssetIfaRequest) -> Self {
        SdkIssueAssetIfaRequest {
            amounts: j.amounts,
            inflation_amounts: j.inflation_amounts,
            ticker: j.ticker,
            name: j.name,
            precision: j.precision,
            reject_list_url: j.reject_list_url,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonIssueAssetUdaRequest {
    pub ticker: String,
    pub name: String,
    #[serde(default)]
    pub details: Option<String>,
    pub precision: u8,
    #[serde(default)]
    pub media_file_digest: Option<String>,
    #[serde(default)]
    pub attachments_file_digests: Vec<String>,
}

impl From<JsonIssueAssetUdaRequest> for SdkIssueAssetUdaRequest {
    fn from(j: JsonIssueAssetUdaRequest) -> Self {
        SdkIssueAssetUdaRequest {
            ticker: j.ticker,
            name: j.name,
            details: j.details,
            precision: j.precision,
            media_file_digest: j.media_file_digest,
            attachments_file_digests: j.attachments_file_digests,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetBalanceInfo {
    pub settled: u64,
    pub future: u64,
    pub spendable: u64,
    pub offchain_outbound: u64,
    pub offchain_inbound: u64,
}

impl From<AssetBalanceInfo> for JsonAssetBalanceInfo {
    fn from(a: AssetBalanceInfo) -> Self {
        JsonAssetBalanceInfo {
            settled: a.settled,
            future: a.future,
            spendable: a.spendable,
            offchain_outbound: a.offchain_outbound,
            offchain_inbound: a.offchain_inbound,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonMedia {
    pub file_path: String,
    pub digest: String,
    pub mime: String,
}

impl From<Media> for JsonMedia {
    fn from(m: Media) -> Self {
        JsonMedia {
            file_path: m.file_path,
            digest: m.digest,
            mime: m.mime,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonEmbeddedMedia {
    pub mime: String,
    pub data: Vec<u8>,
}

impl From<EmbeddedMedia> for JsonEmbeddedMedia {
    fn from(m: EmbeddedMedia) -> Self {
        JsonEmbeddedMedia {
            mime: m.mime,
            data: m.data,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonProofOfReserves {
    pub utxo: String,
    pub proof: Vec<u8>,
}

impl From<ProofOfReserves> for JsonProofOfReserves {
    fn from(p: ProofOfReserves) -> Self {
        JsonProofOfReserves {
            utxo: p.utxo,
            proof: p.proof,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonMediaAttachment {
    pub key: u8,
    pub media: JsonMedia,
}

impl From<MediaAttachment> for JsonMediaAttachment {
    fn from(a: MediaAttachment) -> Self {
        JsonMediaAttachment {
            key: a.key,
            media: a.media.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonToken {
    pub index: u32,
    pub ticker: Option<String>,
    pub name: Option<String>,
    pub details: Option<String>,
    pub embedded_media: Option<JsonEmbeddedMedia>,
    pub media: Option<JsonMedia>,
    pub attachments: Vec<JsonMediaAttachment>,
    pub reserves: Option<JsonProofOfReserves>,
}

impl From<Token> for JsonToken {
    fn from(t: Token) -> Self {
        JsonToken {
            index: t.index,
            ticker: t.ticker,
            name: t.name,
            details: t.details,
            embedded_media: t.embedded_media.map(Into::into),
            media: t.media.map(Into::into),
            attachments: t.attachments.into_iter().map(Into::into).collect(),
            reserves: t.reserves.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonTokenLight {
    pub index: u32,
    pub ticker: Option<String>,
    pub name: Option<String>,
    pub details: Option<String>,
    pub embedded_media: bool,
    pub media: Option<JsonMedia>,
    pub attachments: Vec<JsonMediaAttachment>,
    pub reserves: bool,
}

impl From<TokenLight> for JsonTokenLight {
    fn from(t: TokenLight) -> Self {
        JsonTokenLight {
            index: t.index,
            ticker: t.ticker,
            name: t.name,
            details: t.details,
            embedded_media: t.embedded_media,
            media: t.media.map(Into::into),
            attachments: t.attachments.into_iter().map(Into::into).collect(),
            reserves: t.reserves,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetNia {
    pub asset_id: String,
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub issued_supply: u64,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: JsonAssetBalanceInfo,
    pub media: Option<JsonMedia>,
}

impl From<AssetNia> for JsonAssetNia {
    fn from(a: AssetNia) -> Self {
        JsonAssetNia {
            asset_id: fmt_contract_id(&a.asset_id),
            ticker: a.ticker,
            name: a.name,
            details: a.details,
            precision: a.precision,
            issued_supply: a.issued_supply,
            timestamp: a.timestamp,
            added_at: a.added_at,
            balance: a.balance.into(),
            media: a.media.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetCfa {
    pub asset_id: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub issued_supply: u64,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: JsonAssetBalanceInfo,
    pub media: Option<JsonMedia>,
}

impl From<AssetCfa> for JsonAssetCfa {
    fn from(a: AssetCfa) -> Self {
        JsonAssetCfa {
            asset_id: fmt_contract_id(&a.asset_id),
            name: a.name,
            details: a.details,
            precision: a.precision,
            issued_supply: a.issued_supply,
            timestamp: a.timestamp,
            added_at: a.added_at,
            balance: a.balance.into(),
            media: a.media.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetIfa {
    pub asset_id: String,
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub initial_supply: u64,
    pub max_supply: u64,
    pub known_circulating_supply: u64,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: JsonAssetBalanceInfo,
    pub media: Option<JsonMedia>,
    pub reject_list_url: Option<String>,
}

impl From<AssetIfa> for JsonAssetIfa {
    fn from(a: AssetIfa) -> Self {
        JsonAssetIfa {
            asset_id: fmt_contract_id(&a.asset_id),
            ticker: a.ticker,
            name: a.name,
            details: a.details,
            precision: a.precision,
            initial_supply: a.initial_supply,
            max_supply: a.max_supply,
            known_circulating_supply: a.known_circulating_supply,
            timestamp: a.timestamp,
            added_at: a.added_at,
            balance: a.balance.into(),
            media: a.media.map(Into::into),
            reject_list_url: a.reject_list_url,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetUda {
    pub asset_id: String,
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: JsonAssetBalanceInfo,
    pub token: Option<JsonTokenLight>,
}

impl From<AssetUda> for JsonAssetUda {
    fn from(a: AssetUda) -> Self {
        JsonAssetUda {
            asset_id: fmt_contract_id(&a.asset_id),
            ticker: a.ticker,
            name: a.name,
            details: a.details,
            precision: a.precision,
            timestamp: a.timestamp,
            added_at: a.added_at,
            balance: a.balance.into(),
            token: a.token.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonListAssetsResponse {
    pub nia: Option<Vec<JsonAssetNia>>,
    pub uda: Option<Vec<JsonAssetUda>>,
    pub cfa: Option<Vec<JsonAssetCfa>>,
    pub ifa: Option<Vec<JsonAssetIfa>>,
}

impl From<ListAssetsResponse> for JsonListAssetsResponse {
    fn from(r: ListAssetsResponse) -> Self {
        JsonListAssetsResponse {
            nia: r.nia.map(|v| v.into_iter().map(Into::into).collect()),
            uda: r.uda.map(|v| v.into_iter().map(Into::into).collect()),
            cfa: r.cfa.map(|v| v.into_iter().map(Into::into).collect()),
            ifa: r.ifa.map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetMetadataInfo {
    pub asset_schema: String,
    pub initial_supply: u64,
    pub max_supply: u64,
    pub known_circulating_supply: u64,
    pub timestamp: i64,
    pub name: String,
    pub precision: u8,
    pub ticker: Option<String>,
    pub details: Option<String>,
    pub token: Option<JsonToken>,
}

impl From<AssetMetadataInfo> for JsonAssetMetadataInfo {
    fn from(a: AssetMetadataInfo) -> Self {
        JsonAssetMetadataInfo {
            asset_schema: a.asset_schema,
            initial_supply: a.initial_supply,
            max_supply: a.max_supply,
            known_circulating_supply: a.known_circulating_supply,
            timestamp: a.timestamp,
            name: a.name,
            precision: a.precision,
            ticker: a.ticker,
            details: a.details,
            token: a.token.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAssetMediaResponse {
    pub bytes_hex: String,
}

impl From<AssetMediaResponse> for JsonAssetMediaResponse {
    fn from(r: AssetMediaResponse) -> Self {
        JsonAssetMediaResponse {
            bytes_hex: r.bytes_hex,
        }
    }
}

// ---------------------------------------------------------------------------
// Node info / network / btc / address / sign / fee / indexer
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct JsonNodeInfo {
    pub pubkey: String,
    pub num_channels: u64,
    pub num_usable_channels: u64,
    pub local_balance_sat: u64,
    pub eventual_close_fees_sat: u64,
    pub pending_outbound_payments_sat: u64,
    pub num_peers: u64,
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub max_media_upload_size_mb: u16,
    pub rgb_htlc_min_msat: u64,
    pub rgb_channel_capacity_min_sat: u64,
    pub channel_capacity_min_sat: u64,
    pub channel_capacity_max_sat: u64,
    pub channel_asset_min_amount: u64,
    pub channel_asset_max_amount: u64,
    pub network_nodes: u64,
    pub network_channels: u64,
}

impl From<NodeInfo> for JsonNodeInfo {
    fn from(n: NodeInfo) -> Self {
        JsonNodeInfo {
            pubkey: fmt_pubkey(&n.pubkey),
            num_channels: n.num_channels,
            num_usable_channels: n.num_usable_channels,
            local_balance_sat: n.local_balance_sat,
            eventual_close_fees_sat: n.eventual_close_fees_sat,
            pending_outbound_payments_sat: n.pending_outbound_payments_sat,
            num_peers: n.num_peers,
            account_xpub_vanilla: n.account_xpub_vanilla,
            account_xpub_colored: n.account_xpub_colored,
            max_media_upload_size_mb: n.max_media_upload_size_mb,
            rgb_htlc_min_msat: n.rgb_htlc_min_msat,
            rgb_channel_capacity_min_sat: n.rgb_channel_capacity_min_sat,
            channel_capacity_min_sat: n.channel_capacity_min_sat,
            channel_capacity_max_sat: n.channel_capacity_max_sat,
            channel_asset_min_amount: n.channel_asset_min_amount,
            channel_asset_max_amount: n.channel_asset_max_amount,
            network_nodes: n.network_nodes,
            network_channels: n.network_channels,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonNetworkInfo {
    pub network: String,
    pub height: u32,
}

impl From<NetworkInfo> for JsonNetworkInfo {
    fn from(n: NetworkInfo) -> Self {
        JsonNetworkInfo {
            network: n.network,
            height: n.height,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonAddressInfo {
    pub address: String,
}

impl From<AddressInfo> for JsonAddressInfo {
    fn from(a: AddressInfo) -> Self {
        JsonAddressInfo { address: a.address }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonBtcBalance {
    pub settled: u64,
    pub future: u64,
    pub spendable: u64,
}

impl From<BtcBalance> for JsonBtcBalance {
    fn from(b: BtcBalance) -> Self {
        JsonBtcBalance {
            settled: b.settled,
            future: b.future,
            spendable: b.spendable,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonBtcBalanceInfo {
    pub vanilla: JsonBtcBalance,
    pub colored: JsonBtcBalance,
}

impl From<BtcBalanceInfo> for JsonBtcBalanceInfo {
    fn from(b: BtcBalanceInfo) -> Self {
        JsonBtcBalanceInfo {
            vanilla: b.vanilla.into(),
            colored: b.colored.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonSignMessageResponse {
    pub signed_message: String,
}

impl From<SignMessageResponse> for JsonSignMessageResponse {
    fn from(s: SignMessageResponse) -> Self {
        JsonSignMessageResponse {
            signed_message: s.signed_message,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonEstimateFeeResponse {
    pub fee_rate: f64,
}

impl From<EstimateFeeResponse> for JsonEstimateFeeResponse {
    fn from(e: EstimateFeeResponse) -> Self {
        JsonEstimateFeeResponse {
            fee_rate: e.fee_rate,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonCheckIndexerUrlResponse {
    pub indexer_protocol: String,
}

impl From<CheckIndexerUrlResponse> for JsonCheckIndexerUrlResponse {
    fn from(c: CheckIndexerUrlResponse) -> Self {
        JsonCheckIndexerUrlResponse {
            indexer_protocol: c.indexer_protocol,
        }
    }
}

// ---------------------------------------------------------------------------
// Send btc / create utxos / list transactions / list unspents / list transfers / swaps
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonSendBtcRequest {
    pub amount: u64,
    pub address: String,
    pub fee_rate: u64,
    pub skip_sync: bool,
}

impl From<JsonSendBtcRequest> for SdkSendBtcRequest {
    fn from(j: JsonSendBtcRequest) -> Self {
        SdkSendBtcRequest {
            amount: j.amount,
            address: j.address,
            fee_rate: j.fee_rate,
            skip_sync: j.skip_sync,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonSendBtcResponse {
    pub txid: String,
}

impl From<SdkSendBtcResponse> for JsonSendBtcResponse {
    fn from(r: SdkSendBtcResponse) -> Self {
        JsonSendBtcResponse {
            txid: fmt_txid(&r.txid),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonCreateUtxosRequest {
    pub up_to: bool,
    #[serde(default)]
    pub num: Option<u8>,
    #[serde(default)]
    pub size: Option<u32>,
    pub fee_rate: u64,
    pub skip_sync: bool,
}

impl From<JsonCreateUtxosRequest> for SdkCreateUtxosRequest {
    fn from(j: JsonCreateUtxosRequest) -> Self {
        SdkCreateUtxosRequest {
            up_to: j.up_to,
            num: j.num,
            size: j.size,
            fee_rate: j.fee_rate,
            skip_sync: j.skip_sync,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) enum TransactionTypeStr {
    RgbSend,
    Drain,
    CreateUtxos,
    User,
}

impl From<TransactionType> for TransactionTypeStr {
    fn from(t: TransactionType) -> Self {
        match t {
            TransactionType::RgbSend => TransactionTypeStr::RgbSend,
            TransactionType::Drain => TransactionTypeStr::Drain,
            TransactionType::CreateUtxos => TransactionTypeStr::CreateUtxos,
            TransactionType::User => TransactionTypeStr::User,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonBlockTime {
    pub height: u32,
    pub timestamp: u64,
}

impl From<BlockTime> for JsonBlockTime {
    fn from(b: BlockTime) -> Self {
        JsonBlockTime {
            height: b.height,
            timestamp: b.timestamp,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonTransaction {
    pub transaction_type: TransactionTypeStr,
    pub txid: String,
    pub received: u64,
    pub sent: u64,
    pub fee: u64,
    pub confirmation_time: Option<JsonBlockTime>,
}

impl From<Transaction> for JsonTransaction {
    fn from(t: Transaction) -> Self {
        JsonTransaction {
            transaction_type: t.transaction_type.into(),
            txid: fmt_txid(&t.txid),
            received: t.received,
            sent: t.sent,
            fee: t.fee,
            confirmation_time: t.confirmation_time.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonTransferTransportEndpoint {
    pub endpoint: String,
    pub transport_type: String,
    pub used: bool,
}

impl From<TransferTransportEndpoint> for JsonTransferTransportEndpoint {
    fn from(e: TransferTransportEndpoint) -> Self {
        JsonTransferTransportEndpoint {
            endpoint: e.endpoint,
            transport_type: e.transport_type,
            used: e.used,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonTransfer {
    pub idx: i32,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: String,
    pub requested_assignment: Option<String>,
    pub assignments: Vec<String>,
    pub kind: String,
    pub txid: Option<String>,
    pub recipient_id: Option<String>,
    pub receive_utxo: Option<String>,
    pub change_utxo: Option<String>,
    pub expiration: Option<i64>,
    pub transport_endpoints: Vec<JsonTransferTransportEndpoint>,
}

impl From<Transfer> for JsonTransfer {
    fn from(t: Transfer) -> Self {
        JsonTransfer {
            idx: t.idx,
            created_at: t.created_at,
            updated_at: t.updated_at,
            status: t.status,
            requested_assignment: t.requested_assignment,
            assignments: t.assignments,
            kind: t.kind,
            txid: t.txid.as_ref().map(fmt_txid),
            recipient_id: t.recipient_id,
            receive_utxo: t.receive_utxo,
            change_utxo: t.change_utxo,
            expiration: t.expiration,
            transport_endpoints: t.transport_endpoints.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRgbAllocation {
    pub asset_id: Option<String>,
    pub assignment: String,
    pub settled: bool,
}

impl From<RgbAllocation> for JsonRgbAllocation {
    fn from(a: RgbAllocation) -> Self {
        JsonRgbAllocation {
            asset_id: a.asset_id.as_ref().map(fmt_contract_id),
            assignment: a.assignment,
            settled: a.settled,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonUtxo {
    pub outpoint: String,
    pub btc_amount: u64,
    pub colorable: bool,
}

impl From<Utxo> for JsonUtxo {
    fn from(u: Utxo) -> Self {
        JsonUtxo {
            outpoint: u.outpoint,
            btc_amount: u.btc_amount,
            colorable: u.colorable,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonUnspent {
    pub utxo: JsonUtxo,
    pub rgb_allocations: Vec<JsonRgbAllocation>,
}

impl From<Unspent> for JsonUnspent {
    fn from(u: Unspent) -> Self {
        JsonUnspent {
            utxo: u.utxo.into(),
            rgb_allocations: u.rgb_allocations.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) enum SwapStatusStr {
    Waiting,
    Pending,
    Succeeded,
    Expired,
    Failed,
}

impl From<SwapStatus> for SwapStatusStr {
    fn from(s: SwapStatus) -> Self {
        match s {
            SwapStatus::Waiting => SwapStatusStr::Waiting,
            SwapStatus::Pending => SwapStatusStr::Pending,
            SwapStatus::Succeeded => SwapStatusStr::Succeeded,
            SwapStatus::Expired => SwapStatusStr::Expired,
            SwapStatus::Failed => SwapStatusStr::Failed,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonSwap {
    pub qty_from: u64,
    pub qty_to: u64,
    pub from_asset: Option<String>,
    pub to_asset: Option<String>,
    pub payment_hash: String,
    pub status: SwapStatusStr,
    pub requested_at: u64,
    pub initiated_at: Option<u64>,
    pub expires_at: u64,
    pub completed_at: Option<u64>,
}

impl From<Swap> for JsonSwap {
    fn from(s: Swap) -> Self {
        JsonSwap {
            qty_from: s.qty_from,
            qty_to: s.qty_to,
            from_asset: s.from_asset.as_ref().map(fmt_contract_id),
            to_asset: s.to_asset.as_ref().map(fmt_contract_id),
            payment_hash: fmt_payment_hash(&s.payment_hash),
            status: s.status.into(),
            requested_at: s.requested_at,
            initiated_at: s.initiated_at,
            expires_at: s.expires_at,
            completed_at: s.completed_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonSwapList {
    pub taker: Vec<JsonSwap>,
    pub maker: Vec<JsonSwap>,
}

impl From<SwapList> for JsonSwapList {
    fn from(s: SwapList) -> Self {
        JsonSwapList {
            taker: s.taker.into_iter().map(Into::into).collect(),
            maker: s.maker.into_iter().map(Into::into).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Maker / taker / onion / postassetmedia
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonMakerInitRequest {
    pub qty_from: u64,
    pub qty_to: u64,
    #[serde(default)]
    pub from_asset: Option<String>,
    #[serde(default)]
    pub to_asset: Option<String>,
    pub timeout_sec: u32,
}

impl TryFrom<JsonMakerInitRequest> for SdkMakerInitRequest {
    type Error = Error;
    fn try_from(j: JsonMakerInitRequest) -> Result<Self, Self::Error> {
        Ok(SdkMakerInitRequest {
            qty_from: j.qty_from,
            qty_to: j.qty_to,
            from_asset: j.from_asset.map(|s| parse_contract_id(&s)).transpose()?,
            to_asset: j.to_asset.map(|s| parse_contract_id(&s)).transpose()?,
            timeout_sec: j.timeout_sec,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonMakerInitResponse {
    pub payment_hash: String,
    pub payment_secret: String,
    pub swapstring: String,
}

impl From<SdkMakerInitResponse> for JsonMakerInitResponse {
    fn from(r: SdkMakerInitResponse) -> Self {
        JsonMakerInitResponse {
            payment_hash: fmt_payment_hash(&r.payment_hash),
            payment_secret: r.payment_secret,
            swapstring: r.swapstring,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonMakerExecuteRequest {
    pub swapstring: String,
    pub payment_secret: String,
    pub taker_pubkey: String,
}

impl TryFrom<JsonMakerExecuteRequest> for SdkMakerExecuteRequest {
    type Error = Error;
    fn try_from(j: JsonMakerExecuteRequest) -> Result<Self, Self::Error> {
        Ok(SdkMakerExecuteRequest {
            swapstring: j.swapstring,
            payment_secret: j.payment_secret,
            taker_pubkey: parse_pubkey(&j.taker_pubkey)?,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonTakerRequest {
    pub swapstring: String,
}

impl From<JsonTakerRequest> for SdkTakerRequest {
    fn from(j: JsonTakerRequest) -> Self {
        SdkTakerRequest {
            swapstring: j.swapstring,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonSendOnionMessageRequest {
    pub node_ids: Vec<String>,
    pub tlv_type: u64,
    pub data: String,
}

impl TryFrom<JsonSendOnionMessageRequest> for SdkSendOnionMessageRequest {
    type Error = Error;
    fn try_from(j: JsonSendOnionMessageRequest) -> Result<Self, Self::Error> {
        Ok(SdkSendOnionMessageRequest {
            node_ids: j
                .node_ids
                .iter()
                .map(|s| parse_pubkey(s))
                .collect::<Result<Vec<_>, _>>()?,
            tlv_type: j.tlv_type,
            data: j.data,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonPostAssetMediaRequest {
    pub file_bytes: Vec<u8>,
}

impl From<JsonPostAssetMediaRequest> for SdkPostAssetMediaRequest {
    fn from(j: JsonPostAssetMediaRequest) -> Self {
        SdkPostAssetMediaRequest {
            file_bytes: j.file_bytes,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonPostAssetMediaResponse {
    pub digest: String,
}

impl From<SdkPostAssetMediaResponse> for JsonPostAssetMediaResponse {
    fn from(r: SdkPostAssetMediaResponse) -> Self {
        JsonPostAssetMediaResponse { digest: r.digest }
    }
}

// ---------------------------------------------------------------------------
// Channel-id getter helper
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct JsonChannelIdResponse {
    pub channel_id: String,
}
