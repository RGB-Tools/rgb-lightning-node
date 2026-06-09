use crate::NodeHandle;

pub type PublicKey = bitcoin::secp256k1::PublicKey;
pub type Txid = bitcoin::Txid;
pub type ContractId = rgb_lib::ContractId;
pub type ChannelId = lightning::ln::types::ChannelId;
pub type PaymentHash = lightning::types::payment::PaymentHash;
pub type Bolt11Invoice = lightning_invoice::Bolt11Invoice;

pub struct RecipientId(pub String);
pub struct TransportEndpoint(pub String);

pub struct SdkNode {
    pub(crate) handle: NodeHandle,
}

#[derive(Debug, thiserror::Error)]
pub enum RlnError {
    #[error("node is not initialized")]
    NotInitialized,
    #[error("invalid request")]
    InvalidRequest,
    #[error("resource not found")]
    NotFound,
    #[error("conflict with current node state")]
    Conflict,
    #[error("failed bitcoind connection")]
    FailedBitcoindConnection,
    #[error("failed bdk sync")]
    FailedBdkSync,
    #[error("failed broadcast")]
    FailedBroadcast,
    #[error("failed peer connection")]
    FailedPeerConnection,
    #[error("insufficient capacity")]
    InsufficientCapacity,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("no available utxos")]
    NoAvailableUtxos,
    #[error("no route")]
    NoRoute,
    #[error("external signer required")]
    ExternalSignerRequired,
    #[error("external signer mismatch")]
    ExternalSignerMismatch,
    #[error("external signer unavailable")]
    ExternalSignerUnavailable,
    #[error("external signer protocol error")]
    ExternalSignerProtocolError,
    #[error("unsupported in external signer mode")]
    UnsupportedInExternalSignerMode,
    #[error("internal error")]
    Internal,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for RlnError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Internal
    }
}

pub struct NodeInfo {
    pub pubkey: PublicKey,
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
    pub latest_rgs_snapshot_timestamp: Option<u64>,
}

pub struct NetworkInfo {
    pub network: String,
    pub height: u32,
}

pub struct AddressInfo {
    pub address: String,
}

pub struct BtcBalance {
    pub settled: u64,
    pub future: u64,
    pub spendable: u64,
}

pub struct BtcBalanceInfo {
    pub vanilla: BtcBalance,
    pub colored: BtcBalance,
}

pub struct SignMessageResponse {
    pub signed_message: String,
}

pub struct EstimateFeeResponse {
    pub fee_rate: f64,
}

pub struct CheckIndexerUrlResponse {
    pub indexer_protocol: String,
}

pub struct Payment {
    pub amt_msat: Option<u64>,
    pub asset_amount: Option<u64>,
    pub asset_id: Option<ContractId>,
    pub payment_hash: PaymentHash,
    pub payment_type: PaymentType,
    pub status: HtlcStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub payee_pubkey: PublicKey,
    pub preimage: Option<String>,
    pub description_hash: Option<String>,
}

pub enum PaymentType {
    Outbound,
    InboundAutoClaim,
    InboundHodl,
}

pub enum HtlcStatus {
    Pending,
    Claimable,
    Claiming,
    Succeeded,
    Cancelled,
    Failed,
}

pub struct Swap {
    pub qty_from: u64,
    pub qty_to: u64,
    pub from_asset: Option<ContractId>,
    pub to_asset: Option<ContractId>,
    pub payment_hash: PaymentHash,
    pub status: SwapStatus,
    pub requested_at: u64,
    pub initiated_at: Option<u64>,
    pub expires_at: u64,
    pub completed_at: Option<u64>,
}

pub enum SwapStatus {
    Waiting,
    Pending,
    Succeeded,
    Expired,
    Failed,
}

pub struct Channel {
    pub channel_id: ChannelId,
    pub peer_pubkey: PublicKey,
    pub status: ChannelStatus,
    pub ready: bool,
    pub capacity_sat: u64,
    pub local_balance_sat: u64,
    pub outbound_balance_msat: u64,
    pub inbound_balance_msat: u64,
    pub next_outbound_htlc_limit_msat: u64,
    pub next_outbound_htlc_minimum_msat: u64,
    pub is_usable: bool,
    pub public: bool,
    pub funding_txid: Option<Txid>,
    pub peer_alias: Option<String>,
    pub short_channel_id: Option<u64>,
    pub asset_id: Option<ContractId>,
    pub asset_local_amount: Option<u64>,
    pub asset_remote_amount: Option<u64>,
    pub virtual_open_mode: Option<String>,
}

pub enum ChannelStatus {
    Opening,
    Opened,
    Closing,
}

pub struct Peer {
    pub pubkey: PublicKey,
}

pub struct SwapList {
    pub taker: Vec<Swap>,
    pub maker: Vec<Swap>,
}

pub struct BlockTime {
    pub height: u32,
    pub timestamp: u64,
}

pub enum TransactionType {
    RgbSend,
    Drain,
    CreateUtxos,
    SendBtc,
    Incoming,
}

pub struct Transaction {
    pub transaction_type: TransactionType,
    pub txid: Txid,
    pub received: u64,
    pub sent: u64,
    pub fee: u64,
    pub confirmation_time: Option<BlockTime>,
}

pub struct AssetBalanceInfo {
    pub settled: u64,
    pub future: u64,
    pub spendable: u64,
    pub offchain_outbound: u64,
    pub offchain_inbound: u64,
}

pub struct AssetMetadataInfo {
    pub asset_schema: String,
    pub initial_supply: u64,
    pub max_supply: u64,
    pub known_circulating_supply: u64,
    pub timestamp: i64,
    pub name: String,
    pub precision: u8,
    pub ticker: Option<String>,
    pub details: Option<String>,
    pub token: Option<Token>,
}

pub struct AssetMediaResponse {
    pub bytes_hex: String,
}

pub struct EmbeddedMedia {
    pub mime: String,
    pub data: Vec<u8>,
}

pub struct Media {
    pub file_path: String,
    pub digest: String,
    pub mime: String,
}

pub struct ProofOfReserves {
    pub utxo: String,
    pub proof: Vec<u8>,
}

pub struct MediaAttachment {
    pub key: u8,
    pub media: Media,
}

pub struct Token {
    pub index: u32,
    pub ticker: Option<String>,
    pub name: Option<String>,
    pub details: Option<String>,
    pub embedded_media: Option<EmbeddedMedia>,
    pub media: Option<Media>,
    pub attachments: Vec<MediaAttachment>,
    pub reserves: Option<ProofOfReserves>,
}

pub struct TokenLight {
    pub index: u32,
    pub ticker: Option<String>,
    pub name: Option<String>,
    pub details: Option<String>,
    pub embedded_media: bool,
    pub media: Option<Media>,
    pub attachments: Vec<MediaAttachment>,
    pub reserves: bool,
}

pub struct AssetNia {
    pub asset_id: ContractId,
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub issued_supply: u64,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: AssetBalanceInfo,
    pub media: Option<Media>,
}

pub struct AssetUda {
    pub asset_id: ContractId,
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: AssetBalanceInfo,
    pub token: Option<TokenLight>,
}

pub struct AssetCfa {
    pub asset_id: ContractId,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub issued_supply: u64,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: AssetBalanceInfo,
    pub media: Option<Media>,
}

pub struct AssetIfa {
    pub asset_id: ContractId,
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub initial_supply: u64,
    pub max_supply: u64,
    pub known_circulating_supply: u64,
    pub timestamp: i64,
    pub added_at: i64,
    pub balance: AssetBalanceInfo,
    pub media: Option<Media>,
    pub reject_list_url: Option<String>,
}

pub struct ListAssetsResponse {
    pub nia: Option<Vec<AssetNia>>,
    pub uda: Option<Vec<AssetUda>>,
    pub cfa: Option<Vec<AssetCfa>>,
    pub ifa: Option<Vec<AssetIfa>>,
}

pub struct DecodeLnInvoiceResponse {
    pub amt_msat: Option<u64>,
    pub expiry_sec: u64,
    pub timestamp: u64,
    pub asset_id: Option<ContractId>,
    pub asset_amount: Option<u64>,
    pub payment_hash: PaymentHash,
    pub payment_secret: String,
    pub payee_pubkey: Option<PublicKey>,
    pub min_final_cltv_expiry_delta: u64,
    pub network: String,
}

pub struct DecodeRgbInvoiceResponse {
    pub recipient_id: String,
    pub recipient_type: String,
    pub asset_schema: Option<String>,
    pub asset_id: Option<ContractId>,
    pub assignment: String,
    pub network: String,
    pub expiration_timestamp: Option<i64>,
    pub transport_endpoints: Vec<String>,
}

pub enum InvoiceStatus {
    Pending,
    Claimable,
    Claiming,
    Succeeded,
    Cancelled,
    Failed,
    Expired,
}

pub struct TransferTransportEndpoint {
    pub endpoint: String,
    pub transport_type: String,
    pub used: bool,
}

pub struct Transfer {
    pub idx: i32,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: String,
    pub requested_assignment: Option<String>,
    pub assignments: Vec<String>,
    pub kind: String,
    pub txid: Option<Txid>,
    pub recipient_id: Option<String>,
    pub receive_utxo: Option<String>,
    pub change_utxo: Option<String>,
    pub expiration: Option<i64>,
    pub transport_endpoints: Vec<TransferTransportEndpoint>,
}

pub struct RgbAllocation {
    pub asset_id: Option<ContractId>,
    pub assignment: String,
    pub settled: bool,
}

pub struct Utxo {
    pub outpoint: String,
    pub btc_amount: u64,
    pub colorable: bool,
}

pub struct Unspent {
    pub utxo: Utxo,
    pub rgb_allocations: Vec<RgbAllocation>,
}

pub struct LnInvoiceRequest {
    pub amt_msat: Option<u64>,
    pub expiry_sec: u32,
    pub asset_id: Option<ContractId>,
    pub asset_amount: Option<u64>,
    pub payment_hash: Option<PaymentHash>,
    pub description_hash: Option<String>,
    pub min_final_cltv_expiry_delta: Option<u16>,
}

pub struct CancelHodlInvoiceRequest {
    pub payment_hash: PaymentHash,
}

pub struct ClaimHodlInvoiceRequest {
    pub payment_hash: PaymentHash,
    pub payment_preimage: String,
}

pub struct ClaimHodlInvoiceResponse {
    pub changed: bool,
}

pub struct InflateRequest {
    pub asset_id: ContractId,
    pub inflation_amounts: Vec<u64>,
    pub fee_rate: u64,
    pub min_confirmations: u8,
}

pub struct InflateResponse {
    pub txid: Txid,
}

pub struct SdkUnlockRequest {
    pub password: String,
    pub bitcoind_rpc_username: Option<String>,
    pub bitcoind_rpc_password: Option<String>,
    pub bitcoind_rpc_host: Option<String>,
    pub bitcoind_rpc_port: Option<u16>,
    pub indexer_url: Option<String>,
    pub proxy_endpoint: Option<String>,
    pub announce_addresses: Vec<String>,
    pub announce_alias: Option<String>,
    // None → P2P gossip (default). Some(url) → Rapid Gossip Sync against url.
    pub gossip_rgs_server_url: Option<String>,
}

pub struct SdkExternalSignerBootstrap {
    pub node_id: String,
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub master_fingerprint: String,
    pub protocol_version: String,
    pub api_level: u32,
}

pub struct SdkVssClearFenceRequest {
    pub password: String,
}

pub struct SdkOpenChannelRequest {
    pub peer_pubkey_and_opt_addr: String,
    pub capacity_sat: u64,
    pub push_msat: u64,
    pub public: bool,
    pub with_anchors: bool,
    pub fee_base_msat: Option<u32>,
    pub fee_proportional_millionths: Option<u32>,
    pub temporary_channel_id: Option<ChannelId>,
    pub asset_id: Option<ContractId>,
    pub asset_amount: Option<u64>,
    pub push_asset_amount: Option<u64>,
    pub virtual_open_mode: Option<String>,
}

pub struct SdkOpenChannelResponse {
    pub temporary_channel_id: ChannelId,
}

pub struct SdkDisconnectPeerRequest {
    pub peer_pubkey: PublicKey,
}

pub struct SdkCloseChannelRequest {
    pub channel_id: ChannelId,
    pub peer_pubkey: PublicKey,
    pub force: bool,
}

pub struct SdkSendPaymentRequest {
    pub invoice: String,
    pub amt_msat: Option<u64>,
    pub asset_id: Option<ContractId>,
    pub asset_amount: Option<u64>,
}

pub struct SdkSendPaymentResponse {
    pub payment_id: String,
    pub payment_hash: Option<PaymentHash>,
    pub payment_secret: Option<String>,
    pub status: HtlcStatus,
}

pub struct SdkRefreshTransfersRequest {
    pub skip_sync: bool,
}

pub struct SdkFailTransfersRequest {
    pub batch_transfer_idx: Option<i32>,
    pub no_asset_only: bool,
    pub skip_sync: bool,
}

pub struct SdkFailTransfersResponse {
    pub transfers_changed: bool,
}

pub struct SdkCreateUtxosRequest {
    pub up_to: bool,
    pub num: Option<u8>,
    pub size: Option<u32>,
    pub fee_rate: u64,
    pub skip_sync: bool,
}

pub struct SdkIssueAssetNiaRequest {
    pub amounts: Vec<u64>,
    pub ticker: String,
    pub name: String,
    pub precision: u8,
}

pub struct SdkIssueAssetCfaRequest {
    pub amounts: Vec<u64>,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub file_digest: Option<String>,
}

pub struct SdkIssueAssetIfaRequest {
    pub amounts: Vec<u64>,
    pub inflation_amounts: Vec<u64>,
    pub ticker: String,
    pub name: String,
    pub precision: u8,
    pub reject_list_url: Option<String>,
}

pub struct SdkIssueAssetUdaRequest {
    pub ticker: String,
    pub name: String,
    pub details: Option<String>,
    pub precision: u8,
    pub media_file_digest: Option<String>,
    pub attachments_file_digests: Vec<String>,
}

pub struct SdkKeysendRequest {
    pub dest_pubkey: PublicKey,
    pub amt_msat: u64,
    pub asset_id: Option<ContractId>,
    pub asset_amount: Option<u64>,
}

pub struct SdkKeysendResponse {
    pub payment_hash: PaymentHash,
    pub payment_preimage: String,
    pub status: HtlcStatus,
}

pub struct SdkSendBtcRequest {
    pub amount: u64,
    pub address: String,
    pub fee_rate: u64,
    pub skip_sync: bool,
}

pub struct SdkSendBtcResponse {
    pub txid: Txid,
}

pub struct SdkMakerInitRequest {
    pub qty_from: u64,
    pub qty_to: u64,
    pub from_asset: Option<ContractId>,
    pub to_asset: Option<ContractId>,
    pub timeout_sec: u32,
}

pub struct SdkMakerInitResponse {
    pub payment_hash: PaymentHash,
    pub payment_secret: String,
    pub swapstring: String,
}

pub struct SdkMakerExecuteRequest {
    pub swapstring: String,
    pub payment_secret: String,
    pub taker_pubkey: PublicKey,
}

pub struct SdkTakerRequest {
    pub swapstring: String,
}

pub struct SdkSendOnionMessageRequest {
    pub node_ids: Vec<PublicKey>,
    pub tlv_type: u64,
    pub data: String,
}

pub struct SdkPostAssetMediaRequest {
    pub file_bytes: Vec<u8>,
}

pub struct SdkPostAssetMediaResponse {
    pub digest: String,
}

pub struct SdkRgbInvoiceRequest {
    pub asset_id: Option<ContractId>,
    pub assignment_kind: Option<AssignmentKind>,
    pub assignment_amount: Option<u64>,
    pub duration_seconds: Option<u32>,
    pub min_confirmations: u8,
    pub witness: bool,
}

pub struct SdkRgbInvoiceResponse {
    pub recipient_id: RecipientId,
    pub invoice: String,
    pub expiration_timestamp: Option<i64>,
    pub batch_transfer_idx: i32,
}

pub struct LnInvoiceResponse {
    pub invoice: Bolt11Invoice,
}

pub struct SdkInitRequest {
    pub storage_dir_path: String,
    pub daemon_listening_port: u16,
    pub ldk_peer_listening_port: u16,
    pub network: String,
    pub max_media_upload_size_mb: u16,
    pub enable_virtual_channels_v0: Option<bool>,
    pub virtual_peer_pubkeys: Option<Vec<PublicKey>>,
    pub lsp_base_url: Option<String>,
    pub lsp_bearer_token: Option<String>,
    pub vss_url: Option<String>,
    pub vss_allow_http: bool,
    pub vss_allow_empty_restore: bool,
}

pub struct SendRgbRequest {
    pub donation: bool,
    pub fee_rate: u64,
    pub min_confirmations: u8,
    pub recipient_groups: Vec<AssetRecipients>,
}

pub struct SendRgbResponse {
    pub txid: Txid,
    pub batch_transfer_idx: i32,
}

pub struct AssetRecipients {
    pub asset_id: ContractId,
    pub recipients: Vec<RgbRecipient>,
}

pub struct RgbRecipient {
    pub recipient_id: RecipientId,
    pub witness_data: Option<WitnessData>,
    pub assignment_kind: AssignmentKind,
    pub assignment_amount: Option<u64>,
    pub transport_endpoints: Vec<TransportEndpoint>,
}

pub struct WitnessData {
    pub amount_sat: u64,
    pub blinding: Option<u64>,
}

pub enum AssignmentKind {
    Fungible,
    NonFungible,
    InflationRight,
    ReplaceRight,
    Any,
}

pub(super) fn uniffi_state_slot() -> &'static std::sync::Mutex<Option<NodeHandle>> {
    static SLOT: std::sync::OnceLock<std::sync::Mutex<Option<NodeHandle>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(None))
}
