// NOTE: This module mirrors core behavior from `src/routes.rs` for SDK consumers.
// If route-level business logic changes, keep SDK equivalents in sync.

use crate::async_order::{
    read_async_payments_next_hash_index, write_async_payments_next_hash_index,
    AsyncOrderNewResultWire, AsyncOrderOutboundInvoiceResultWire, ASYNC_ORDER_MAX_HASH_BATCH_SIZE,
    ASYNC_ORDER_RESPONSE_TIMEOUT_SECS,
};
use crate::core_types::async_order::{
    AsyncOrderNewRequest, AsyncOrderNewResponse, AsyncOrderOutboundInvoiceRequest,
    AsyncOrderOutboundInvoiceResponse,
};
use crate::core_types::{FEE_RATE, MIN_CHANNEL_CONFIRMATIONS};
use crate::error::APIError;
#[cfg(feature = "vss")]
use crate::ldk::derive_vss_identity;
use crate::ldk::{
    clear_rgb_payment_pending, start_ldk, write_rgb_payment_info_file, InvoiceType, PaymentInfo,
    VirtualChannelSessionStatus,
};
use crate::rgb::{check_rgb_proxy_endpoint, get_rgb_channel_info_optional};
use crate::signer::{
    read_key_source_file, validate_bootstrap_payload, validate_key_source_matches_bootstrap,
    write_key_source_file, BootstrapData, KeySourceFile, SUPPORTED_SIGNER_API_LEVEL,
};
use crate::swap::{SwapData, SwapInfo, SwapString};
use crate::utils::{
    check_already_initialized, check_channel_id, check_password_strength, check_password_validity,
    connect_peer_if_necessary, encrypt_and_save_mnemonic, get_current_timestamp,
    get_max_local_rgb_amount, get_route, hex_str, hex_str_to_compressed_pubkey, hex_str_to_vec,
    is_external_signer_mode_configured, new_jsonrpc_request_id, parse_peer_info,
    validate_and_parse_description_hash, validate_and_parse_payment_hash,
    validate_and_parse_payment_preimage, AppState, UserOnionMessageContents,
};
use amplify::{map, s};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::ScriptBuf;
use lightning::chain::channelmonitor::Balance;
use lightning::ln::channel_state::ChannelShutdownState;
use lightning::ln::channelmanager::Bolt11InvoiceParameters;
use lightning::ln::channelmanager::{
    OptionalOfferPaymentParams, PaymentId, RecipientOnionFields, Retry,
};
use lightning::ln::types::ChannelId;
use lightning::offers::offer::{self, Offer};
use lightning::rgb_utils::RgbKvStoreExt;
use lightning::rgb_utils::{RgbInfo, STATIC_BLINDING};
use lightning::routing::gossip::NodeId;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{
    Path as LnPath, PaymentParameters, Route, RouteHint, RouteHintHop, RouteParameters,
    RouteParametersConfig,
};
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning::util::config::{
    ChannelConfig, ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig,
};
use lightning::util::errors::APIError as LDKAPIError;
use lightning::util::IS_SWAP_SCID;
use lightning::{
    onion_message::messenger::Destination, onion_message::messenger::MessageSendInstructions,
};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description, PaymentSecret};
use regex::Regex;
use rgb_lib::utils::recipient_id_from_script_buf;
use rgb_lib::wallet::rust_only::check_indexer_url as rgb_lib_check_indexer_url;
use rgb_lib::wallet::{
    Invoice as RgbLibInvoice, Recipient as RgbLibRecipient, RecipientInfo,
    WitnessData as RgbLibWitnessData,
};
use rgb_lib::{
    bdk_wallet::keys::bip39::Mnemonic,
    keys::{generate_keys, WitnessVersion},
    ContractId, RgbTransport,
};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use rgb_lib::wallet::rust_only::IndexerProtocol as RgbLibIndexerProtocol;
use rgb_lib::wallet::RecipientType as RgbLibRecipientType;
use rgb_lib::wallet::{
    AssetCFA as RgbLibAssetCFA, AssetIFA as RgbLibAssetIFA, AssetNIA as RgbLibAssetNIA,
    AssetUDA as RgbLibAssetUDA, EmbeddedMedia as RgbLibEmbeddedMedia, Media as RgbLibMedia,
    ProofOfReserves as RgbLibProofOfReserves, Token as RgbLibToken, TokenLight as RgbLibTokenLight,
};
use rgb_lib::BitcoinNetwork as RgbBitcoinNetwork;
use rgb_lib::{AssetSchema as RgbLibAssetSchema, Assignment as RgbLibAssignment};
use serde_json::Value;

const SDK_HTLC_MIN_MSAT: u64 = 3_000_000;
const SDK_OPENRGBCHANNEL_MIN_SAT: u64 = SDK_HTLC_MIN_MSAT / 1000 * 10 + 10;
const SDK_OPENCHANNEL_MIN_SAT: u64 = 5506;
const SDK_OPENCHANNEL_MAX_SAT: u64 = 16_777_215;
const SDK_OPENCHANNEL_MIN_RGB_AMT: u64 = 1;
const SDK_INVOICE_MIN_MSAT: u64 = SDK_HTLC_MIN_MSAT;
const SDK_UTXO_NUM: u8 = 4;
const SDK_UTXO_SIZE_SAT: u32 = 32_000;
const SDK_DUST_LIMIT_MSAT: u64 = 546_000;
const SDK_MAX_SWAP_FEE_MSAT: u64 = SDK_HTLC_MIN_MSAT;
const SDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA: u32 = 14;
const SDK_VIRTUAL_OPEN_MODE_TRUSTED_NO_BROADCAST: &str = "trusted_no_broadcast";

struct OpenChannelVirtualIntentGuard {
    unlocked_state: Arc<crate::utils::UnlockedAppState>,
    temporary_channel_id: Option<ChannelId>,
}

impl OpenChannelVirtualIntentGuard {
    fn new(
        unlocked_state: Arc<crate::utils::UnlockedAppState>,
        temporary_channel_id: ChannelId,
    ) -> Self {
        Self {
            unlocked_state,
            temporary_channel_id: Some(temporary_channel_id),
        }
    }

    fn disarm(&mut self) {
        self.temporary_channel_id = None;
    }
}

impl Drop for OpenChannelVirtualIntentGuard {
    fn drop(&mut self) {
        if let Some(temporary_channel_id) = self.temporary_channel_id.take() {
            self.unlocked_state
                .virtual_channel_draft_delete(&temporary_channel_id);
        }
    }
}

fn check_changing_state(state: &AppState) -> Result<(), APIError> {
    if *state.changing_state.lock().unwrap() {
        return Err(APIError::ChangingState);
    }
    Ok(())
}

async fn check_locked(
    state: &Arc<AppState>,
) -> Result<tokio::sync::MutexGuard<'_, Option<Arc<crate::utils::UnlockedAppState>>>, APIError> {
    check_changing_state(state)?;
    let unlocked_app_state = state.unlocked_app_state.lock().await;
    if unlocked_app_state.is_some() {
        Err(APIError::UnlockedNode)
    } else {
        Ok(unlocked_app_state)
    }
}

async fn check_unlocked(
    state: &Arc<AppState>,
) -> Result<tokio::sync::MutexGuard<'_, Option<Arc<crate::utils::UnlockedAppState>>>, APIError> {
    check_changing_state(state)?;
    let unlocked_app_state = state.unlocked_app_state.lock().await;
    if unlocked_app_state.is_none() {
        Err(APIError::LockedNode)
    } else {
        Ok(unlocked_app_state)
    }
}

fn update_changing_state(state: &Arc<AppState>, updated: bool) {
    let mut changing_state = state.changing_state.lock().unwrap();
    *changing_state = updated;
}

fn update_ldk_background_services(
    state: &Arc<AppState>,
    updated: Option<crate::ldk::LdkBackgroundServices>,
) {
    let mut ldk_background_services = state.ldk_background_services.lock().unwrap();
    *ldk_background_services = updated;
}

async fn update_unlocked_app_state(
    state: &Arc<AppState>,
    updated: Option<Arc<crate::utils::UnlockedAppState>>,
) {
    let mut unlocked_app_state = state.unlocked_app_state.lock().await;
    *unlocked_app_state = updated;
}

pub(crate) struct NodeInfoData {
    pub(crate) pubkey: String,
    pub(crate) num_channels: usize,
    pub(crate) num_usable_channels: usize,
    pub(crate) local_balance_sat: u64,
    pub(crate) eventual_close_fees_sat: u64,
    pub(crate) pending_outbound_payments_sat: u64,
    pub(crate) num_peers: usize,
    pub(crate) account_xpub_vanilla: String,
    pub(crate) account_xpub_colored: String,
    pub(crate) max_media_upload_size_mb: u16,
    pub(crate) rgb_htlc_min_msat: u64,
    pub(crate) rgb_channel_capacity_min_sat: u64,
    pub(crate) channel_capacity_min_sat: u64,
    pub(crate) channel_capacity_max_sat: u64,
    pub(crate) channel_asset_min_amount: u64,
    pub(crate) channel_asset_max_amount: u64,
    pub(crate) network_nodes: usize,
    pub(crate) network_channels: usize,
}

pub(crate) struct NetworkInfoData {
    pub(crate) network: RgbBitcoinNetwork,
    pub(crate) height: u32,
}

pub(crate) struct AddressData {
    pub(crate) address: String,
}

pub(crate) struct AssetBalanceData {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
    pub(crate) offchain_outbound: u64,
    pub(crate) offchain_inbound: u64,
}

pub(crate) struct AssetMetadataData {
    pub(crate) asset_schema: RgbLibAssetSchema,
    pub(crate) initial_supply: u64,
    pub(crate) max_supply: u64,
    pub(crate) known_circulating_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) name: String,
    pub(crate) precision: u8,
    pub(crate) ticker: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) token: Option<Token>,
}

pub(crate) struct BtcBalance {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
}

pub(crate) struct BtcBalanceData {
    pub(crate) vanilla: BtcBalance,
    pub(crate) colored: BtcBalance,
}

pub(crate) struct DecodeLnInvoiceData {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) expiry_sec: u64,
    pub(crate) timestamp: u64,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) payment_hash: String,
    pub(crate) payment_secret: String,
    pub(crate) payee_pubkey: Option<String>,
    pub(crate) min_final_cltv_expiry_delta: u64,
    pub(crate) network: RgbBitcoinNetwork,
}

pub(crate) struct DecodeRgbInvoiceData {
    pub(crate) recipient_id: String,
    pub(crate) recipient_type: RgbLibRecipientType,
    pub(crate) asset_schema: Option<RgbLibAssetSchema>,
    pub(crate) asset_id: Option<String>,
    pub(crate) assignment: RgbLibAssignment,
    pub(crate) network: RgbBitcoinNetwork,
    pub(crate) expiration_timestamp: Option<i64>,
    pub(crate) transport_endpoints: Vec<String>,
}

pub(crate) struct EstimateFeeData {
    pub(crate) fee_rate: f64,
}

pub(crate) struct AssetMediaData {
    pub(crate) bytes_hex: String,
}

pub(crate) struct ChannelIdData {
    pub(crate) channel_id: String,
}

pub(crate) struct InvoiceStatusData {
    pub(crate) status: InvoiceStatus,
}

pub(crate) struct CheckIndexerUrlData {
    pub(crate) indexer_protocol: RgbLibIndexerProtocol,
}

pub(crate) struct SignMessageData {
    pub(crate) signed_message: String,
}

pub(crate) struct SendRgbData {
    pub(crate) txid: String,
    pub(crate) batch_transfer_idx: i32,
}

pub(crate) enum AssignmentKindData {
    Fungible,
    NonFungible,
    InflationRight,
    ReplaceRight,
    Any,
}

fn rgb_assignment_from_kind(
    assignment_kind: AssignmentKindData,
    assignment_amount: Option<u64>,
) -> Result<RgbLibAssignment, APIError> {
    match (assignment_kind, assignment_amount) {
        (AssignmentKindData::Fungible, Some(v)) => Ok(RgbLibAssignment::Fungible(v)),
        (AssignmentKindData::InflationRight, Some(v)) => Ok(RgbLibAssignment::InflationRight(v)),
        (AssignmentKindData::NonFungible, None) => Ok(RgbLibAssignment::NonFungible),
        (AssignmentKindData::Any, None) => Ok(RgbLibAssignment::Any),
        _ => Err(APIError::InvalidAmount(
            "invalid RGB assignment payload".to_string(),
        )),
    }
}

pub(crate) struct WitnessDataInput {
    pub(crate) amount_sat: u64,
    pub(crate) blinding: Option<u64>,
}

pub(crate) struct RecipientInput {
    pub(crate) recipient_id: String,
    pub(crate) witness_data: Option<WitnessDataInput>,
    pub(crate) assignment_kind: AssignmentKindData,
    pub(crate) assignment_amount: Option<u64>,
    pub(crate) transport_endpoints: Vec<String>,
}

pub(crate) struct AssetRecipientsInput {
    pub(crate) asset_id: String,
    pub(crate) recipients: Vec<RecipientInput>,
}

pub(crate) struct SendRgbRequestData {
    pub(crate) donation: bool,
    pub(crate) fee_rate: u64,
    pub(crate) min_confirmations: u8,
    pub(crate) recipient_groups: Vec<AssetRecipientsInput>,
}

pub(crate) struct InitData {
    pub(crate) mnemonic: String,
}

pub(crate) struct UnlockRequest {
    pub(crate) password: String,
    pub(crate) bitcoind_rpc_username: String,
    pub(crate) bitcoind_rpc_password: String,
    pub(crate) bitcoind_rpc_host: String,
    pub(crate) bitcoind_rpc_port: u16,
    pub(crate) indexer_url: Option<String>,
    pub(crate) proxy_endpoint: Option<String>,
    pub(crate) announce_addresses: Vec<String>,
    pub(crate) announce_alias: Option<String>,
}

fn validate_external_signer_bootstrap(bootstrap: &BootstrapData) -> Result<(), APIError> {
    if bootstrap.api_level != SUPPORTED_SIGNER_API_LEVEL {
        return Err(APIError::ExternalSignerProtocolError(format!(
            "unsupported external signer api_level {}, expected {}",
            bootstrap.api_level, SUPPORTED_SIGNER_API_LEVEL
        )));
    }
    validate_bootstrap_payload(bootstrap)
        .map_err(|e| APIError::ExternalSignerProtocolError(e.to_string()))
}

pub(crate) struct VssClearFenceRequest {
    pub(crate) password: String,
}

pub(crate) struct OpenChannelRequestData {
    pub(crate) peer_pubkey_and_opt_addr: String,
    pub(crate) capacity_sat: u64,
    pub(crate) push_msat: u64,
    pub(crate) public: bool,
    pub(crate) with_anchors: bool,
    pub(crate) fee_base_msat: Option<u32>,
    pub(crate) fee_proportional_millionths: Option<u32>,
    pub(crate) temporary_channel_id: Option<String>,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) push_asset_amount: Option<u64>,
    pub(crate) virtual_open_mode: Option<String>,
}

pub(crate) struct OpenChannelData {
    pub(crate) temporary_channel_id: String,
}

pub(crate) struct DisconnectPeerRequestData {
    pub(crate) peer_pubkey: String,
}

pub(crate) struct CloseChannelRequestData {
    pub(crate) channel_id: String,
    pub(crate) peer_pubkey: String,
    pub(crate) force: bool,
}

pub(crate) struct SendPaymentRequestData {
    pub(crate) invoice: String,
    pub(crate) amt_msat: Option<u64>,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
}

pub(crate) struct SendPaymentData {
    pub(crate) payment_id: String,
    pub(crate) payment_hash: Option<String>,
    pub(crate) payment_secret: Option<String>,
    pub(crate) status: HtlcStatus,
}

pub(crate) struct RefreshTransfersRequestData {
    pub(crate) skip_sync: bool,
}

pub(crate) struct FailTransfersRequestData {
    pub(crate) batch_transfer_idx: Option<i32>,
    pub(crate) no_asset_only: bool,
    pub(crate) skip_sync: bool,
}

pub(crate) struct FailTransfersData {
    pub(crate) transfers_changed: bool,
}

pub(crate) struct CreateUtxosRequestData {
    pub(crate) up_to: bool,
    pub(crate) num: Option<u8>,
    pub(crate) size: Option<u32>,
    pub(crate) fee_rate: u64,
    pub(crate) skip_sync: bool,
}

pub(crate) struct IssueAssetNiaRequestData {
    pub(crate) amounts: Vec<u64>,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) precision: u8,
}

pub(crate) struct IssueAssetCfaRequestData {
    pub(crate) amounts: Vec<u64>,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) file_digest: Option<String>,
}

pub(crate) struct IssueAssetIFARequestData {
    pub(crate) amounts: Vec<u64>,
    pub(crate) inflation_amounts: Vec<u64>,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) precision: u8,
    pub(crate) reject_list_url: Option<String>,
}

pub(crate) struct IssueAssetUdaRequestData {
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) media_file_digest: Option<String>,
    pub(crate) attachments_file_digests: Vec<String>,
}

pub(crate) struct KeysendRequestData {
    pub(crate) dest_pubkey: String,
    pub(crate) amt_msat: u64,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
}

pub(crate) struct KeysendData {
    pub(crate) payment_hash: String,
    pub(crate) payment_preimage: String,
    pub(crate) status: HtlcStatus,
}

pub(crate) struct SendBtcRequestData {
    pub(crate) amount: u64,
    pub(crate) address: String,
    pub(crate) fee_rate: u64,
    pub(crate) skip_sync: bool,
}

pub(crate) struct SendBtcData {
    pub(crate) txid: String,
}

pub(crate) struct MakerInitRequestData {
    pub(crate) qty_from: u64,
    pub(crate) qty_to: u64,
    pub(crate) from_asset: Option<String>,
    pub(crate) to_asset: Option<String>,
    pub(crate) timeout_sec: u32,
}

pub(crate) struct MakerInitData {
    pub(crate) payment_hash: String,
    pub(crate) payment_secret: String,
    pub(crate) swapstring: String,
}

pub(crate) struct MakerExecuteRequestData {
    pub(crate) swapstring: String,
    pub(crate) payment_secret: String,
    pub(crate) taker_pubkey: String,
}

pub(crate) struct TakerRequestData {
    pub(crate) swapstring: String,
}

pub(crate) struct SendOnionMessageRequestData {
    pub(crate) node_ids: Vec<String>,
    pub(crate) tlv_type: u64,
    pub(crate) data: String,
}

pub(crate) struct PostAssetMediaData {
    pub(crate) digest: String,
}

pub(crate) struct RgbInvoiceRequestData {
    pub(crate) asset_id: Option<String>,
    pub(crate) assignment_kind: Option<AssignmentKindData>,
    pub(crate) assignment_amount: Option<u64>,
    pub(crate) duration_seconds: Option<u32>,
    pub(crate) min_confirmations: u8,
    pub(crate) witness: bool,
}

pub(crate) struct RgbInvoiceData {
    pub(crate) recipient_id: String,
    pub(crate) invoice: String,
    pub(crate) expiration_timestamp: Option<i64>,
    pub(crate) batch_transfer_idx: i32,
}

pub(crate) struct ListAssetsData {
    pub(crate) nia: Option<Vec<AssetNIA>>,
    pub(crate) uda: Option<Vec<AssetUDA>>,
    pub(crate) cfa: Option<Vec<AssetCFA>>,
    pub(crate) ifa: Option<Vec<AssetIFA>>,
}

pub(crate) struct LnInvoiceData {
    pub(crate) invoice: String,
}

pub(crate) struct PaymentData {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) asset_id: Option<String>,
    pub(crate) payment_hash: String,
    pub(crate) payment_type: PaymentType,
    pub(crate) status: HtlcStatus,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) payee_pubkey: String,
    pub(crate) preimage: Option<String>,
}

pub(crate) struct CancelHodlInvoiceRequestData {
    pub(crate) payment_hash: String,
}

pub(crate) struct ClaimHodlInvoiceRequestData {
    pub(crate) payment_hash: String,
    pub(crate) payment_preimage: String,
}

pub(crate) struct ClaimHodlInvoiceResponseData {
    pub(crate) changed: bool,
}

pub(crate) struct InflateRequestData {
    pub(crate) asset_id: String,
    pub(crate) inflation_amounts: Vec<u64>,
    pub(crate) fee_rate: u64,
    pub(crate) min_confirmations: u8,
}

pub(crate) struct InflateResponseData {
    pub(crate) txid: String,
}

pub(crate) struct ChannelData {
    pub(crate) channel_id: String,
    pub(crate) funding_txid: Option<String>,
    pub(crate) peer_pubkey: String,
    pub(crate) peer_alias: Option<String>,
    pub(crate) short_channel_id: Option<u64>,
    pub(crate) status: ChannelStatus,
    pub(crate) ready: bool,
    pub(crate) capacity_sat: u64,
    pub(crate) local_balance_sat: u64,
    pub(crate) outbound_balance_msat: u64,
    pub(crate) inbound_balance_msat: u64,
    pub(crate) next_outbound_htlc_limit_msat: u64,
    pub(crate) next_outbound_htlc_minimum_msat: u64,
    pub(crate) is_usable: bool,
    pub(crate) public: bool,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_local_amount: Option<u64>,
    pub(crate) asset_remote_amount: Option<u64>,
    pub(crate) virtual_open_mode: Option<String>,
}

pub(crate) struct TransactionData {
    pub(crate) transaction_type: TransactionType,
    pub(crate) txid: String,
    pub(crate) received: u64,
    pub(crate) sent: u64,
    pub(crate) fee: u64,
    pub(crate) confirmation_time: Option<BlockTime>,
}

pub(crate) struct TransferTransportEndpointData {
    pub(crate) endpoint: String,
    pub(crate) transport_type: TransportType,
    pub(crate) used: bool,
}

pub(crate) struct TransferData {
    pub(crate) idx: i32,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) status: TransferStatus,
    pub(crate) requested_assignment: Option<RgbLibAssignment>,
    pub(crate) assignments: Vec<RgbLibAssignment>,
    pub(crate) kind: TransferKind,
    pub(crate) txid: Option<String>,
    pub(crate) recipient_id: Option<String>,
    pub(crate) receive_utxo: Option<String>,
    pub(crate) change_utxo: Option<String>,
    pub(crate) expiration: Option<i64>,
    pub(crate) transport_endpoints: Vec<TransferTransportEndpointData>,
}

pub(crate) struct RgbAllocationData {
    pub(crate) asset_id: Option<String>,
    pub(crate) assignment: RgbLibAssignment,
    pub(crate) settled: bool,
}

pub(crate) struct UtxoData {
    pub(crate) outpoint: String,
    pub(crate) btc_amount: u64,
    pub(crate) colorable: bool,
}

pub(crate) struct UnspentData {
    pub(crate) utxo: UtxoData,
    pub(crate) rgb_allocations: Vec<RgbAllocationData>,
}

pub(crate) struct PeerData {
    pub(crate) pubkey: String,
}

pub(crate) struct SwapViewData {
    pub(crate) qty_from: u64,
    pub(crate) qty_to: u64,
    pub(crate) from_asset: Option<String>,
    pub(crate) to_asset: Option<String>,
    pub(crate) payment_hash: String,
    pub(crate) status: SwapStatus,
    pub(crate) requested_at: u64,
    pub(crate) initiated_at: Option<u64>,
    pub(crate) expires_at: u64,
    pub(crate) completed_at: Option<u64>,
}

pub(crate) struct SwapListData {
    pub(crate) taker: Vec<SwapViewData>,
    pub(crate) maker: Vec<SwapViewData>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum ChannelStatus {
    #[default]
    Opening,
    Opened,
    Closing,
}

pub(crate) type HtlcStatus = crate::core_types::HTLCStatus;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaymentType {
    Outbound,
    InboundAutoClaim,
    InboundHodl,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum InvoiceStatus {
    Pending,
    Claimable,
    Claiming,
    Succeeded,
    Cancelled,
    Failed,
    Expired,
}

pub(crate) type SwapStatus = crate::core_types::SwapStatus;

#[derive(Debug)]
pub(crate) struct BlockTime {
    pub(crate) height: u32,
    pub(crate) timestamp: u64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TransactionType {
    RgbSend,
    Drain,
    CreateUtxos,
    SendBtc,
    Incoming,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TransferKind {
    Issuance,
    ReceiveBlind,
    ReceiveWitness,
    Send,
    Inflation,
    Burn,
}

#[derive(Debug, PartialEq)]
pub(crate) enum TransferStatus {
    Initiated,
    WaitingCounterparty,
    WaitingSafeHeight,
    WaitingConfirmations,
    Settled,
    Failed,
}

#[derive(Debug)]
pub(crate) enum TransportType {
    JsonRpc,
}

pub(crate) struct EmbeddedMedia {
    pub(crate) mime: String,
    pub(crate) data: Vec<u8>,
}

impl From<RgbLibEmbeddedMedia> for EmbeddedMedia {
    fn from(value: RgbLibEmbeddedMedia) -> Self {
        Self {
            mime: value.mime,
            data: value.data,
        }
    }
}

pub(crate) struct Media {
    pub(crate) file_path: String,
    pub(crate) digest: String,
    pub(crate) mime: String,
}

impl From<RgbLibMedia> for Media {
    fn from(value: RgbLibMedia) -> Self {
        Self {
            file_path: value.file_path,
            digest: value.digest,
            mime: value.mime,
        }
    }
}

pub(crate) struct ProofOfReserves {
    pub(crate) utxo: String,
    pub(crate) proof: Vec<u8>,
}

impl From<RgbLibProofOfReserves> for ProofOfReserves {
    fn from(value: RgbLibProofOfReserves) -> Self {
        Self {
            utxo: value.utxo.to_string(),
            proof: value.proof,
        }
    }
}

pub(crate) struct Token {
    pub(crate) index: u32,
    pub(crate) ticker: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) embedded_media: Option<EmbeddedMedia>,
    pub(crate) media: Option<Media>,
    pub(crate) attachments: HashMap<u8, Media>,
    pub(crate) reserves: Option<ProofOfReserves>,
}

impl From<RgbLibToken> for Token {
    fn from(value: RgbLibToken) -> Self {
        Self {
            index: value.index,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            embedded_media: value.embedded_media.map(Into::into),
            media: value.media.map(Into::into),
            attachments: value
                .attachments
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            reserves: value.reserves.map(Into::into),
        }
    }
}

pub(crate) struct TokenLight {
    pub(crate) index: u32,
    pub(crate) ticker: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) details: Option<String>,
    pub(crate) embedded_media: bool,
    pub(crate) media: Option<Media>,
    pub(crate) attachments: HashMap<u8, Media>,
    pub(crate) reserves: bool,
}

impl From<RgbLibTokenLight> for TokenLight {
    fn from(value: RgbLibTokenLight) -> Self {
        Self {
            index: value.index,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            embedded_media: value.embedded_media,
            media: value.media.map(Into::into),
            attachments: value
                .attachments
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            reserves: value.reserves,
        }
    }
}

pub(crate) struct AssetBalance {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
    pub(crate) offchain_outbound: u64,
    pub(crate) offchain_inbound: u64,
}

pub(crate) struct AssetNIA {
    pub(crate) asset_id: String,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) issued_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) media: Option<Media>,
}

impl From<RgbLibAssetNIA> for AssetNIA {
    fn from(value: RgbLibAssetNIA) -> Self {
        Self {
            asset_id: value.asset_id,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            precision: value.precision,
            issued_supply: value.issued_supply,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            media: value.media.map(Into::into),
        }
    }
}

pub(crate) struct AssetUDA {
    pub(crate) asset_id: String,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) token: Option<TokenLight>,
}

impl From<RgbLibAssetUDA> for AssetUDA {
    fn from(value: RgbLibAssetUDA) -> Self {
        Self {
            asset_id: value.asset_id,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            precision: value.precision,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            token: value.token.map(Into::into),
        }
    }
}

pub(crate) struct AssetCFA {
    pub(crate) asset_id: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) issued_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) media: Option<Media>,
}

impl From<RgbLibAssetCFA> for AssetCFA {
    fn from(value: RgbLibAssetCFA) -> Self {
        Self {
            asset_id: value.asset_id,
            name: value.name,
            details: value.details,
            precision: value.precision,
            issued_supply: value.issued_supply,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            media: value.media.map(Into::into),
        }
    }
}

pub(crate) struct AssetIFA {
    pub(crate) asset_id: String,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) details: Option<String>,
    pub(crate) precision: u8,
    pub(crate) initial_supply: u64,
    pub(crate) max_supply: u64,
    pub(crate) known_circulating_supply: u64,
    pub(crate) timestamp: i64,
    pub(crate) added_at: i64,
    pub(crate) balance: AssetBalance,
    pub(crate) media: Option<Media>,
    pub(crate) reject_list_url: Option<String>,
}

impl From<RgbLibAssetIFA> for AssetIFA {
    fn from(value: RgbLibAssetIFA) -> Self {
        Self {
            asset_id: value.asset_id,
            ticker: value.ticker,
            name: value.name,
            details: value.details,
            precision: value.precision,
            initial_supply: value.initial_supply,
            max_supply: value.max_supply,
            known_circulating_supply: value.known_circulating_supply,
            timestamp: value.timestamp,
            added_at: value.added_at,
            balance: AssetBalance {
                settled: value.balance.settled,
                future: value.balance.future,
                spendable: value.balance.spendable,
                offchain_outbound: 0,
                offchain_inbound: 0,
            },
            media: value.media.map(Into::into),
            reject_list_url: value.reject_list_url,
        }
    }
}

/*
 * -------------------------------------------------------------------------
 * ROUTES-PARITY METHODS
 * -------------------------------------------------------------------------
 * The async functions below intentionally mirror business logic from
 * `src/routes.rs` (same validations and core behavior, SDK-shaped inputs/outputs).
 * When route logic changes, review and update the corresponding method here.
 */

pub(crate) async fn estimate_fee(
    state: Arc<AppState>,
    blocks: u16,
) -> Result<EstimateFeeData, APIError> {
    let fee_rate = check_unlocked(&state)
        .await?
        .clone()
        .unwrap()
        .rgb_get_fee_estimation(blocks)?;
    Ok(EstimateFeeData { fee_rate })
}

pub(crate) async fn check_indexer_url(
    state: Arc<AppState>,
    indexer_url: String,
) -> Result<CheckIndexerUrlData, APIError> {
    let indexer_protocol = rgb_lib_check_indexer_url(&indexer_url, state.static_state.network)?;
    Ok(CheckIndexerUrlData { indexer_protocol })
}

pub(crate) async fn check_proxy_endpoint(proxy_endpoint: String) -> Result<(), APIError> {
    check_rgb_proxy_endpoint(&proxy_endpoint).await?;
    Ok(())
}

pub(crate) async fn node_info(state: Arc<AppState>) -> Result<NodeInfoData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let chans = unlocked_state.channel_manager.list_channels();

    let balances = unlocked_state.chain_monitor.get_claimable_balances(&[]);
    let local_balance_sat = balances
        .iter()
        .map(|b| b.claimable_amount_satoshis())
        .sum::<u64>();

    let close_fees_map = |b| match b {
        &Balance::ClaimableOnChannelClose {
            ref balance_candidates,
            confirmed_balance_candidate_index,
            ..
        } => balance_candidates[confirmed_balance_candidate_index].transaction_fee_satoshis,
        _ => 0,
    };
    let eventual_close_fees_sat = balances.iter().map(close_fees_map).sum::<u64>();

    let pending_payments_map = |b| match b {
        &Balance::MaybeTimeoutClaimableHTLC {
            amount_satoshis,
            outbound_payment,
            ..
        } if outbound_payment => amount_satoshis,
        _ => 0,
    };
    let pending_outbound_payments_sat = balances.iter().map(pending_payments_map).sum::<u64>();

    let graph_lock = unlocked_state.network_graph.read_only();
    let network_nodes = graph_lock.nodes().len();
    let network_channels = graph_lock.channels().len();

    let wallet_data = unlocked_state.rgb_get_keys();

    Ok(NodeInfoData {
        pubkey: unlocked_state.runtime_node_pubkey(),
        num_channels: chans.len(),
        num_usable_channels: chans.iter().filter(|c| c.is_usable).count(),
        local_balance_sat,
        eventual_close_fees_sat,
        pending_outbound_payments_sat,
        num_peers: unlocked_state.peer_manager.list_peers().len(),
        account_xpub_vanilla: wallet_data.account_xpub_vanilla,
        account_xpub_colored: wallet_data.account_xpub_colored,
        max_media_upload_size_mb: state.static_state.max_media_upload_size_mb,
        rgb_htlc_min_msat: SDK_HTLC_MIN_MSAT,
        rgb_channel_capacity_min_sat: SDK_OPENRGBCHANNEL_MIN_SAT,
        channel_capacity_min_sat: SDK_OPENCHANNEL_MIN_SAT,
        channel_capacity_max_sat: SDK_OPENCHANNEL_MAX_SAT,
        channel_asset_min_amount: SDK_OPENCHANNEL_MIN_RGB_AMT,
        channel_asset_max_amount: u64::MAX,
        network_nodes,
        network_channels,
    })
}

pub(crate) async fn network_info(state: Arc<AppState>) -> Result<NetworkInfoData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    let best_block = unlocked_state.channel_manager.current_best_block();

    Ok(NetworkInfoData {
        network: state.static_state.network,
        height: best_block.height,
    })
}

pub(crate) async fn address(state: Arc<AppState>) -> Result<AddressData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    Ok(AddressData {
        address: unlocked_state.rgb_get_address()?,
    })
}

pub(crate) async fn async_order_new(
    state: Arc<AppState>,
    request: AsyncOrderNewRequest,
) -> Result<AsyncOrderNewResponse, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = Arc::clone(guard.as_ref().unwrap());
    drop(guard);

    let host_node_id =
        hex_str_to_compressed_pubkey(&request.host_node_id).ok_or(APIError::InvalidPubkey)?;
    if unlocked_state
        .peer_manager
        .peer_by_node_id(&host_node_id)
        .is_none()
    {
        return Err(APIError::InvalidPeerInfo(s!(
            "/apay/new requires a connected host peer"
        )));
    }

    let params = unlocked_state
        .async_payments_preimage_root
        .prepare_async_order_new_params(
            read_async_payments_next_hash_index(unlocked_state.kv_store.as_ref(), &host_node_id)
                .map_err(|err| APIError::Unexpected(err.message))?,
            ASYNC_ORDER_MAX_HASH_BATCH_SIZE,
        )
        .map_err(|err| APIError::InvalidRequest(err.message))?;
    let hashes = params.hashes.clone();
    let first_hash_index = hashes
        .first()
        .map(|entry| entry.hash_index)
        .expect("validated async_order.new hash batch is non-empty");
    let last_hash_index = hashes
        .last()
        .map(|entry| entry.hash_index)
        .expect("validated async_order.new hash batch is non-empty");
    let request_id = new_jsonrpc_request_id();

    let response_rx = unlocked_state
        .async_order_handler
        .queue_async_order_new(host_node_id, Value::String(request_id.clone()), params)
        .map_err(|err| APIError::InvalidRequest(err.message))?;
    unlocked_state.peer_manager.process_events();
    let order_state_value = match timeout(
        Duration::from_secs(ASYNC_ORDER_RESPONSE_TIMEOUT_SECS),
        response_rx,
    )
    .await
    {
        Ok(Ok(Ok(result))) => result,
        Ok(Ok(Err(err))) => {
            return Err(APIError::InvalidRequest(format!(
                "async_order host error {}: {}",
                err.code, err.message
            )));
        }
        Ok(Err(_)) => {
            return Err(APIError::Network(s!(
                "/apay/new response channel closed before host replied"
            )))
        }
        Err(_) => {
            unlocked_state
                .async_order_handler
                .forget_async_order_response(host_node_id, &request_id);
            return Err(APIError::Network(s!(
                "/apay/new timed out waiting for host response"
            )));
        }
    };
    let order_state: AsyncOrderNewResultWire =
        serde_json::from_value(order_state_value).map_err(|err| {
            APIError::InvalidRequest(format!("invalid async_order.new response: {err}"))
        })?;
    let next_hash_index = order_state.next_index_expected;
    write_async_payments_next_hash_index(
        unlocked_state.kv_store.as_ref(),
        &host_node_id,
        next_hash_index,
    )
    .map_err(|err| APIError::Unexpected(err.message))?;

    Ok(AsyncOrderNewResponse {
        request_id,
        host_node_id: hex_str(&host_node_id.serialize()),
        protocol_version: order_state.protocol_version,
        order_id: order_state.order_id,
        status: order_state.status,
        accepted_through_index: order_state.accepted_through_index,
        next_index_expected: order_state.next_index_expected,
        unused_hashes: order_state.unused_hashes,
        refill_batch_size: order_state.refill_batch_size,
        first_hash_index,
        last_hash_index,
        hashes,
    })
}

pub(crate) async fn async_order_outbound_invoice(
    state: Arc<AppState>,
    request: AsyncOrderOutboundInvoiceRequest,
) -> Result<AsyncOrderOutboundInvoiceResponse, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = Arc::clone(guard.as_ref().unwrap());
    drop(guard);

    let peer_node_id =
        hex_str_to_compressed_pubkey(&request.client_node_id).ok_or(APIError::InvalidPubkey)?;
    if unlocked_state
        .peer_manager
        .peer_by_node_id(&peer_node_id)
        .is_none()
    {
        return Err(APIError::InvalidPeerInfo(s!(
            "/apay/outboundinvoice requires a connected recipient peer"
        )));
    }

    let request_id = new_jsonrpc_request_id();
    let response_rx = unlocked_state
        .async_order_handler
        .queue_async_order_request_invoice(
            peer_node_id,
            Value::String(request_id.clone()),
            request.params,
        )
        .map_err(|err| APIError::InvalidRequest(err.message))?;
    unlocked_state.peer_manager.process_events();

    let response_value = match timeout(
        Duration::from_secs(ASYNC_ORDER_RESPONSE_TIMEOUT_SECS),
        response_rx,
    )
    .await
    {
        Ok(Ok(Ok(result))) => result,
        Ok(Ok(Err(err))) => {
            return Err(APIError::InvalidRequest(format!(
                "async_order host error {}: {}",
                err.code, err.message
            )));
        }
        Ok(Err(_)) => {
            return Err(APIError::Network(s!(
                "/apay/outboundinvoice response channel closed before peer replied"
            )))
        }
        Err(_) => {
            unlocked_state
                .async_order_handler
                .forget_async_order_response(peer_node_id, &request_id);
            return Err(APIError::Network(s!(
                "/apay/outboundinvoice timed out waiting for peer response"
            )));
        }
    };

    let response: AsyncOrderOutboundInvoiceResultWire = serde_json::from_value(response_value)
        .map_err(|err| {
            APIError::InvalidRequest(format!("invalid request_invoice response: {err}"))
        })?;

    Ok(AsyncOrderOutboundInvoiceResponse {
        payment_hash: response.payment_hash,
        bolt11: response.bolt11,
    })
}

pub(crate) async fn btc_balance(
    state: Arc<AppState>,
    skip_sync: bool,
) -> Result<BtcBalanceData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    let btc_balance = unlocked_state.rgb_get_btc_balance(skip_sync)?;

    Ok(BtcBalanceData {
        vanilla: BtcBalance {
            settled: btc_balance.vanilla.settled,
            future: btc_balance.vanilla.future,
            spendable: btc_balance.vanilla.spendable,
        },
        colored: BtcBalance {
            settled: btc_balance.colored.settled,
            future: btc_balance.colored.future,
            spendable: btc_balance.colored.spendable,
        },
    })
}

pub(crate) async fn sign_message(
    state: Arc<AppState>,
    message: String,
) -> Result<SignMessageData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let trimmed = message.trim();
    let signed_message = unlocked_state.sign_node_message(trimmed.as_bytes())?;
    Ok(SignMessageData { signed_message })
}

pub(crate) async fn get_channel_id(
    state: Arc<AppState>,
    temporary_channel_id: String,
) -> Result<ChannelIdData, APIError> {
    let tmp_chan_id = check_channel_id(&temporary_channel_id)?;
    let channel_ids = check_unlocked(&state).await?.clone().unwrap().channel_ids();
    let channel_id = channel_ids
        .get(&tmp_chan_id)
        .map(|channel_id| channel_id.0.as_hex().to_string())
        .ok_or(APIError::UnknownTemporaryChannelId)?;

    Ok(ChannelIdData { channel_id })
}

pub(crate) async fn list_channels(state: Arc<AppState>) -> Result<Vec<ChannelData>, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut channels = vec![];
    let virtual_sessions = unlocked_state.virtual_channel_session_store();
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let status = match chan_info.channel_shutdown_state.unwrap() {
            ChannelShutdownState::NotShuttingDown => {
                if chan_info.is_channel_ready {
                    ChannelStatus::Opened
                } else {
                    ChannelStatus::Opening
                }
            }
            _ => ChannelStatus::Closing,
        };
        let mut channel = ChannelData {
            channel_id: chan_info.channel_id.0.as_hex().to_string(),
            peer_pubkey: hex_str(&chan_info.counterparty.node_id.serialize()),
            status,
            ready: chan_info.is_channel_ready,
            capacity_sat: chan_info.channel_value_satoshis,
            local_balance_sat: 0,
            outbound_balance_msat: chan_info.outbound_capacity_msat,
            inbound_balance_msat: chan_info.inbound_capacity_msat,
            next_outbound_htlc_limit_msat: chan_info.next_outbound_htlc_limit_msat,
            next_outbound_htlc_minimum_msat: chan_info.next_outbound_htlc_minimum_msat,
            is_usable: chan_info.is_usable,
            public: chan_info.is_announced,
            funding_txid: None,
            peer_alias: None,
            short_channel_id: None,
            asset_id: None,
            asset_local_amount: None,
            asset_remote_amount: None,
            virtual_open_mode: None,
        };

        if virtual_sessions.contains_key(&chan_info.channel_id) {
            channel.virtual_open_mode =
                Some(SDK_VIRTUAL_OPEN_MODE_TRUSTED_NO_BROADCAST.to_string());
        }

        if let Some(funding_txo) = chan_info.funding_txo {
            channel.funding_txid = Some(funding_txo.txid.to_string());
            if let Ok(chan_monitor) = unlocked_state
                .chain_monitor
                .get_monitor(chan_info.channel_id)
            {
                channel.local_balance_sat = chan_monitor
                    .get_claimable_balances()
                    .iter()
                    .map(|b| b.claimable_amount_satoshis())
                    .sum::<u64>();
            }
        }

        if let Some(node_info) = unlocked_state
            .network_graph
            .read_only()
            .nodes()
            .get(&NodeId::from_pubkey(&chan_info.counterparty.node_id))
        {
            if let Some(announcement) = &node_info.announcement_info {
                channel.peer_alias = Some(announcement.alias().to_string());
            }
        }

        channel.short_channel_id = chan_info.short_channel_id;

        let channel_id_str = chan_info.channel_id.0.as_hex().to_string();
        if let Ok(rgb_info) = unlocked_state
            .kv_store
            .read_rgb_channel_info(&channel_id_str, false)
        {
            channel.asset_id = Some(rgb_info.contract_id.to_string());
            channel.asset_local_amount = Some(rgb_info.local_rgb_amount);
            channel.asset_remote_amount = Some(rgb_info.remote_rgb_amount);
        }

        channels.push(channel);
    }

    Ok(channels)
}

pub(crate) async fn list_peers(state: Arc<AppState>) -> Result<Vec<PeerData>, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    Ok(unlocked_state
        .peer_manager
        .list_peers()
        .into_iter()
        .map(|peer_details| PeerData {
            pubkey: peer_details.counterparty_node_id.to_string(),
        })
        .collect())
}

pub(crate) async fn asset_balance(
    state: Arc<AppState>,
    asset_id: String,
) -> Result<AssetBalanceData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;
    let balance = unlocked_state.rgb_get_asset_balance(contract_id)?;

    let mut offchain_outbound = 0;
    let mut offchain_inbound = 0;
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let channel_id_str = chan_info.channel_id.0.as_hex().to_string();
        let rgb_info = match unlocked_state
            .kv_store
            .read_rgb_channel_info(&channel_id_str, false)
        {
            Ok(info) => info,
            Err(_) => continue,
        };
        if rgb_info.contract_id == contract_id {
            offchain_outbound += rgb_info.local_rgb_amount;
            offchain_inbound += rgb_info.remote_rgb_amount;
        }
    }

    Ok(AssetBalanceData {
        settled: balance.settled,
        future: balance.future,
        spendable: balance.spendable,
        offchain_outbound,
        offchain_inbound,
    })
}

pub(crate) async fn asset_metadata(
    state: Arc<AppState>,
    asset_id: String,
) -> Result<AssetMetadataData, APIError> {
    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;
    let metadata = check_unlocked(&state)
        .await?
        .clone()
        .unwrap()
        .rgb_get_asset_metadata(contract_id)?;

    Ok(AssetMetadataData {
        asset_schema: metadata.asset_schema,
        initial_supply: metadata.initial_supply,
        max_supply: metadata.max_supply,
        known_circulating_supply: metadata.known_circulating_supply,
        timestamp: metadata.timestamp,
        name: metadata.name,
        precision: metadata.precision,
        ticker: metadata.ticker,
        details: metadata.details,
        token: metadata.token.map(Into::into),
    })
}

pub(crate) async fn get_asset_media(
    state: Arc<AppState>,
    digest: String,
) -> Result<AssetMediaData, APIError> {
    let file_path = check_unlocked(&state)
        .await?
        .clone()
        .unwrap()
        .rgb_get_media_dir()
        .join(digest.to_lowercase());
    if !file_path.exists() {
        return Err(APIError::InvalidMediaDigest);
    }

    let mut buf_reader = BufReader::new(File::open(file_path).await?);
    let mut file_bytes = Vec::new();
    buf_reader.read_to_end(&mut file_bytes).await?;

    Ok(AssetMediaData {
        bytes_hex: hex_str(&file_bytes),
    })
}

pub(crate) async fn list_assets(
    state: Arc<AppState>,
    filter_asset_schemas: Vec<rgb_lib::AssetSchema>,
) -> Result<ListAssetsData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let rgb_assets = unlocked_state.rgb_list_assets(filter_asset_schemas)?;

    let mut offchain_balances = HashMap::new();
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let channel_id_str = chan_info.channel_id.0.as_hex().to_string();
        let rgb_info = match unlocked_state
            .kv_store
            .read_rgb_channel_info(&channel_id_str, false)
        {
            Ok(info) => info,
            Err(_) => continue,
        };
        offchain_balances
            .entry(rgb_info.contract_id.to_string())
            .and_modify(|(offchain_outbound, offchain_inbound)| {
                *offchain_outbound += rgb_info.local_rgb_amount;
                *offchain_inbound += rgb_info.remote_rgb_amount;
            })
            .or_insert((rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount));
    }

    let nia = rgb_assets.nia.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetNIA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });
    let uda = rgb_assets.uda.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetUDA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });
    let cfa = rgb_assets.cfa.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetCFA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });
    let ifa = rgb_assets.ifa.map(|assets| {
        assets
            .into_iter()
            .map(|a| {
                let mut asset: AssetIFA = a.into();
                (
                    asset.balance.offchain_outbound,
                    asset.balance.offchain_inbound,
                ) = *offchain_balances.get(&asset.asset_id).unwrap_or(&(0, 0));
                asset
            })
            .collect()
    });

    Ok(ListAssetsData { nia, uda, cfa, ifa })
}

pub(crate) async fn send_rgb(
    state: Arc<AppState>,
    recipient_map: HashMap<String, Vec<rgb_lib::wallet::Recipient>>,
    donation: bool,
    fee_rate: u64,
    min_confirmations: u8,
) -> Result<SendRgbData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let send_result = if unlocked_state.external_signer_mode {
        let unlocked_state_copy = unlocked_state.clone();
        let begin_result = tokio::task::spawn_blocking(move || {
            unlocked_state_copy.rgb_send_begin(
                recipient_map,
                donation,
                fee_rate,
                min_confirmations,
                None,
                false,
                None,
            )
        })
        .await
        .unwrap()?;
        let unlocked_state_copy = unlocked_state.clone();
        let signed_psbt = tokio::task::spawn_blocking(move || {
            unlocked_state_copy.rgb_sign_psbt(begin_result.psbt)
        })
        .await
        .unwrap()
        .map_err(|e| {
            tracing::error!("rgb_sign_psbt failed during RGB send: {e}");
            APIError::from(e)
        })?;
        let unlocked_state_copy = unlocked_state.clone();
        tokio::task::spawn_blocking(move || unlocked_state_copy.rgb_send_end(signed_psbt))
            .await
            .unwrap()?
    } else {
        let unlocked_state_copy = unlocked_state.clone();
        tokio::task::spawn_blocking(move || {
            unlocked_state_copy.rgb_send(recipient_map, donation, fee_rate, min_confirmations, None)
        })
        .await
        .unwrap()?
    };

    Ok(SendRgbData {
        txid: send_result.txid,
        batch_transfer_idx: send_result.batch_transfer_idx,
    })
}

pub(crate) async fn send_rgb_from_groups(
    state: Arc<AppState>,
    request: SendRgbRequestData,
) -> Result<SendRgbData, APIError> {
    if request.recipient_groups.is_empty() {
        return Err(APIError::InvalidAmount(
            "recipient_groups cannot be empty".to_string(),
        ));
    }

    let recipient_map = request
        .recipient_groups
        .into_iter()
        .map(|group| {
            let recipients = group
                .recipients
                .into_iter()
                .map(|r| {
                    let assignment =
                        rgb_assignment_from_kind(r.assignment_kind, r.assignment_amount)?;
                    let recipient = RgbLibRecipient {
                        recipient_id: r.recipient_id,
                        witness_data: r.witness_data.map(|w| RgbLibWitnessData {
                            amount_sat: w.amount_sat,
                            blinding: w.blinding,
                        }),
                        assignment,
                        transport_endpoints: r.transport_endpoints,
                    };
                    Ok::<RgbLibRecipient, APIError>(recipient)
                })
                .collect::<Result<Vec<_>, APIError>>()?;
            Ok((group.asset_id, recipients))
        })
        .collect::<Result<HashMap<_, _>, APIError>>()?;

    send_rgb(
        state,
        recipient_map,
        request.donation,
        request.fee_rate,
        request.min_confirmations,
    )
    .await
}

pub(crate) async fn init(
    state: Arc<AppState>,
    password: String,
    mnemonic: Option<String>,
) -> Result<InitData, APIError> {
    let _unlocked_state = check_locked(&state).await?;
    if is_external_signer_mode_configured(&state)? {
        return Err(APIError::ExternalSignerRequired);
    }

    check_password_strength(password.clone())?;
    check_already_initialized(&state.db())?;

    let mnemonic = match mnemonic {
        Some(mnemonic) => Mnemonic::from_str(&mnemonic)
            .map_err(|e| APIError::InvalidMnemonic(e.to_string()))?
            .to_string(),
        None => generate_keys(state.static_state.network, WitnessVersion::Taproot).mnemonic,
    };

    encrypt_and_save_mnemonic(password, mnemonic.clone(), &state.db())?;
    Ok(InitData { mnemonic })
}

pub(crate) async fn init_with_external_signer(
    state: Arc<AppState>,
    key_source: KeySourceFile,
) -> Result<(), APIError> {
    if key_source.api_level != SUPPORTED_SIGNER_API_LEVEL {
        return Err(APIError::ExternalSignerProtocolError(format!(
            "unsupported external signer api_level {}, expected {}",
            key_source.api_level, SUPPORTED_SIGNER_API_LEVEL
        )));
    }
    let _unlocked_state = check_locked(&state).await?;
    check_already_initialized(&state.db())?;

    if read_key_source_file(&state.static_state.storage_dir_path)
        .map_err(|e| APIError::ExternalSignerProtocolError(e.to_string()))?
        .is_some()
    {
        return Err(APIError::AlreadyInitialized);
    }

    write_key_source_file(&state.static_state.storage_dir_path, &key_source)
        .map_err(|e| APIError::ExternalSignerProtocolError(e.to_string()))?;
    Ok(())
}

/// Triggers a synchronous RGB-wallet backup to VSS, returning the
/// server-side version of the uploaded backup. Mirrors `/vssbackup`.
///
/// The auto-backup path runs asynchronously, so this entry point is what
/// callers reach for when they need a *deterministic* push — e.g. before
/// shutting a node down or in tests that verify VSS restore.
pub(crate) async fn vss_backup(state: Arc<AppState>) -> Result<i64, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap().clone();
    drop(guard);

    #[cfg(not(feature = "vss"))]
    {
        let _ = unlocked_state;
        Err(APIError::Unexpected(
            "VSS support is not compiled in".to_string(),
        ))
    }

    #[cfg(feature = "vss")]
    {
        let vss_client = unlocked_state
            .rgb_wallet_wrapper
            .vss_client()
            .ok_or_else(|| APIError::Unexpected("VSS is not configured".to_string()))?;

        let wrapper = unlocked_state.rgb_wallet_wrapper.clone();
        let version = tokio::task::spawn_blocking(move || {
            let wallet = wrapper.get_rgb_wallet();
            let rt = vss_client.handle().clone();
            rt.block_on(wallet.vss_backup(&vss_client))
        })
        .await
        .map_err(|e| APIError::Unexpected(format!("VSS backup task failed: {e}")))?
        .map_err(|e| APIError::Unexpected(format!("VSS backup failed: {e}")))?;

        Ok(version)
    }
}

/// Clears the VSS single-writer fence so a fresh instance can take over a
/// store whose previous owner did not release it (the normal case after any
/// shutdown — `acquire_fence` writes the fence but no code path deletes it).
///
/// Must be called on a locked node (the unlock path acquires the fence
/// itself, so clearing it while unlocked would race against the periodic
/// re-check and panic the running instance).
pub(crate) async fn vss_clear_fence(
    state: Arc<AppState>,
    request: VssClearFenceRequest,
) -> Result<(), APIError> {
    let _locked_state = check_locked(&state).await?;

    #[cfg(not(feature = "vss"))]
    {
        let _ = request;
        Err(APIError::Unexpected(
            "VSS support is not compiled in".to_string(),
        ))
    }

    #[cfg(feature = "vss")]
    {
        let vss_url = state
            .static_state
            .vss_url
            .clone()
            .ok_or_else(|| APIError::FailedVssInit("VSS is not configured".to_string()))?;

        let mnemonic = check_password_validity(&request.password, &state.db())?;
        let identity = derive_vss_identity(&mnemonic, state.static_state.network.into())?;

        tokio::task::spawn_blocking(move || {
            let store = crate::vss_kv_store::VssKvStore::new(
                vss_url,
                identity.pubkey_hex,
                identity.signing_key,
            )?;
            store.delete_fence()
        })
        .await
        .map_err(|e| APIError::Unexpected(format!("vss_clear_fence task failed: {e}")))?
        .map_err(|e| APIError::FailedVssInit(format!("vss_clear_fence failed: {e}")))?;

        Ok(())
    }
}

pub(crate) async fn unlock(state: Arc<AppState>, request: UnlockRequest) -> Result<(), APIError> {
    tracing::info!("Unlock started");
    if is_external_signer_mode_configured(&state)? {
        return Err(APIError::ExternalSignerRequired);
    }

    match check_locked(&state).await {
        Ok(unlocked_state) => {
            update_changing_state(&state, true);
            drop(unlocked_state);
        }
        Err(e) => {
            return Err(match e {
                APIError::UnlockedNode => APIError::AlreadyUnlocked,
                _ => e,
            });
        }
    }

    let mnemonic = match check_password_validity(&request.password, &state.db()) {
        Ok(mnemonic) => mnemonic,
        Err(e) => {
            update_changing_state(&state, false);
            return Err(e);
        }
    };

    tracing::debug!("Starting LDK...");
    let unlock_request = crate::core_types::UnlockRequest {
        bitcoind_rpc_username: request.bitcoind_rpc_username,
        bitcoind_rpc_password: request.bitcoind_rpc_password,
        bitcoind_rpc_host: request.bitcoind_rpc_host,
        bitcoind_rpc_port: request.bitcoind_rpc_port,
        indexer_url: request.indexer_url,
        proxy_endpoint: request.proxy_endpoint,
        announce_addresses: request.announce_addresses,
        announce_alias: request.announce_alias,
    };
    let (new_ldk_background_services, new_unlocked_app_state) = match start_ldk(
        state.clone(),
        crate::core_types::NodeKeySource::InternalMnemonic(mnemonic),
        unlock_request,
    )
    .await
    {
        Ok((nlbs, nuap)) => (nlbs, nuap),
        Err(e) => {
            update_changing_state(&state, false);
            return Err(e);
        }
    };
    tracing::debug!("LDK started");

    update_unlocked_app_state(&state, Some(new_unlocked_app_state)).await;
    update_ldk_background_services(&state, Some(new_ldk_background_services));
    update_changing_state(&state, false);
    tracing::info!("Unlock completed");
    Ok(())
}

pub(crate) async fn unlock_with_attached_external_signer(
    state: Arc<AppState>,
    request: UnlockRequest,
) -> Result<(), APIError> {
    struct ChangingStateGuard {
        state: Arc<AppState>,
        active: bool,
    }

    impl ChangingStateGuard {
        fn new(state: Arc<AppState>) -> Self {
            Self {
                state,
                active: true,
            }
        }

        fn disarm(&mut self) {
            self.active = false;
        }
    }

    impl Drop for ChangingStateGuard {
        fn drop(&mut self) {
            if self.active {
                update_changing_state(&self.state, false);
            }
        }
    }

    tracing::info!("Attached external-signer unlock started");
    match check_locked(&state).await {
        Ok(unlocked_state) => {
            update_changing_state(&state, true);
            drop(unlocked_state);
        }
        Err(e) => {
            return Err(match e {
                APIError::UnlockedNode => APIError::AlreadyUnlocked,
                _ => e,
            });
        }
    }
    let mut changing_state_guard = ChangingStateGuard::new(Arc::clone(&state));

    let signer_attachment = match state.get_attached_external_signer().clone() {
        Some(attachment) => attachment,
        None => {
            return Err(APIError::ExternalSignerUnavailable(
                "attached external signer is not registered".to_string(),
            ));
        }
    };
    validate_external_signer_bootstrap(&signer_attachment.bootstrap)?;
    let key_source = match read_key_source_file(&state.static_state.storage_dir_path)
        .map_err(|e| APIError::ExternalSignerProtocolError(e.to_string()))?
    {
        Some(key_source) => key_source,
        None => return Err(APIError::ExternalSignerRequired),
    };
    if validate_key_source_matches_bootstrap(&key_source, &signer_attachment.bootstrap).is_err() {
        return Err(APIError::ExternalSignerMismatch);
    }

    let unlock_request = crate::core_types::UnlockRequest {
        bitcoind_rpc_username: request.bitcoind_rpc_username,
        bitcoind_rpc_password: request.bitcoind_rpc_password,
        bitcoind_rpc_host: request.bitcoind_rpc_host,
        bitcoind_rpc_port: request.bitcoind_rpc_port,
        indexer_url: request.indexer_url,
        proxy_endpoint: request.proxy_endpoint,
        announce_addresses: request.announce_addresses,
        announce_alias: request.announce_alias,
    };
    let (new_ldk_background_services, new_unlocked_app_state) = match start_ldk(
        state.clone(),
        crate::core_types::NodeKeySource::External(crate::core_types::ExternalKeySource {
            bootstrap: signer_attachment.bootstrap.clone(),
            signer_attachment,
        }),
        unlock_request,
    )
    .await
    {
        Ok((nlbs, nuap)) => (nlbs, nuap),
        Err(e) => return Err(e),
    };

    update_unlocked_app_state(&state, Some(new_unlocked_app_state)).await;
    update_ldk_background_services(&state, Some(new_ldk_background_services));
    changing_state_guard.disarm();
    update_changing_state(&state, false);
    Ok(())
}

pub(crate) async fn connect_peer(
    state: Arc<AppState>,
    peer_pubkey_and_addr: String,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let (peer_pubkey, peer_addr) = parse_peer_info(peer_pubkey_and_addr.to_string())?;

    if let Some(peer_addr) = peer_addr {
        connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone())
            .await?;
        state
            .get_db()
            .persist_channel_peer(&peer_pubkey, &peer_addr)?;
    } else {
        return Err(APIError::InvalidPeerInfo(s!(
            "incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`"
        )));
    }

    Ok(())
}

pub(crate) async fn disconnect_peer(
    state: Arc<AppState>,
    request: DisconnectPeerRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let peer_pubkey =
        PublicKey::from_str(&request.peer_pubkey).map_err(|_| APIError::InvalidPubkey)?;

    for channel in unlocked_state.channel_manager.list_channels() {
        if channel.counterparty.node_id == peer_pubkey {
            return Err(APIError::FailedPeerDisconnection(s!(
                "node has an active channel with this peer, close any channels first"
            )));
        }
    }

    state.get_db().delete_channel_peer(&request.peer_pubkey)?;

    if unlocked_state
        .peer_manager
        .peer_by_node_id(&peer_pubkey)
        .is_none()
    {
        return Err(APIError::FailedPeerDisconnection(format!(
            "Could not find peer {peer_pubkey}"
        )));
    }

    unlocked_state
        .peer_manager
        .disconnect_by_node_id(peer_pubkey);
    Ok(())
}

pub(crate) async fn close_channel(
    state: Arc<AppState>,
    request: CloseChannelRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let channel_id_vec = hex_str_to_vec(&request.channel_id);
    if channel_id_vec.is_none() || channel_id_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidChannelID);
    }
    let requested_cid = ChannelId(channel_id_vec.unwrap().try_into().unwrap());

    let peer_pubkey_vec = match hex_str_to_vec(&request.peer_pubkey) {
        Some(peer_pubkey_vec) => peer_pubkey_vec,
        None => return Err(APIError::InvalidPubkey),
    };
    let peer_pubkey = match PublicKey::from_slice(&peer_pubkey_vec) {
        Ok(peer_pubkey) => peer_pubkey,
        Err(_) => return Err(APIError::InvalidPubkey),
    };

    let virtual_session = unlocked_state.virtual_channel_session_get(&requested_cid);
    if let Some(session) = virtual_session.as_ref() {
        if session.peer_id != peer_pubkey {
            return Err(APIError::CannotCloseChannel(
                "peer pubkey does not match trusted virtual channel session".to_string(),
            ));
        }
    }

    let chan_details = if let Some(chan_details) = unlocked_state
        .channel_manager
        .list_channels()
        .into_iter()
        .find(|c| c.channel_id == requested_cid)
    {
        if chan_details.trusted_no_broadcast {
            if let Some(session) = virtual_session.as_ref() {
                match session.status {
                    VirtualChannelSessionStatus::Abandoned => {
                        tracing::warn!(
                            "virtual session {} is persisted as abandoned but the live trusted channel is still present; retrying close without rewriting session state",
                            requested_cid
                        );
                    }
                    VirtualChannelSessionStatus::AbandonPending => {
                        return Err(APIError::CannotCloseChannel(
                            "virtual cleanup is already in progress".to_string(),
                        ));
                    }
                    VirtualChannelSessionStatus::Active => {}
                }
            }
        }
        chan_details
    } else {
        if let Some(session) = virtual_session.as_ref() {
            if !matches!(session.status, VirtualChannelSessionStatus::Abandoned) {
                unlocked_state.virtual_channel_session_update_status(
                    session,
                    VirtualChannelSessionStatus::Abandoned,
                );
            }
            return Ok(());
        }
        return Err(APIError::UnknownChannelId);
    };

    if virtual_session.is_some() && !chan_details.trusted_no_broadcast {
        return Err(APIError::Unexpected(format!(
            "virtual channel session exists for {requested_cid}, but live channel is not trusted_no_broadcast"
        )));
    }

    match chan_details.channel_shutdown_state {
        Some(ChannelShutdownState::NotShuttingDown) => {}
        _ => {
            return Err(APIError::CannotCloseChannel(s!(
                "Channel is already being closed"
            )))
        }
    }

    if chan_details.trusted_no_broadcast {
        if !state.static_state.enable_virtual_channels_v0 {
            return Err(APIError::CannotCloseChannel(
                "trusted virtual channels v0 are disabled".to_string(),
            ));
        }
        let Some(session) = virtual_session else {
            return Err(APIError::CannotCloseChannel(
                "virtual cleanup is host-only and requires a host-side session".to_string(),
            ));
        };
        if request.force {
            return Err(APIError::CannotCloseChannel(
                "force=true is not supported for trusted virtual channels".to_string(),
            ));
        }
        unlocked_state
            .virtual_channel_ensure_no_client_value(&chan_details)
            .map_err(APIError::CannotCloseChannel)?;

        unlocked_state.virtual_channel_session_update_status(
            &session,
            VirtualChannelSessionStatus::AbandonPending,
        );
        match unlocked_state.channel_manager.abandon_virtual_channel(
            &requested_cid,
            &peer_pubkey,
            true,
        ) {
            Ok(()) => {
                unlocked_state.virtual_channel_session_update_status(
                    &session,
                    VirtualChannelSessionStatus::Abandoned,
                );
                tracing::info!(
                    "EVENT: abandon_virtual_channel succeeded; session is now abandoned"
                );
            }
            Err(e) => {
                let error = match e {
                    LDKAPIError::APIMisuseError { err } => err,
                    _ => format!("{e:?}"),
                };
                let live_virtual_channel_still_exists = unlocked_state
                    .channel_manager
                    .list_channels()
                    .into_iter()
                    .any(|c| c.channel_id == requested_cid && c.trusted_no_broadcast);
                if live_virtual_channel_still_exists {
                    unlocked_state.virtual_channel_session_update_status(
                        &session,
                        VirtualChannelSessionStatus::Active,
                    );
                    return Err(APIError::CannotCloseChannel(error));
                }
                unlocked_state.virtual_channel_session_update_status(
                    &session,
                    VirtualChannelSessionStatus::Abandoned,
                );
                tracing::info!(
                    "EVENT: abandon_virtual_channel returned error '{}' but channel {} is absent from live LDK state; reconciling session to abandoned",
                    error,
                    requested_cid,
                );
                return Ok(());
            }
        }

        return Ok(());
    }

    if request.force {
        match unlocked_state
            .channel_manager
            .force_close_broadcasting_latest_txn(
                &requested_cid,
                &peer_pubkey,
                "Manually force-closed".to_string(),
            ) {
            Ok(()) => tracing::info!("EVENT: initiating channel force-close"),
            Err(e) => match e {
                LDKAPIError::APIMisuseError { err } => {
                    return Err(APIError::FailedClosingChannel(err))
                }
                _ => return Err(APIError::CannotCloseChannel(format!("{e:?}"))),
            },
        }
    } else {
        match unlocked_state
            .channel_manager
            .close_channel(&requested_cid, &peer_pubkey)
        {
            Ok(()) => tracing::info!("EVENT: initiating channel close"),
            Err(e) => match e {
                LDKAPIError::APIMisuseError { err } => {
                    return Err(APIError::FailedClosingChannel(err))
                }
                _ => return Err(APIError::CannotCloseChannel(format!("{e:?}"))),
            },
        }
    }

    Ok(())
}

/// In external signer mode, on-chain RGB flows that need signing use `rgb_sign_psbt` (never the
/// watch-only wallet's private `sign_psbt`) for create_utxos, send_btc, and send_rgb PSBT paths.
pub(crate) async fn create_utxos(
    state: Arc<AppState>,
    request: CreateUtxosRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let num = request.num.unwrap_or(SDK_UTXO_NUM);
    let size = request.size.unwrap_or(SDK_UTXO_SIZE_SAT);
    if unlocked_state.external_signer_mode {
        let unsigned_psbt = unlocked_state
            .rgb_create_utxos_begin(
                request.up_to,
                num,
                size,
                request.fee_rate,
                request.skip_sync,
            )
            .map_err(|e| {
                tracing::error!("rgb_create_utxos_begin failed in external signer mode: {e}");
                APIError::from(e)
            })?;
        let signed_psbt = unlocked_state.rgb_sign_psbt(unsigned_psbt).map_err(|e| {
            tracing::error!("rgb_sign_psbt failed in external signer mode: {e}");
            APIError::from(e)
        })?;
        let _created = unlocked_state
            .rgb_create_utxos_end(signed_psbt, request.skip_sync)
            .map_err(|e| {
                tracing::error!("rgb_create_utxos_end failed in external signer mode: {e}");
                APIError::from(e)
            })?;
    } else {
        unlocked_state.rgb_create_utxos(
            request.up_to,
            num,
            size,
            request.fee_rate,
            request.skip_sync,
        )?;
    }
    tracing::debug!("UTXO creation complete");

    Ok(())
}

pub(crate) async fn issue_asset_nia(
    state: Arc<AppState>,
    request: IssueAssetNiaRequestData,
) -> Result<AssetNIA, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    if unlocked_state.external_signer_mode {
        return Err(APIError::UnsupportedInExternalSignerMode(
            "asset issuance is not supported in external signer mode".to_string(),
        ));
    }

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let asset = unlocked_state.rgb_issue_asset_nia(
        request.ticker,
        request.name,
        request.precision,
        request.amounts,
    )?;

    Ok(asset.into())
}

pub(crate) async fn issue_asset_cfa(
    state: Arc<AppState>,
    request: IssueAssetCfaRequestData,
) -> Result<AssetCFA, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    if unlocked_state.external_signer_mode {
        return Err(APIError::UnsupportedInExternalSignerMode(
            "asset issuance is not supported in external signer mode".to_string(),
        ));
    }

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let file_path = request.file_digest.map(|d| {
        unlocked_state
            .rgb_get_media_dir()
            .join(d.to_lowercase())
            .to_string_lossy()
            .to_string()
    });

    let asset = unlocked_state.rgb_issue_asset_cfa(
        request.name,
        request.details,
        request.precision,
        request.amounts,
        file_path,
    )?;

    Ok(asset.into())
}

pub(crate) async fn issue_asset_ifa(
    state: Arc<AppState>,
    request: IssueAssetIFARequestData,
) -> Result<AssetIFA, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    if unlocked_state.external_signer_mode {
        return Err(APIError::UnsupportedInExternalSignerMode(
            "asset issuance is not supported in external signer mode".to_string(),
        ));
    }

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let asset = unlocked_state.rgb_issue_asset_ifa(
        request.ticker,
        request.name,
        request.precision,
        request.amounts,
        request.inflation_amounts,
        request.reject_list_url,
    )?;

    Ok(asset.into())
}

pub(crate) async fn issue_asset_uda(
    state: Arc<AppState>,
    request: IssueAssetUdaRequestData,
) -> Result<AssetUDA, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    if unlocked_state.external_signer_mode {
        return Err(APIError::UnsupportedInExternalSignerMode(
            "asset issuance is not supported in external signer mode".to_string(),
        ));
    }

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let rgb_media_dir = unlocked_state.rgb_get_media_dir();
    let get_string_path = |d: String| {
        rgb_media_dir
            .join(d.to_lowercase())
            .to_string_lossy()
            .to_string()
    };
    let media_file_path = request.media_file_digest.map(get_string_path);
    let attachments_file_paths = request
        .attachments_file_digests
        .into_iter()
        .map(get_string_path)
        .collect();

    let asset = unlocked_state.rgb_issue_asset_uda(
        request.ticker,
        request.name,
        request.details,
        request.precision,
        media_file_path,
        attachments_file_paths,
    )?;

    Ok(asset.into())
}

pub(crate) async fn keysend(
    state: Arc<AppState>,
    request: KeysendRequestData,
) -> Result<KeysendData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let dest_pubkey_vec = match hex_str_to_vec(&request.dest_pubkey) {
        Some(peer_pubkey_vec) => peer_pubkey_vec,
        None => return Err(APIError::InvalidPubkey),
    };
    let dest_pubkey = match PublicKey::from_slice(&dest_pubkey_vec) {
        Ok(peer_pubkey) => peer_pubkey,
        Err(_) => return Err(APIError::InvalidPubkey),
    };

    let amt_msat = request.amt_msat;
    if amt_msat < SDK_HTLC_MIN_MSAT {
        return Err(APIError::InvalidAmount(format!(
            "amt_msat cannot be less than {SDK_HTLC_MIN_MSAT}"
        )));
    }

    let payment_preimage = PaymentPreimage(unlocked_state.entropy_source.get_secure_random_bytes());
    let payment_hash_inner = Sha256::hash(&payment_preimage.0[..]).to_byte_array();
    let payment_id = PaymentId(payment_hash_inner);
    let payment_hash = PaymentHash(payment_hash_inner);

    let rgb_payment = match (request.asset_id, request.asset_amount) {
        (Some(asset_id), Some(rgb_amount)) => {
            let contract_id =
                ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;
            Some((contract_id, rgb_amount))
        }
        (None, None) => None,
        _ => {
            return Err(APIError::IncompleteRGBInfo);
        }
    };

    let route_params = RouteParameters::from_payment_params_and_value(
        PaymentParameters::for_keysend(dest_pubkey, 40, false),
        amt_msat,
        rgb_payment,
    );
    let created_at = get_current_timestamp();
    unlocked_state.add_outbound_payment(
        payment_id,
        PaymentInfo {
            preimage: None,
            secret: None,
            status: HtlcStatus::Pending,
            amt_msat: Some(amt_msat),
            claim_deadline_height: None,
            created_at,
            updated_at: created_at,
            payee_pubkey: dest_pubkey,
            expires_at: None,
            invoice_type: None,
        },
    )?;
    if let Some((contract_id, rgb_amount)) = rgb_payment {
        write_rgb_payment_info_file(
            &payment_hash,
            contract_id,
            rgb_amount,
            false,
            false,
            unlocked_state.kv_store.as_ref(),
        );
    }

    let status = match unlocked_state.channel_manager.send_spontaneous_payment(
        Some(payment_preimage),
        RecipientOnionFields::spontaneous_empty(),
        payment_id,
        route_params,
        Retry::Timeout(Duration::from_secs(10)),
    ) {
        Ok(_payment_hash) => {
            tracing::info!(
                "EVENT: initiated sending {} msats to {}",
                amt_msat,
                dest_pubkey
            );
            HtlcStatus::Pending
        }
        Err(e) => {
            tracing::error!("ERROR: failed to send payment: {:?}", e);
            clear_rgb_payment_pending(&payment_hash, false, unlocked_state.kv_store.as_ref());
            unlocked_state.update_outbound_payment_status(payment_id, HtlcStatus::Failed);
            HtlcStatus::Failed
        }
    };

    Ok(KeysendData {
        payment_hash: hex_str(&payment_hash.0),
        payment_preimage: hex_str(&payment_preimage.0),
        status,
    })
}

pub(crate) async fn send_btc(
    state: Arc<AppState>,
    request: SendBtcRequestData,
) -> Result<SendBtcData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let txid = if unlocked_state.external_signer_mode {
        let unsigned_psbt =
            unlocked_state.rgb_send_btc_begin(request.address, request.amount, request.fee_rate)?;
        let signed_psbt = unlocked_state.rgb_sign_psbt(unsigned_psbt).map_err(|e| {
            tracing::error!("rgb_sign_psbt failed during send_btc (PSBT path): {e}");
            APIError::from(e)
        })?;
        unlocked_state.rgb_send_btc_end(signed_psbt)?
    } else {
        unlocked_state.rgb_send_btc(
            request.address,
            request.amount,
            request.fee_rate,
            request.skip_sync,
        )?
    };

    Ok(SendBtcData { txid })
}

pub(crate) async fn post_asset_media(
    state: Arc<AppState>,
    file_bytes: Vec<u8>,
) -> Result<PostAssetMediaData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    if file_bytes.is_empty() {
        return Err(APIError::MediaFileEmpty);
    }
    let file_hash: Sha256 = Hash::hash(&file_bytes[..]);
    let digest = file_hash.to_string();

    let file_path = unlocked_state.rgb_get_media_dir().join(&digest);
    let mut write = true;
    if file_path.exists() {
        let mut buf_reader = BufReader::new(File::open(&file_path).await?);
        let mut existing_file_bytes = Vec::new();
        buf_reader.read_to_end(&mut existing_file_bytes).await?;
        if file_bytes != existing_file_bytes {
            tokio::fs::remove_file(&file_path).await?;
        } else {
            write = false;
        }
    }
    if write {
        let mut file = File::create(&file_path).await?;
        file.write_all(&file_bytes).await?;
    }

    Ok(PostAssetMediaData { digest })
}

pub(crate) async fn rgb_invoice(
    state: Arc<AppState>,
    request: RgbInvoiceRequestData,
) -> Result<RgbInvoiceData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let assignment = match request.assignment_kind {
        Some(kind) => rgb_assignment_from_kind(kind, request.assignment_amount)?,
        None => RgbLibAssignment::Any,
    };

    let expiration_timestamp = request
        .duration_seconds
        .map(|duration| get_current_timestamp() + u64::from(duration));
    let receive_data = if request.witness {
        unlocked_state.rgb_witness_receive(
            request.asset_id,
            assignment,
            expiration_timestamp,
            vec![unlocked_state.proxy_endpoint.clone()],
            request.min_confirmations,
        )?
    } else {
        unlocked_state.rgb_blind_receive(
            request.asset_id,
            assignment,
            expiration_timestamp,
            vec![unlocked_state.proxy_endpoint.clone()],
            request.min_confirmations,
        )?
    };

    Ok(RgbInvoiceData {
        recipient_id: receive_data.recipient_id,
        invoice: receive_data.invoice,
        expiration_timestamp: receive_data.expiration_timestamp.map(|t| t as i64),
        batch_transfer_idx: receive_data.batch_transfer_idx,
    })
}

pub(crate) async fn open_channel(
    state: Arc<AppState>,
    request: OpenChannelRequestData,
) -> Result<OpenChannelData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let is_virtual_open = match request.virtual_open_mode.as_deref() {
        None => false,
        Some(SDK_VIRTUAL_OPEN_MODE_TRUSTED_NO_BROADCAST) => true,
        Some(other) => {
            return Err(APIError::InvalidRequest(format!(
                "unknown virtual_open_mode: {other}"
            )));
        }
    };

    if is_virtual_open && !state.static_state.enable_virtual_channels_v0 {
        return Err(APIError::InvalidRequest(
            "trusted virtual channels v0 are disabled".to_string(),
        ));
    }

    if is_virtual_open && request.public {
        return Err(APIError::InvalidRequest(
            "virtual channels requires public=false".to_string(),
        ));
    }

    let mut temporary_channel_id = request
        .temporary_channel_id
        .as_deref()
        .map(check_channel_id)
        .transpose()?;
    if !is_virtual_open {
        if let Some(temporary_channel_id) = temporary_channel_id.as_ref() {
            if unlocked_state
                .channel_ids()
                .contains_key(temporary_channel_id)
                || unlocked_state
                    .virtual_channel_draft_store()
                    .contains_key(temporary_channel_id)
            {
                return Err(APIError::TemporaryChannelIdAlreadyUsed);
            }
        }
    }

    let colored_info = match (request.asset_id, request.asset_amount) {
        (Some(_), Some(amt)) if amt < SDK_OPENCHANNEL_MIN_RGB_AMT => {
            return Err(APIError::InvalidAmount(format!(
                "Channel RGB amount must be equal to or higher than {SDK_OPENCHANNEL_MIN_RGB_AMT}"
            )));
        }
        (Some(asset), Some(amt)) => {
            let asset =
                ContractId::from_str(&asset).map_err(|_| APIError::InvalidAssetID(asset))?;
            Some((asset, amt))
        }
        (None, None) => None,
        _ => return Err(APIError::IncompleteRGBInfo),
    };

    if colored_info.is_some() && request.capacity_sat < SDK_OPENRGBCHANNEL_MIN_SAT {
        return Err(APIError::InvalidAmount(format!(
            "RGB channel amount must be equal to or higher than {SDK_OPENRGBCHANNEL_MIN_SAT} sats"
        )));
    } else if request.capacity_sat < SDK_OPENCHANNEL_MIN_SAT {
        return Err(APIError::InvalidAmount(format!(
            "Channel amount must be equal to or higher than {SDK_OPENCHANNEL_MIN_SAT} sats"
        )));
    }
    if request.capacity_sat > SDK_OPENCHANNEL_MAX_SAT {
        return Err(APIError::InvalidAmount(format!(
            "Channel amount must be equal to or less than {SDK_OPENCHANNEL_MAX_SAT} sats"
        )));
    }

    if request.push_msat > request.capacity_sat * 1000 {
        return Err(APIError::InvalidAmount(s!(
            "Channel push amount cannot be higher than the capacity"
        )));
    }
    if let Some(push_asset_amount) = request.push_asset_amount {
        if colored_info.is_none() {
            return Err(APIError::InvalidAmount(s!(
                "push_asset_amount can only be used with RGB channels (asset_id must be specified)"
            )));
        }
        if let Some((_, asset_amount)) = &colored_info {
            if push_asset_amount > *asset_amount {
                return Err(APIError::InvalidAmount(s!(
                    "push_asset_amount cannot be higher than asset_amount"
                )));
            }
        }
    }

    if colored_info.is_some() && !request.with_anchors {
        return Err(APIError::AnchorsRequired);
    }

    let (peer_pubkey, mut peer_addr) =
        parse_peer_info(request.peer_pubkey_and_opt_addr.to_string())?;

    let mut virtual_draft_reservation = if is_virtual_open {
        let reserved_temporary_channel_id =
            unlocked_state.virtual_channel_add_intent(peer_pubkey, temporary_channel_id)?;
        temporary_channel_id = Some(reserved_temporary_channel_id);
        Some(OpenChannelVirtualIntentGuard::new(
            unlocked_state.clone(),
            reserved_temporary_channel_id,
        ))
    } else {
        None
    };

    if peer_addr.is_none() {
        if let Some(peer) = unlocked_state.peer_manager.peer_by_node_id(&peer_pubkey) {
            if let Some(socket_address) = peer.socket_address {
                if let Ok(mut socket_addrs) = socket_address.to_socket_addrs() {
                    peer_addr = socket_addrs.next();
                }
            }
        }
    }
    if peer_addr.is_none() {
        let peer_info = state.get_db().read_channel_peer_data()?;
        for (pubkey, addr) in peer_info {
            if pubkey == peer_pubkey {
                peer_addr = Some(addr);
                break;
            }
        }
    }
    if let Some(peer_addr) = peer_addr {
        connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone())
            .await?;
        state
            .get_db()
            .persist_channel_peer(&peer_pubkey, &peer_addr)?;
    } else {
        return Err(APIError::InvalidPeerInfo(s!(
            "cannot find the address for the provided pubkey"
        )));
    }

    let mut channel_config = ChannelConfig::default();
    if let Some(fee_base_msat) = request.fee_base_msat {
        channel_config.forwarding_fee_base_msat = fee_base_msat;
    }
    if let Some(fee_proportional_millionths) = request.fee_proportional_millionths {
        channel_config.forwarding_fee_proportional_millionths = fee_proportional_millionths;
    }
    let config = UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            trust_own_funding_0conf: true,
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            announce_for_forwarding: if is_virtual_open {
                false
            } else {
                request.public
            },
            our_htlc_minimum_msat: SDK_HTLC_MIN_MSAT,
            minimum_depth: if is_virtual_open {
                0
            } else {
                MIN_CHANNEL_CONFIRMATIONS as u32
            },
            negotiate_scid_privacy: is_virtual_open,
            negotiate_anchors_zero_fee_htlc_tx: request.with_anchors,
            their_channel_reserve_satoshis_override: if is_virtual_open { Some(0) } else { None },
            ..Default::default()
        },
        channel_config,
        ..Default::default()
    };

    let consignment_endpoint = if let Some((contract_id, asset_amount)) = &colored_info {
        let balance = unlocked_state.rgb_get_asset_balance(*contract_id)?;
        let spendable_rgb_amount = balance.spendable;
        if *asset_amount > spendable_rgb_amount {
            return Err(APIError::InsufficientAssets);
        }
        Some(RgbTransport::from_str(&unlocked_state.proxy_endpoint).unwrap())
    } else {
        None
    };

    let schema = if let Some((contract_id, asset_amount)) = &colored_info {
        let mut fake_p2wsh: [u8; 34] = [0; 34];
        fake_p2wsh[1] = 32;
        let script_buf = ScriptBuf::from_bytes(fake_p2wsh.to_vec());
        let recipient_id = recipient_id_from_script_buf(script_buf, state.static_state.network);
        let asset_id = contract_id.to_string();
        let schema = unlocked_state
            .rgb_get_asset_metadata(*contract_id)?
            .asset_schema;
        let assignment = match schema {
            RgbLibAssetSchema::Nia | RgbLibAssetSchema::Cfa | RgbLibAssetSchema::Ifa => {
                RgbLibAssignment::Fungible(*asset_amount)
            }
            RgbLibAssetSchema::Uda => RgbLibAssignment::NonFungible,
        };

        let recipient_map = map! {
            asset_id => vec![RgbLibRecipient {
                recipient_id,
                witness_data: Some(RgbLibWitnessData {
                    amount_sat: request.capacity_sat,
                    blinding: Some(STATIC_BLINDING + 1),
                }),
                assignment,
                transport_endpoints: vec![unlocked_state.proxy_endpoint.clone()],
        }]};

        let unlocked_state_copy = unlocked_state.clone();
        tokio::task::spawn_blocking(move || {
            unlocked_state_copy.rgb_send_begin(
                recipient_map,
                true,
                FEE_RATE,
                MIN_CHANNEL_CONFIRMATIONS,
                None,
                true,
                Some(0),
            )
        })
        .await
        .unwrap()?;
        Some(schema)
    } else {
        None
    };

    // Persist RGB channel_info before create_channel so funding
    // event handlers always observe the metadata.
    let (temporary_channel_id, rgb_metadata_temp_id_str) =
        if let Some((contract_id, asset_amount)) = &colored_info {
            let temp_id = match temporary_channel_id {
                Some(id) => id,
                None => loop {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&unlocked_state.entropy_source.get_secure_random_bytes());
                    let candidate = ChannelId::from_bytes(bytes);
                    if !unlocked_state.channel_ids().contains_key(&candidate)
                        && !unlocked_state
                            .virtual_channel_draft_store()
                            .contains_key(&candidate)
                    {
                        break candidate;
                    }
                },
            };
            let temp_id_str = temp_id.0.as_hex().to_string();
            let push_amount = request.push_asset_amount.unwrap_or(0);
            let rgb_info = RgbInfo {
                contract_id: *contract_id,
                schema: schema.unwrap(),
                local_rgb_amount: *asset_amount - push_amount,
                remote_rgb_amount: push_amount,
            };
            unlocked_state
                .kv_store
                .write_rgb_channel_info(&temp_id_str, &rgb_info, true);
            unlocked_state
                .kv_store
                .write_rgb_channel_info(&temp_id_str, &rgb_info, false);
            (Some(temp_id), Some(temp_id_str))
        } else {
            (temporary_channel_id, None)
        };

    *unlocked_state.rgb_send_lock.lock().unwrap() = true;
    tracing::debug!("RGB send lock set to true");

    let temporary_channel_id = unlocked_state
        .channel_manager
        .create_channel(
            peer_pubkey,
            request.capacity_sat,
            request.push_msat,
            0,
            temporary_channel_id,
            Some(config),
            consignment_endpoint,
            request.push_asset_amount,
        )
        .map_err(|e| {
            *unlocked_state.rgb_send_lock.lock().unwrap() = false;
            tracing::debug!("RGB send lock set to false (open channel failure: {e:?})");
            if let Some(temp_id_str) = rgb_metadata_temp_id_str.as_deref() {
                let _ = unlocked_state
                    .kv_store
                    .remove_rgb_channel_info(temp_id_str, true);
                let _ = unlocked_state
                    .kv_store
                    .remove_rgb_channel_info(temp_id_str, false);
            }
            match e {
                LDKAPIError::APIMisuseError { err }
                    if err.contains("fee for initial commitment transaction") =>
                {
                    let mut commitment_tx_fee = 0;
                    let re = Regex::new(r"fee for initial commitment transaction fee of (\d+).")
                        .unwrap();
                    if let Some(captures) = re.captures(&err) {
                        if let Some(fee_str) = captures.get(1) {
                            commitment_tx_fee = fee_str.as_str().parse().unwrap();
                        }
                    }
                    APIError::InsufficientCapacity(commitment_tx_fee)
                }
                _ => APIError::FailedOpenChannel(format!("{e:?}")),
            }
        })?;
    if let Some(virtual_draft_reservation) = virtual_draft_reservation.as_mut() {
        virtual_draft_reservation.disarm();
    }

    let temporary_channel_id = temporary_channel_id.0.as_hex().to_string();
    tracing::info!("EVENT: initiated channel with peer {}", peer_pubkey);

    Ok(OpenChannelData {
        temporary_channel_id,
    })
}

pub(crate) async fn send_payment(
    state: Arc<AppState>,
    request: SendPaymentRequestData,
) -> Result<SendPaymentData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut status = HtlcStatus::Pending;
    let created_at = get_current_timestamp();

    let (payment_id, payment_hash, payment_secret) = if let Ok(offer) =
        Offer::from_str(&request.invoice)
    {
        let random_bytes = unlocked_state.entropy_source.get_secure_random_bytes();
        let payment_id = PaymentId(random_bytes);

        let amt_msat = match (offer.amount(), request.amt_msat) {
            (Some(offer::Amount::Bitcoin { amount_msats }), _) => amount_msats,
            (_, Some(amt)) => amt,
            (amt, _) => {
                return Err(APIError::InvalidAmount(format!(
                    "cannot process non-Bitcoin-denominated offer value {amt:?}"
                )));
            }
        };
        if request.amt_msat.is_some() && request.amt_msat != Some(amt_msat) {
            return Err(APIError::InvalidAmount(format!(
                "amount didn't match offer of {amt_msat}msat"
            )));
        }

        let secret = None;
        unlocked_state.add_outbound_payment(
            payment_id,
            PaymentInfo {
                preimage: None,
                secret,
                status,
                amt_msat: Some(amt_msat),
                claim_deadline_height: None,
                created_at,
                updated_at: created_at,
                payee_pubkey: offer
                    .issuer_signing_pubkey()
                    .ok_or(APIError::InvalidInvoice(s!("missing signing pubkey")))?,
                expires_at: None,
                invoice_type: None,
            },
        )?;

        let params = OptionalOfferPaymentParams {
            retry_strategy: Retry::Timeout(Duration::from_secs(10)),
            ..Default::default()
        };
        let pay = unlocked_state.channel_manager.pay_for_offer(
            &offer,
            Some(amt_msat),
            payment_id,
            params,
        );
        if pay.is_err() {
            tracing::error!("ERROR: failed to pay: {:?}", pay);
            unlocked_state.update_outbound_payment_status(payment_id, HtlcStatus::Failed);
            status = HtlcStatus::Failed;
            unlocked_state.update_outbound_payment_status(payment_id, status);
        }
        (payment_id, None, secret)
    } else {
        let invoice = Bolt11Invoice::from_str(&request.invoice)
            .map_err(|e| APIError::InvalidInvoice(e.to_string()))?;

        let payment_id = PaymentId((*invoice.payment_hash()).to_byte_array());
        let payment_secret = Some(*invoice.payment_secret());
        let zero_amt_invoice =
            invoice.amount_milli_satoshis().is_none() || invoice.amount_milli_satoshis() == Some(0);

        let amt_msat = if zero_amt_invoice {
            if let Some(amt_msat) = request.amt_msat {
                amt_msat
            } else {
                return Err(APIError::InvalidAmount(s!(
                    "need an amount for the given 0-value invoice"
                )));
            }
        } else {
            if request.amt_msat.is_some() && invoice.amount_milli_satoshis() != request.amt_msat {
                return Err(APIError::InvalidAmount(format!(
                    "amount didn't match invoice value of {}msat",
                    invoice.amount_milli_satoshis().unwrap_or(0)
                )));
            }
            invoice.amount_milli_satoshis().unwrap_or(0)
        };

        let rgb_payment = match (invoice.rgb_contract_id(), invoice.rgb_amount()) {
            (Some(rgb_contract_id), Some(rgb_amount)) => {
                if amt_msat < SDK_INVOICE_MIN_MSAT {
                    return Err(APIError::InvalidAmount(format!(
                            "amt_msat in invoice sending an RGB asset cannot be less than {SDK_INVOICE_MIN_MSAT}"
                        )));
                }
                Some((rgb_contract_id, rgb_amount))
            }
            (Some(rgb_contract_id), None) => {
                if amt_msat < SDK_INVOICE_MIN_MSAT {
                    return Err(APIError::InvalidAmount(format!(
                            "amt_msat in invoice sending an RGB asset cannot be less than {SDK_INVOICE_MIN_MSAT}"
                        )));
                }
                if let Some(asset_id) = request.asset_id.as_ref() {
                    let payload_contract_id = ContractId::from_str(asset_id)
                        .map_err(|_| APIError::InvalidAssetID(asset_id.clone()))?;
                    if payload_contract_id != rgb_contract_id {
                        return Err(APIError::InvalidInvoice(s!(
                            "invoice RGB contract ID doesn't match the requested one"
                        )));
                    }
                }
                let rgb_amount = request.asset_amount.ok_or(APIError::IncompleteRGBInfo)?;
                Some((rgb_contract_id, rgb_amount))
            }
            (None, None) => None,
            (None, Some(_)) => {
                return Err(APIError::InvalidInvoice(s!(
                    "invoice has an RGB amount but not an RGB contract ID"
                )));
            }
        };

        let secret = payment_secret;
        unlocked_state.add_outbound_payment(
            payment_id,
            PaymentInfo {
                preimage: None,
                secret,
                status,
                amt_msat: Some(amt_msat),
                claim_deadline_height: None,
                created_at,
                updated_at: created_at,
                payee_pubkey: invoice.get_payee_pub_key(),
                expires_at: None,
                invoice_type: None,
            },
        )?;
        let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
        if let Some((contract_id, rgb_amount)) = rgb_payment {
            write_rgb_payment_info_file(
                &payment_hash,
                contract_id,
                rgb_amount,
                false,
                false,
                unlocked_state.kv_store.as_ref(),
            );
        }

        let bolt11_retry = if rgb_payment.is_some() {
            Retry::Timeout(Duration::from_secs(120))
        } else {
            Retry::Timeout(Duration::from_secs(10))
        };
        match unlocked_state.channel_manager.pay_for_bolt11_invoice(
            &invoice,
            payment_id,
            Some(amt_msat),
            RouteParametersConfig::default(),
            bolt11_retry,
        ) {
            Ok(_) => {
                let payee_pubkey = invoice.recover_payee_pub_key();
                tracing::info!(
                    "EVENT: initiated sending {} msats to {}",
                    amt_msat,
                    payee_pubkey
                );
            }
            Err(e) => {
                tracing::error!("ERROR: failed to send payment: {:?}", e);
                clear_rgb_payment_pending(&payment_hash, false, unlocked_state.kv_store.as_ref());
                status = HtlcStatus::Failed;
                unlocked_state.update_outbound_payment_status(payment_id, status);
            }
        };

        (payment_id, Some(payment_hash), secret)
    };

    Ok(SendPaymentData {
        payment_id: hex_str(&payment_id.0),
        payment_hash: payment_hash.map(|h| hex_str(&h.0)),
        payment_secret: payment_secret.map(|s| hex_str(&s.0)),
        status,
    })
}

pub(crate) async fn fail_transfers(
    state: Arc<AppState>,
    request: FailTransfersRequestData,
) -> Result<FailTransfersData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    let unlocked_state_copy = unlocked_state.clone();

    let transfers_changed = tokio::task::spawn_blocking(move || {
        unlocked_state_copy.rgb_fail_transfers(
            request.batch_transfer_idx,
            request.no_asset_only,
            request.skip_sync,
        )
    })
    .await
    .unwrap()?;

    Ok(FailTransfersData { transfers_changed })
}

pub(crate) async fn refresh_transfers(
    state: Arc<AppState>,
    request: RefreshTransfersRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    let unlocked_state_copy = unlocked_state.clone();

    tokio::task::spawn_blocking(move || unlocked_state_copy.rgb_refresh(request.skip_sync))
        .await
        .unwrap()?;
    Ok(())
}

pub(crate) async fn maker_execute(
    state: Arc<AppState>,
    request: MakerExecuteRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let swapstring = SwapString::from_str(&request.swapstring)
        .map_err(|e| APIError::InvalidSwapString(request.swapstring.clone(), e.to_string()))?;
    let payment_secret = hex_str_to_vec(&request.payment_secret)
        .and_then(|data| data.try_into().ok())
        .map(PaymentSecret)
        .ok_or(APIError::InvalidPaymentSecret)?;
    let taker_pk =
        PublicKey::from_str(&request.taker_pubkey).map_err(|_| APIError::InvalidPubkey)?;

    if get_current_timestamp() > swapstring.swap_info.expiry {
        unlocked_state.update_maker_swap_status(&swapstring.payment_hash, SwapStatus::Expired);
        return Err(APIError::ExpiredSwapOffer);
    }

    let payment_preimage = unlocked_state
        .channel_manager
        .get_payment_preimage(swapstring.payment_hash, payment_secret)
        .map_err(|_| APIError::MissingSwapPaymentPreimage)?;

    let swap_info = swapstring.swap_info;
    let receive_hints = unlocked_state
        .channel_manager
        .list_usable_channels()
        .iter()
        .filter(|details| {
            match get_rgb_channel_info_optional(
                &details.channel_id,
                false,
                unlocked_state.kv_store.as_ref(),
            ) {
                _ if swap_info.is_from_btc() => true,
                Some(rgb_info) if Some(rgb_info.contract_id) == swap_info.from_asset => true,
                _ => false,
            }
        })
        .map(|details| {
            let config = details.counterparty.forwarding_info.as_ref().unwrap();
            RouteHint(vec![RouteHintHop {
                src_node_id: details.counterparty.node_id,
                short_channel_id: details.short_channel_id.unwrap(),
                cltv_expiry_delta: config.cltv_expiry_delta,
                htlc_maximum_msat: None,
                htlc_minimum_msat: None,
                fees: RoutingFees {
                    base_msat: config.fee_base_msat,
                    proportional_millionths: config.fee_proportional_millionths,
                },
                htlc_maximum_rgb: None,
            }])
        })
        .collect();

    let rgb_payment = swap_info
        .to_asset
        .map(|to_asset| (to_asset, swap_info.qty_to));
    let first_leg = get_route(
        &unlocked_state.channel_manager,
        &unlocked_state.router,
        unlocked_state.runtime_node_id(),
        taker_pk,
        if swap_info.is_to_btc() {
            Some(swap_info.qty_to + SDK_HTLC_MIN_MSAT)
        } else {
            Some(SDK_HTLC_MIN_MSAT)
        },
        rgb_payment,
        vec![],
    );

    let rgb_payment = swap_info
        .from_asset
        .map(|from_asset| (from_asset, swap_info.qty_from));
    let second_leg = get_route(
        &unlocked_state.channel_manager,
        &unlocked_state.router,
        taker_pk,
        unlocked_state.runtime_node_id(),
        if swap_info.is_to_btc() || swap_info.is_asset_asset() {
            Some(SDK_HTLC_MIN_MSAT)
        } else {
            Some(swap_info.qty_from + SDK_HTLC_MIN_MSAT)
        },
        rgb_payment,
        receive_hints,
    );

    let (mut first_leg, mut second_leg) = match (first_leg, second_leg) {
        (Some(f), Some(s)) => (f, s),
        _ => return Err(APIError::NoRoute),
    };

    second_leg.paths[0].hops[0].short_channel_id |= IS_SWAP_SCID;

    first_leg.paths[0]
        .hops
        .last_mut()
        .expect("Path not to be empty")
        .fee_msat = 0;

    let fullpaths = first_leg.paths[0]
        .hops
        .clone()
        .into_iter()
        .map(|mut hop| {
            if swap_info.is_to_asset() {
                hop.rgb_payment = Some((swap_info.to_asset.unwrap(), swap_info.qty_to));
            }
            hop
        })
        .chain(second_leg.paths[0].hops.clone().into_iter().map(|mut hop| {
            if swap_info.is_from_asset() {
                hop.rgb_payment = Some((swap_info.from_asset.unwrap(), swap_info.qty_from));
            }
            hop
        }))
        .collect::<Vec<_>>();

    let total_fee = fullpaths
        .iter()
        .rev()
        .skip(1)
        .map(|hop| hop.fee_msat)
        .sum::<u64>();

    if total_fee >= SDK_MAX_SWAP_FEE_MSAT {
        return Err(APIError::FailedPayment(format!(
            "Fee too high: {total_fee}"
        )));
    }

    let route = Route {
        paths: vec![LnPath {
            hops: fullpaths,
            blinded_tail: None,
        }],
        route_params: Some(RouteParameters {
            payment_params: PaymentParameters::for_keysend(
                unlocked_state.runtime_node_id(),
                SDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA,
                false,
            ),
            final_value_msat: 0,
            max_total_routing_fee_msat: None,
            rgb_payment: None,
        }),
    };

    if swap_info.is_to_asset() {
        write_rgb_payment_info_file(
            &swapstring.payment_hash,
            swap_info.to_asset.unwrap(),
            swap_info.qty_to,
            true,
            false,
            unlocked_state.kv_store.as_ref(),
        );
    }

    unlocked_state.update_maker_swap_status(&swapstring.payment_hash, SwapStatus::Pending);

    let payment_hash: PaymentHash = payment_preimage.into();
    let err = unlocked_state
        .channel_manager
        .send_spontaneous_payment_with_route(
            route,
            payment_hash,
            payment_preimage,
            RecipientOnionFields::spontaneous_empty(),
            PaymentId(swapstring.payment_hash.0),
        )
        .err();

    match err {
        None => Ok(()),
        Some(e) => {
            clear_rgb_payment_pending(
                &swapstring.payment_hash,
                false,
                unlocked_state.kv_store.as_ref(),
            );
            unlocked_state.update_maker_swap_status(&swapstring.payment_hash, SwapStatus::Failed);
            Err(APIError::FailedPayment(format!("{e:?}")))
        }
    }
}

pub(crate) async fn maker_init(
    state: Arc<AppState>,
    request: MakerInitRequestData,
) -> Result<MakerInitData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let from_asset = match &request.from_asset {
        None => None,
        Some(asset) => {
            Some(ContractId::from_str(asset).map_err(|_| APIError::InvalidAssetID(asset.clone()))?)
        }
    };

    let to_asset = match &request.to_asset {
        None => None,
        Some(asset) => {
            Some(ContractId::from_str(asset).map_err(|_| APIError::InvalidAssetID(asset.clone()))?)
        }
    };

    if from_asset.is_none() && to_asset.is_none() {
        return Err(APIError::InvalidSwap(s!("cannot swap BTC for BTC")));
    }
    if from_asset == to_asset {
        return Err(APIError::InvalidSwap(s!("cannot swap the same asset")));
    }

    let expiry = get_current_timestamp() + request.timeout_sec as u64;
    let swap_info = SwapInfo {
        from_asset,
        to_asset,
        qty_from: request.qty_from,
        qty_to: request.qty_to,
        expiry,
    };
    let swap_data = SwapData::create_from_swap_info(&swap_info);

    if let Some(to_asset) = to_asset {
        let max_balance = get_max_local_rgb_amount(
            to_asset,
            unlocked_state.channel_manager.list_channels().iter(),
            unlocked_state.kv_store.as_ref(),
        );
        if swap_info.qty_to > max_balance {
            return Err(APIError::InsufficientAssets);
        }
    }

    let (payment_hash, payment_secret) = unlocked_state
        .channel_manager
        .create_inbound_payment(Some(SDK_DUST_LIMIT_MSAT), request.timeout_sec, None)
        .unwrap();
    unlocked_state.add_maker_swap(payment_hash, swap_data);

    let swapstring = SwapString::from_swap_info(&swap_info, payment_hash).to_string();
    Ok(MakerInitData {
        payment_hash: payment_hash.0.as_hex().to_string(),
        payment_secret: payment_secret.0.as_hex().to_string(),
        swapstring,
    })
}

pub(crate) async fn taker(state: Arc<AppState>, request: TakerRequestData) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    let swapstring = SwapString::from_str(&request.swapstring)
        .map_err(|e| APIError::InvalidSwapString(request.swapstring.clone(), e.to_string()))?;

    if get_current_timestamp() > swapstring.swap_info.expiry {
        return Err(APIError::ExpiredSwapOffer);
    }

    if let Some(from_asset) = swapstring.swap_info.from_asset {
        let max_balance = get_max_local_rgb_amount(
            from_asset,
            unlocked_state.channel_manager.list_channels().iter(),
            unlocked_state.kv_store.as_ref(),
        );
        if swapstring.swap_info.qty_from > max_balance {
            return Err(APIError::InsufficientAssets);
        }
    }

    let swap_data = SwapData::create_from_swap_info(&swapstring.swap_info);
    unlocked_state.add_taker_swap(swapstring.payment_hash, swap_data);
    Ok(())
}

pub(crate) async fn send_onion_message(
    state: Arc<AppState>,
    request: SendOnionMessageRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    if request.node_ids.is_empty() {
        return Err(APIError::InvalidNodeIds(s!(
            "sendonionmessage requires at least one node id for the path"
        )));
    }

    let mut intermediate_nodes = Vec::new();
    for pk_str in request.node_ids {
        let node_pubkey_vec = hex_str_to_vec(&pk_str).ok_or_else(|| {
            APIError::InvalidNodeIds(format!("Couldn't parse peer_pubkey '{pk_str}'"))
        })?;
        let node_pubkey = PublicKey::from_slice(&node_pubkey_vec).map_err(|_| {
            APIError::InvalidNodeIds(format!("Couldn't parse peer_pubkey '{pk_str}'"))
        })?;
        intermediate_nodes.push(node_pubkey);
    }

    if request.tlv_type < 64 {
        return Err(APIError::InvalidTlvType(s!(
            "need an integral message type above 64"
        )));
    }

    let data = hex_str_to_vec(&request.data)
        .ok_or(APIError::InvalidOnionData(s!("need a hex data string")))?;

    let destination = Destination::Node(intermediate_nodes.pop().unwrap());
    let message_send_instructions = MessageSendInstructions::WithoutReplyPath { destination };

    unlocked_state
        .onion_messenger
        .send_onion_message(
            UserOnionMessageContents {
                tlv_type: request.tlv_type,
                data,
            },
            message_send_instructions,
        )
        .map_err(|e| APIError::FailedSendingOnionMessage(format!("{e:?}")))?;

    Ok(())
}

pub(crate) async fn sync(state: Arc<AppState>) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    unlocked_state.rgb_sync()?;
    Ok(())
}

pub(crate) async fn decode_ln_invoice(
    state: Arc<AppState>,
    invoice: String,
) -> Result<DecodeLnInvoiceData, APIError> {
    let _guard = state.get_unlocked_app_state();
    let invoice =
        Bolt11Invoice::from_str(&invoice).map_err(|e| APIError::InvalidInvoice(e.to_string()))?;

    Ok(DecodeLnInvoiceData {
        amt_msat: invoice.amount_milli_satoshis(),
        expiry_sec: invoice.expiry_time().as_secs(),
        timestamp: invoice.duration_since_epoch().as_secs(),
        asset_id: invoice.rgb_contract_id().map(|c| c.to_string()),
        asset_amount: invoice.rgb_amount(),
        payment_hash: hex_str(&invoice.payment_hash().to_byte_array()),
        payment_secret: hex_str(&invoice.payment_secret().0),
        payee_pubkey: Some(invoice.get_payee_pub_key().to_string()),
        min_final_cltv_expiry_delta: invoice.min_final_cltv_expiry_delta(),
        network: match invoice.network() {
            bitcoin::Network::Bitcoin => rgb_lib::BitcoinNetwork::Mainnet,
            bitcoin::Network::Testnet => rgb_lib::BitcoinNetwork::Testnet,
            bitcoin::Network::Testnet4 => rgb_lib::BitcoinNetwork::Testnet4,
            bitcoin::Network::Signet => rgb_lib::BitcoinNetwork::Signet,
            bitcoin::Network::Regtest => rgb_lib::BitcoinNetwork::Regtest,
        },
    })
}

pub(crate) async fn decode_rgb_invoice(
    state: Arc<AppState>,
    invoice: String,
) -> Result<DecodeRgbInvoiceData, APIError> {
    let _guard = state.get_unlocked_app_state();
    let invoice_data = RgbLibInvoice::new(invoice)?.invoice_data();
    let recipient_info = RecipientInfo::new(invoice_data.recipient_id.clone())?;

    Ok(DecodeRgbInvoiceData {
        recipient_id: invoice_data.recipient_id,
        recipient_type: recipient_info.recipient_type,
        asset_schema: invoice_data.asset_schema,
        asset_id: invoice_data.asset_id,
        assignment: invoice_data.assignment,
        network: invoice_data.network,
        expiration_timestamp: invoice_data.expiration_timestamp.map(|t| t as i64),
        transport_endpoints: invoice_data.transport_endpoints,
    })
}

pub(crate) async fn invoice_status(
    state: Arc<AppState>,
    invoice: String,
) -> Result<InvoiceStatusData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let invoice =
        Bolt11Invoice::from_str(&invoice).map_err(|e| APIError::InvalidInvoice(e.to_string()))?;
    let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
    let status = match unlocked_state.inbound_payments().get(&payment_hash) {
        Some(v) => match HtlcStatus::from(v.status) {
            HtlcStatus::Pending if invoice.is_expired() => InvoiceStatus::Expired,
            HtlcStatus::Pending => InvoiceStatus::Pending,
            HtlcStatus::Claimable => InvoiceStatus::Claimable,
            HtlcStatus::Claiming => InvoiceStatus::Claiming,
            HtlcStatus::Succeeded => InvoiceStatus::Succeeded,
            HtlcStatus::Cancelled => InvoiceStatus::Cancelled,
            HtlcStatus::Failed => InvoiceStatus::Failed,
        },
        None => return Err(APIError::UnknownLNInvoice),
    };

    Ok(InvoiceStatusData { status })
}

/*
 * -------------------------------------------------------------------------
 * SDK-ONLY ADAPTERS (UniFFI-oriented)
 * -------------------------------------------------------------------------
 * This method is an SDK-facing adapter corresponding to `routes::ln_invoice`.
 * It keeps route-equivalent semantics while using SDK-native parameter shape.
 */
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_ln_invoice(
    state: Arc<AppState>,
    amt_msat: Option<u64>,
    expiry_sec: u32,
    asset_id: Option<String>,
    asset_amount: Option<u64>,
    payment_hash: Option<String>,
    description_hash: Option<String>,
    min_final_cltv_expiry_delta: Option<u16>,
) -> Result<LnInvoiceData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let contract_id = if let Some(asset_id) = asset_id {
        Some(ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?)
    } else {
        None
    };

    if contract_id.is_some() && amt_msat.unwrap_or(0) < SDK_INVOICE_MIN_MSAT {
        return Err(APIError::InvalidAmount(format!(
            "amt_msat cannot be less than {} when transferring an RGB asset",
            SDK_INVOICE_MIN_MSAT
        )));
    }

    let created_at = get_current_timestamp();
    let requested_payment_hash = match payment_hash {
        Some(payment_hash) => {
            let payment_hash = validate_and_parse_payment_hash(&payment_hash)?;
            if unlocked_state
                .inbound_payments()
                .contains_key(&payment_hash)
            {
                return Err(APIError::PaymentHashAlreadyUsed);
            }
            Some(payment_hash)
        }
        None => None,
    };
    let description = match description_hash {
        Some(description_hash) => {
            Bolt11InvoiceDescription::Hash(validate_and_parse_description_hash(&description_hash)?)
        }
        None => Bolt11InvoiceDescription::Direct(Description::empty()),
    };

    let invoice_params = Bolt11InvoiceParameters {
        amount_msats: amt_msat,
        description,
        invoice_expiry_delta_secs: Some(expiry_sec),
        min_final_cltv_expiry_delta,
        payment_hash: requested_payment_hash,
        contract_id,
        asset_amount,
    };

    let invoice = match unlocked_state
        .channel_manager
        .create_bolt11_invoice(invoice_params)
    {
        Ok(inv) => inv,
        Err(e) => return Err(APIError::FailedInvoiceCreation(e.to_string())),
    };

    let (payment_hash, invoice_type) = match requested_payment_hash {
        Some(payment_hash) => (
            payment_hash,
            InvoiceType::Hodl {
                async_payment_recipient: false,
            },
        ),
        None => (
            PaymentHash((*invoice.payment_hash()).to_byte_array()),
            InvoiceType::AutoClaim,
        ),
    };
    unlocked_state.add_inbound_payment(
        payment_hash,
        PaymentInfo {
            preimage: None,
            secret: Some(*invoice.payment_secret()),
            status: HtlcStatus::Pending,
            amt_msat,
            claim_deadline_height: None,
            created_at,
            updated_at: created_at,
            payee_pubkey: unlocked_state.runtime_node_id(),
            expires_at: Some(created_at + expiry_sec as u64),
            invoice_type: Some(invoice_type),
        },
    );

    Ok(LnInvoiceData {
        invoice: invoice.to_string(),
    })
}

fn payment_type_from_invoice(invoice_type: Option<InvoiceType>) -> PaymentType {
    match invoice_type.unwrap_or(InvoiceType::AutoClaim) {
        InvoiceType::AutoClaim => PaymentType::InboundAutoClaim,
        InvoiceType::Hodl { .. } => PaymentType::InboundHodl,
    }
}

pub(crate) async fn list_payments(state: Arc<AppState>) -> Result<Vec<PaymentData>, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    // Keep inbound invoice status consistent with expiry when payments are read.
    let inbound_payments = unlocked_state.list_updated_inbound_payments();
    let outbound_payments = unlocked_state.outbound_payments();
    let mut payments = vec![];

    for (payment_hash, payment_info) in &inbound_payments {
        let (asset_amount, asset_id) = unlocked_state
            .kv_store
            .read_rgb_payment_info(payment_hash, true)
            .ok()
            .map(|info| (Some(info.amount), Some(info.contract_id.to_string())))
            .unwrap_or((None, None));

        payments.push(PaymentData {
            amt_msat: payment_info.amt_msat,
            asset_amount,
            asset_id,
            payment_hash: hex_str(&payment_hash.0),
            payment_type: payment_type_from_invoice(payment_info.invoice_type),
            status: payment_info.status,
            created_at: payment_info.created_at,
            updated_at: payment_info.updated_at,
            payee_pubkey: payment_info.payee_pubkey.to_string(),
            preimage: payment_info.preimage.map(|p| hex_str(&p.0)),
        });
    }

    for (payment_id, payment_info) in &outbound_payments {
        let payment_hash = &PaymentHash(payment_id.0);

        let (asset_amount, asset_id) = unlocked_state
            .kv_store
            .read_rgb_payment_info(payment_hash, false)
            .ok()
            .map(|info| (Some(info.amount), Some(info.contract_id.to_string())))
            .unwrap_or((None, None));

        payments.push(PaymentData {
            amt_msat: payment_info.amt_msat,
            asset_amount,
            asset_id,
            payment_hash: hex_str(&payment_hash.0),
            payment_type: PaymentType::Outbound,
            status: payment_info.status,
            created_at: payment_info.created_at,
            updated_at: payment_info.updated_at,
            payee_pubkey: payment_info.payee_pubkey.to_string(),
            preimage: payment_info.preimage.map(|p| hex_str(&p.0)),
        });
    }

    Ok(payments)
}

pub(crate) async fn get_payment(
    state: Arc<AppState>,
    payment_hash_hex: String,
    payment_type: PaymentType,
) -> Result<PaymentData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let payment_hash_vec = hex_str_to_vec(&payment_hash_hex);
    if payment_hash_vec.is_none() || payment_hash_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidPaymentHash(payment_hash_hex));
    }
    let requested_ph = PaymentHash(payment_hash_vec.unwrap().try_into().unwrap());

    match payment_type {
        PaymentType::InboundAutoClaim | PaymentType::InboundHodl => {
            let inbound_payments = unlocked_state.list_updated_inbound_payments();
            for (payment_hash, payment_info) in &inbound_payments {
                if payment_hash == &requested_ph
                    && payment_type_from_invoice(payment_info.invoice_type) == payment_type
                {
                    let (asset_amount, asset_id) = unlocked_state
                        .kv_store
                        .read_rgb_payment_info(payment_hash, true)
                        .ok()
                        .map(|info| (Some(info.amount), Some(info.contract_id.to_string())))
                        .unwrap_or((None, None));

                    return Ok(PaymentData {
                        amt_msat: payment_info.amt_msat,
                        asset_amount,
                        asset_id,
                        payment_hash: hex_str(&payment_hash.0),
                        payment_type: payment_type_from_invoice(payment_info.invoice_type),
                        status: payment_info.status,
                        created_at: payment_info.created_at,
                        updated_at: payment_info.updated_at,
                        payee_pubkey: payment_info.payee_pubkey.to_string(),
                        preimage: payment_info.preimage.map(|p| hex_str(&p.0)),
                    });
                }
            }
        }
        PaymentType::Outbound => {
            let outbound_payments = unlocked_state.outbound_payments();
            for (payment_id, payment_info) in &outbound_payments {
                let payment_hash = &PaymentHash(payment_id.0);
                if payment_hash == &requested_ph {
                    let (asset_amount, asset_id) = unlocked_state
                        .kv_store
                        .read_rgb_payment_info(payment_hash, false)
                        .ok()
                        .map(|info| (Some(info.amount), Some(info.contract_id.to_string())))
                        .unwrap_or((None, None));

                    return Ok(PaymentData {
                        amt_msat: payment_info.amt_msat,
                        asset_amount,
                        asset_id,
                        payment_hash: hex_str(&payment_hash.0),
                        payment_type: PaymentType::Outbound,
                        status: payment_info.status,
                        created_at: payment_info.created_at,
                        updated_at: payment_info.updated_at,
                        payee_pubkey: payment_info.payee_pubkey.to_string(),
                        preimage: payment_info.preimage.map(|p| hex_str(&p.0)),
                    });
                }
            }
        }
    }

    Err(APIError::PaymentNotFound(payment_hash_hex))
}

pub(crate) async fn cancel_hodl_invoice(
    state: Arc<AppState>,
    request: CancelHodlInvoiceRequestData,
) -> Result<(), APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let payment_hash = validate_and_parse_payment_hash(&request.payment_hash)?;
    let payment_info = unlocked_state
        .get_inbound_payments()
        .payments
        .get(&payment_hash)
        .cloned()
        .ok_or(APIError::UnknownLNInvoice)?;
    if !matches!(payment_info.invoice_type, Some(InvoiceType::Hodl { .. })) {
        return Err(APIError::InvoiceNotHodl);
    }
    match payment_info.status {
        HtlcStatus::Succeeded => return Err(APIError::InvoiceAlreadyClaimed),
        HtlcStatus::Claimable => {}
        HtlcStatus::Claiming => return Err(APIError::InvoiceSettlingInProgress),
        _ => return Err(APIError::InvoiceNotClaimable),
    }

    unlocked_state
        .fail_htlc_backwards_and_update_inbound_payment(payment_hash, HtlcStatus::Cancelled);
    Ok(())
}

pub(crate) async fn claim_hodl_invoice(
    state: Arc<AppState>,
    request: ClaimHodlInvoiceRequestData,
) -> Result<ClaimHodlInvoiceResponseData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let payment_hash = validate_and_parse_payment_hash(&request.payment_hash)?;
    let preimage = validate_and_parse_payment_preimage(&request.payment_preimage, &payment_hash)?;

    let terminal_error = {
        let mut inbound = unlocked_state.get_inbound_payments();
        let Some(existing_payment_mut) = inbound.payments.get_mut(&payment_hash) else {
            return Err(APIError::UnknownLNInvoice);
        };

        if !matches!(
            existing_payment_mut.invoice_type,
            Some(InvoiceType::Hodl { .. })
        ) {
            return Err(APIError::InvoiceNotHodl);
        }

        match existing_payment_mut.status {
            HtlcStatus::Succeeded => {
                let computed_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
                if computed_hash != payment_hash {
                    return Err(APIError::InvalidPaymentPreimage);
                }
                if let Some(stored_preimage) = existing_payment_mut.preimage {
                    if stored_preimage != preimage {
                        return Err(APIError::InvalidPaymentPreimage);
                    }
                }
                return Ok(ClaimHodlInvoiceResponseData { changed: false });
            }
            HtlcStatus::Claiming => return Err(APIError::InvoiceSettlingInProgress),
            HtlcStatus::Claimable => {}
            _ => return Err(APIError::InvoiceNotClaimable),
        }

        let current_height = unlocked_state.channel_manager.current_best_block().height;
        let now_ts = get_current_timestamp();
        let mut terminal_error = None;

        if let Some(deadline_height) = existing_payment_mut.claim_deadline_height {
            if current_height >= deadline_height {
                terminal_error = Some(APIError::ClaimDeadlineExceeded);
            }
        }

        if terminal_error.is_none() {
            if let Some(expiry) = existing_payment_mut.expires_at {
                if now_ts >= expiry {
                    terminal_error = Some(APIError::InvoiceExpired);
                }
            }
        }

        if terminal_error.is_none() {
            existing_payment_mut.status = HtlcStatus::Claiming;
            existing_payment_mut.updated_at = now_ts;
            unlocked_state.save_inbound_payments(inbound);
        }

        terminal_error
    };

    if let Some(terminal_error) = terminal_error {
        unlocked_state
            .fail_htlc_backwards_and_update_inbound_payment(payment_hash, HtlcStatus::Failed);
        return Err(terminal_error);
    }

    unlocked_state.channel_manager.claim_funds(preimage);
    Ok(ClaimHodlInvoiceResponseData { changed: true })
}

pub(crate) async fn inflate(
    state: Arc<AppState>,
    request: InflateRequestData,
) -> Result<InflateResponseData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();
    if unlocked_state.external_signer_mode {
        return Err(APIError::UnsupportedInExternalSignerMode(
            "inflate is not supported in external signer mode".to_string(),
        ));
    }

    if *unlocked_state.rgb_send_lock.lock().unwrap() {
        return Err(APIError::OpenChannelInProgress);
    }

    let unlocked_state_copy = unlocked_state.clone();
    let inflate_result = tokio::task::spawn_blocking(move || {
        unlocked_state_copy.rgb_inflate(
            request.asset_id,
            request.inflation_amounts,
            request.fee_rate,
            request.min_confirmations,
        )
    })
    .await
    .unwrap()?;

    Ok(InflateResponseData {
        txid: inflate_result.txid,
    })
}

fn map_swap(
    payment_hash: &PaymentHash,
    swap_data: &SwapData,
    taker: bool,
    state: &crate::utils::UnlockedAppState,
) -> SwapViewData {
    let mut status: SwapStatus = swap_data.status;
    if status == SwapStatus::Waiting && get_current_timestamp() > swap_data.swap_info.expiry {
        status = SwapStatus::Expired;
    } else if status == SwapStatus::Pending
        && get_current_timestamp() > swap_data.initiated_at.unwrap() + 86400
    {
        status = SwapStatus::Failed;
    }
    let current_status: SwapStatus = swap_data.status;
    if status != current_status {
        if taker {
            state.update_taker_swap_status(payment_hash, status);
        } else {
            state.update_maker_swap_status(payment_hash, status);
        }
    }

    SwapViewData {
        payment_hash: payment_hash.to_string(),
        qty_from: swap_data.swap_info.qty_from,
        qty_to: swap_data.swap_info.qty_to,
        from_asset: swap_data.swap_info.from_asset.map(|c| c.to_string()),
        to_asset: swap_data.swap_info.to_asset.map(|c| c.to_string()),
        status,
        requested_at: swap_data.requested_at,
        initiated_at: swap_data.initiated_at,
        expires_at: swap_data.swap_info.expiry,
        completed_at: swap_data.completed_at,
    }
}

pub(crate) async fn get_swap(
    state: Arc<AppState>,
    payment_hash_hex: String,
    taker: bool,
) -> Result<SwapViewData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let payment_hash_vec = hex_str_to_vec(&payment_hash_hex);
    if payment_hash_vec.is_none() || payment_hash_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidPaymentHash(payment_hash_hex));
    }
    let requested_ph = PaymentHash(payment_hash_vec.unwrap().try_into().unwrap());

    if taker {
        let taker_swaps = unlocked_state.taker_swaps();
        if let Some(sd) = taker_swaps.get(&requested_ph) {
            return Ok(map_swap(&requested_ph, sd, true, unlocked_state));
        }
    } else {
        let maker_swaps = unlocked_state.maker_swaps();
        if let Some(sd) = maker_swaps.get(&requested_ph) {
            return Ok(map_swap(&requested_ph, sd, false, unlocked_state));
        }
    }

    Err(APIError::SwapNotFound(payment_hash_hex))
}

pub(crate) async fn list_swaps(state: Arc<AppState>) -> Result<SwapListData, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let taker_swaps = unlocked_state.taker_swaps();
    let maker_swaps = unlocked_state.maker_swaps();

    Ok(SwapListData {
        taker: taker_swaps
            .iter()
            .map(|(ph, sd)| map_swap(ph, sd, true, unlocked_state))
            .collect(),
        maker: maker_swaps
            .iter()
            .map(|(ph, sd)| map_swap(ph, sd, false, unlocked_state))
            .collect(),
    })
}

pub(crate) async fn list_transactions(
    state: Arc<AppState>,
    skip_sync: bool,
) -> Result<Vec<TransactionData>, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut transactions = vec![];
    for tx in unlocked_state.rgb_list_transactions(skip_sync)? {
        transactions.push(TransactionData {
            transaction_type: match tx.transaction_type {
                rgb_lib::wallet::TransactionType::RgbSend => TransactionType::RgbSend,
                rgb_lib::wallet::TransactionType::Drain => TransactionType::Drain,
                rgb_lib::wallet::TransactionType::CreateUtxos => TransactionType::CreateUtxos,
                rgb_lib::wallet::TransactionType::SendBtc => TransactionType::SendBtc,
                rgb_lib::wallet::TransactionType::Incoming => TransactionType::Incoming,
            },
            txid: tx.txid,
            received: tx.received,
            sent: tx.sent,
            fee: tx.fee,
            confirmation_time: tx.confirmation_time.map(|ct| BlockTime {
                height: ct.height,
                timestamp: ct.timestamp,
            }),
        });
    }

    Ok(transactions)
}

pub(crate) async fn list_transfers(
    state: Arc<AppState>,
    asset_id: String,
) -> Result<Vec<TransferData>, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut transfers = vec![];
    for transfer in unlocked_state.rgb_list_transfers(asset_id)? {
        transfers.push(TransferData {
            idx: transfer.idx,
            created_at: transfer.created_at,
            updated_at: transfer.updated_at,
            status: match transfer.status {
                rgb_lib::TransferStatus::Initiated => TransferStatus::Initiated,
                rgb_lib::TransferStatus::WaitingCounterparty => TransferStatus::WaitingCounterparty,
                rgb_lib::TransferStatus::WaitingSafeHeight => TransferStatus::WaitingSafeHeight,
                rgb_lib::TransferStatus::WaitingConfirmations => {
                    TransferStatus::WaitingConfirmations
                }
                rgb_lib::TransferStatus::Settled => TransferStatus::Settled,
                rgb_lib::TransferStatus::Failed => TransferStatus::Failed,
            },
            requested_assignment: transfer.requested_assignment,
            assignments: transfer.assignments,
            kind: match transfer.kind {
                rgb_lib::wallet::TransferKind::Issuance => TransferKind::Issuance,
                rgb_lib::wallet::TransferKind::ReceiveBlind => TransferKind::ReceiveBlind,
                rgb_lib::wallet::TransferKind::ReceiveWitness => TransferKind::ReceiveWitness,
                rgb_lib::wallet::TransferKind::Send => TransferKind::Send,
                rgb_lib::wallet::TransferKind::Inflation => TransferKind::Inflation,
                rgb_lib::wallet::TransferKind::Burn => TransferKind::Burn,
            },
            txid: transfer.txid,
            recipient_id: transfer.recipient_id,
            receive_utxo: transfer.receive_utxo.map(|u| u.to_string()),
            change_utxo: transfer.change_utxo.map(|u| u.to_string()),
            expiration: transfer.expiration_timestamp.map(|t| t as i64),
            transport_endpoints: transfer
                .transport_endpoints
                .iter()
                .map(|tte| TransferTransportEndpointData {
                    endpoint: tte.endpoint.clone(),
                    transport_type: match tte.transport_type {
                        rgb_lib::TransportType::JsonRpc => TransportType::JsonRpc,
                    },
                    used: tte.used,
                })
                .collect(),
        });
    }
    Ok(transfers)
}

pub(crate) async fn list_unspents(
    state: Arc<AppState>,
    skip_sync: bool,
) -> Result<Vec<UnspentData>, APIError> {
    let guard = check_unlocked(&state).await?;
    let unlocked_state = guard.as_ref().unwrap();

    let mut unspents = vec![];
    for unspent in unlocked_state.rgb_list_unspents(skip_sync)? {
        unspents.push(UnspentData {
            utxo: UtxoData {
                outpoint: unspent.utxo.outpoint.to_string(),
                btc_amount: unspent.utxo.btc_amount,
                colorable: unspent.utxo.colorable,
            },
            rgb_allocations: unspent
                .rgb_allocations
                .iter()
                .map(|a| RgbAllocationData {
                    asset_id: a.asset_id.clone(),
                    assignment: a.assignment.clone(),
                    settled: a.settled,
                })
                .collect(),
        });
    }
    Ok(unspents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::FilesystemLogger;
    use crate::ldk::attach_external_signer_transport;
    use crate::signer::in_process_transport::InProcessExternalSignerTransport;
    use crate::signer::types::{
        ChannelPublicKeys, ExternalSignerRequest, ExternalSignerResponse, SpendableOutputSignInput,
        WalletInputMetadata,
    };
    use crate::signer::vls_adapter::ExternalSignerBackend;
    use crate::signer::{read_key_source_file, RlnSignerError, SignerIdentity};
    use crate::utils::{AppState, StaticState};
    use rgb_lib::BitcoinNetwork;
    use rln_migration::{Migrator, MigratorTrait};
    use sea_orm::{ConnectOptions, Database};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex, RwLock};
    use tokio::sync::Mutex as TokioMutex;
    use tokio_util::sync::CancellationToken;

    fn mock_locked_state() -> Arc<AppState> {
        let unique = format!(
            "rln-sdk-external-tests-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let storage_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&storage_dir).expect("create temp storage dir");
        let db_path = storage_dir.join("rln_db");
        let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
        let database =
            crate::runtime::block_on(Database::connect(ConnectOptions::new(connection_string)))
                .expect("mock database connection");
        crate::runtime::block_on(Migrator::up(&database, None)).expect("run migrations");
        Arc::new(AppState {
            static_state: Arc::new(StaticState {
                ldk_peer_listening_port: 9735,
                network: BitcoinNetwork::Regtest,
                storage_dir_path: storage_dir.clone(),
                ldk_data_dir: storage_dir.join(".ldk"),
                logger: Arc::new(FilesystemLogger::new(storage_dir)),
                max_media_upload_size_mb: 1,
                enable_virtual_channels_v0: false,
                virtual_peer_pubkeys: vec![],
                lsp_base_url: None,
                lsp_bearer_token: None,
                database: RwLock::new(Arc::new(database)),
                vss_url: None,
                vss_allow_empty_restore: false,
            }),
            cancel_token: CancellationToken::new(),
            unlocked_app_state: Arc::new(TokioMutex::new(None)),
            ldk_background_services: Arc::new(Mutex::new(None)),
            attached_external_signer: Arc::new(Mutex::new(None)),
            changing_state: Mutex::new(false),
            root_public_key: None,
            revoked_tokens: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn sample_bootstrap() -> BootstrapData {
        BootstrapData {
            identity: SignerIdentity {
                node_id: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    .to_string(),
                account_xpub_vanilla: "xpub661MyMwAqRbcF9i3M7GQw1k8f7mR8n4x9nW2f2dJ8f1h9sP2b3K4L5M6N7P8Q9R0S1T2U3V4W5X6Y7Z8".to_string(),
                account_xpub_colored: "xpub661MyMwAqRbcF9i3M7GQw1k8f7mR8n4x9nW2f2dJ8f1h9sP2b3K4L5M6N7P8Q9R0S1T2U3V4W5X6Y7Z8".to_string(),
                master_fingerprint: "00000000".to_string(),
            },
            protocol_version: "1".to_string(),
            api_level: 1,
        }
    }

    fn sample_unlock_request() -> UnlockRequest {
        UnlockRequest {
            password: "unused-in-external-mode".to_string(),
            bitcoind_rpc_username: "user".to_string(),
            bitcoind_rpc_password: "pass".to_string(),
            bitcoind_rpc_host: "127.0.0.1".to_string(),
            bitcoind_rpc_port: 18443,
            indexer_url: Some("127.0.0.1:50001".to_string()),
            proxy_endpoint: Some("rpc://127.0.0.1:3000/json-rpc".to_string()),
            announce_addresses: vec![],
            announce_alias: None,
        }
    }

    struct TestBootstrapBackend {
        bootstrap: BootstrapData,
    }

    impl TestBootstrapBackend {
        fn new(bootstrap: BootstrapData) -> Self {
            Self { bootstrap }
        }

        fn unsupported<T>() -> Result<T, RlnSignerError> {
            Err(RlnSignerError::Unsupported(
                "unused in sdk tests".to_string(),
            ))
        }
    }

    impl ExternalSignerBackend for TestBootstrapBackend {
        fn call(
            &self,
            request: ExternalSignerRequest,
        ) -> Result<ExternalSignerResponse, RlnSignerError> {
            match request {
                ExternalSignerRequest::Bootstrap => {
                    Ok(ExternalSignerResponse::Bootstrap(self.bootstrap.clone()))
                }
                _ => Self::unsupported(),
            }
        }

        fn bootstrap(&self) -> Result<BootstrapData, RlnSignerError> {
            Ok(self.bootstrap.clone())
        }

        fn node_get_node_id(&self, _recipient: String) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_get_destination_script(
            &self,
            _channel_keys_id_hex: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_get_shutdown_scriptpubkey(&self) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_encrypt_peer_storage_payload(
            &self,
            _plaintext_hex: String,
            _random_bytes_hex: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_decrypt_peer_storage_payload(
            &self,
            _ciphertext_hex: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_encrypt_blinded_message_payload(
            &self,
            _plaintext_hex: String,
            _rho_hex: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_decrypt_blinded_message_payload(
            &self,
            _ciphertext_hex: String,
            _rho_hex: String,
        ) -> Result<(String, bool), RlnSignerError> {
            Self::unsupported()
        }

        fn node_get_hmac_for_offer_key(&self) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_crypt_for_offer(
            &self,
            _bytes_hex: String,
            _nonce_hex: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_create_inbound_payment(
            &self,
            _min_value_msat: Option<u64>,
            _invoice_expiry_delta_secs: u32,
            _random_bytes_hex: String,
            _current_time: u64,
            _min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<(String, String), RlnSignerError> {
            Self::unsupported()
        }

        fn node_create_inbound_payment_for_hash(
            &self,
            _payment_hash_hex: String,
            _min_value_msat: Option<u64>,
            _invoice_expiry_delta_secs: u32,
            _current_time: u64,
            _min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_create_spontaneous_payment_secret(
            &self,
            _min_value_msat: Option<u64>,
            _invoice_expiry_delta_secs: u32,
            _current_time: u64,
            _min_final_cltv_expiry_delta: Option<u16>,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn node_verify_inbound_payment(
            &self,
            _payment_hash_hex: String,
            _payment_secret_hex: String,
            _total_msat: u64,
            _highest_seen_timestamp: u64,
        ) -> Result<(Option<String>, Option<u16>), RlnSignerError> {
            Self::unsupported()
        }

        fn node_get_payment_preimage(
            &self,
            _payment_hash_hex: String,
            _payment_secret_hex: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn prepare_async_payments_hashes(
            &self,
            _host_node_id_hex: String,
            _start_index: u64,
            _batch_size: u32,
        ) -> Result<Vec<crate::signer::types::AsyncPaymentsHashEntry>, RlnSignerError> {
            Self::unsupported()
        }

        fn generate_channel_keys_id(
            &self,
            _inbound: bool,
            _channel_value_satoshis: u64,
            _user_channel_id: u128,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn derive_channel_signer(
            &self,
            _channel_value_satoshis: u64,
            _channel_keys_id_hex: String,
        ) -> Result<(String, ChannelPublicKeys), RlnSignerError> {
            Self::unsupported()
        }

        fn sign_spendable_outputs_psbt(
            &self,
            _inputs: Vec<SpendableOutputSignInput>,
            _psbt: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn sign_rgb_psbt(
            &self,
            _descriptors: Vec<String>,
            _psbt: String,
        ) -> Result<String, RlnSignerError> {
            Self::unsupported()
        }

        fn get_wallet_input_metadata(
            &self,
            _txid_hex: String,
            _vout: u32,
            _script_pubkey_hex: Option<String>,
            _amount_sat: Option<u64>,
        ) -> Result<Option<WalletInputMetadata>, RlnSignerError> {
            Self::unsupported()
        }

        fn find_derivation_matches_for_script(
            &self,
            _script_pubkey_hex: String,
            _max_index: u32,
        ) -> Result<Vec<crate::signer::types::DerivedAddressMatch>, RlnSignerError> {
            Self::unsupported()
        }
    }

    fn attach_test_external_signer(
        state: &Arc<AppState>,
        bootstrap: BootstrapData,
    ) -> Result<(), APIError> {
        let backend = Arc::new(TestBootstrapBackend::new(bootstrap));
        let transport = InProcessExternalSignerTransport::new(backend);
        let attachment = attach_external_signer_transport(Arc::new(transport))?;
        state.set_attached_external_signer(Some(attachment));
        Ok(())
    }

    #[tokio::test]
    async fn external_init_persists_key_source_file() {
        let state = mock_locked_state();
        init_with_external_signer(
            state.clone(),
            KeySourceFile::from_bootstrap(&sample_bootstrap()),
        )
        .await
        .expect("external init");

        let key_source = read_key_source_file(&state.static_state.storage_dir_path)
            .expect("read key source")
            .expect("key source present");
        assert_eq!(
            key_source.mode,
            crate::signer::key_source::EXTERNAL_SIGNER_MODE_V1
        );
    }

    #[tokio::test]
    async fn internal_init_is_rejected_in_external_mode() {
        let state = mock_locked_state();
        init_with_external_signer(
            state.clone(),
            KeySourceFile::from_bootstrap(&sample_bootstrap()),
        )
        .await
        .expect("external init");

        let res = init(state, "StrongPass123!".to_string(), None).await;
        assert!(matches!(res, Err(APIError::ExternalSignerRequired)));
    }

    #[tokio::test]
    async fn internal_unlock_is_rejected_in_external_mode() {
        let state = mock_locked_state();
        init_with_external_signer(
            state.clone(),
            KeySourceFile::from_bootstrap(&sample_bootstrap()),
        )
        .await
        .expect("external init");

        let res = unlock(state, sample_unlock_request()).await;
        assert!(matches!(res, Err(APIError::ExternalSignerRequired)));
    }

    #[tokio::test]
    async fn external_init_is_idempotent_for_existing_key_source() {
        let state = mock_locked_state();
        init_with_external_signer(
            state.clone(),
            KeySourceFile::from_bootstrap(&sample_bootstrap()),
        )
        .await
        .expect("external init");

        let res =
            init_with_external_signer(state, KeySourceFile::from_bootstrap(&sample_bootstrap()))
                .await;
        assert!(matches!(res, Err(APIError::AlreadyInitialized)));
    }

    #[tokio::test]
    async fn external_init_with_unsupported_api_level_is_rejected() {
        let state = mock_locked_state();
        let mut bootstrap = sample_bootstrap();
        bootstrap.api_level = 99;
        let res = init_with_external_signer(state, KeySourceFile::from_bootstrap(&bootstrap)).await;
        assert!(matches!(res, Err(APIError::ExternalSignerProtocolError(_))));
    }

    #[tokio::test]
    async fn attached_external_unlock_without_registered_signer_is_unavailable() {
        let state = mock_locked_state();
        let res = unlock_with_attached_external_signer(state, sample_unlock_request()).await;
        assert!(matches!(res, Err(APIError::ExternalSignerUnavailable(_))));
    }

    #[tokio::test]
    async fn attached_external_unlock_without_registered_signer_resets_changing_state() {
        let state = mock_locked_state();
        let res =
            unlock_with_attached_external_signer(Arc::clone(&state), sample_unlock_request()).await;
        assert!(matches!(res, Err(APIError::ExternalSignerUnavailable(_))));
        assert!(!*state.get_changing_state());
    }

    #[tokio::test]
    async fn attached_external_unlock_with_mismatched_bootstrap_fails() {
        let state = mock_locked_state();
        let bootstrap_a = sample_bootstrap();
        init_with_external_signer(state.clone(), KeySourceFile::from_bootstrap(&bootstrap_a))
            .await
            .expect("external init");

        let mut bootstrap_b = sample_bootstrap();
        bootstrap_b.identity.master_fingerprint = "ffffffff".to_string();
        attach_test_external_signer(&state, bootstrap_b).expect("attach mismatched signer");
        // Unlock should fail because attached signer does not match persisted key_source.json.
        let res = unlock_with_attached_external_signer(state, sample_unlock_request()).await;
        assert!(matches!(
            res,
            Err(APIError::ExternalSignerProtocolError(_)) | Err(APIError::ExternalSignerMismatch)
        ));
    }

    #[tokio::test]
    async fn attached_external_unlock_with_mismatched_bootstrap_resets_changing_state() {
        let state = mock_locked_state();
        let bootstrap_a = sample_bootstrap();
        init_with_external_signer(state.clone(), KeySourceFile::from_bootstrap(&bootstrap_a))
            .await
            .expect("external init");

        let mut bootstrap_b = sample_bootstrap();
        bootstrap_b.identity.master_fingerprint = "ffffffff".to_string();
        attach_test_external_signer(&state, bootstrap_b).expect("attach mismatched signer");
        let res =
            unlock_with_attached_external_signer(Arc::clone(&state), sample_unlock_request()).await;
        assert!(matches!(
            res,
            Err(APIError::ExternalSignerProtocolError(_)) | Err(APIError::ExternalSignerMismatch)
        ));
        assert!(!*state.get_changing_state());
    }

    #[tokio::test]
    async fn external_mode_rejects_issue_and_inflate_operations() {
        let state = mock_locked_state();
        let bootstrap = sample_bootstrap();
        init_with_external_signer(state.clone(), KeySourceFile::from_bootstrap(&bootstrap))
            .await
            .expect("external init");

        attach_test_external_signer(&state, bootstrap.clone()).expect("attach test signer");
        let unlock_res =
            unlock_with_attached_external_signer(state.clone(), sample_unlock_request()).await;
        // If unlock cannot proceed in this isolated unit env (e.g. missing bitcoind),
        // this test cannot validate runtime mode guards.
        if unlock_res.is_err() {
            return;
        }

        let nia = issue_asset_nia(
            state.clone(),
            IssueAssetNiaRequestData {
                amounts: vec![1],
                ticker: "T".to_string(),
                name: "Token".to_string(),
                precision: 0,
            },
        )
        .await;
        assert!(matches!(
            nia,
            Err(APIError::UnsupportedInExternalSignerMode(_))
        ));

        let cfa = issue_asset_cfa(
            state.clone(),
            IssueAssetCfaRequestData {
                amounts: vec![1],
                name: "CFA".to_string(),
                details: None,
                precision: 0,
                file_digest: None,
            },
        )
        .await;
        assert!(matches!(
            cfa,
            Err(APIError::UnsupportedInExternalSignerMode(_))
        ));

        let ifa = issue_asset_ifa(
            state.clone(),
            IssueAssetIFARequestData {
                amounts: vec![1],
                inflation_amounts: vec![1],
                ticker: "I".to_string(),
                name: "IFA".to_string(),
                precision: 0,
                reject_list_url: None,
            },
        )
        .await;
        assert!(matches!(
            ifa,
            Err(APIError::UnsupportedInExternalSignerMode(_))
        ));

        let uda = issue_asset_uda(
            state.clone(),
            IssueAssetUdaRequestData {
                ticker: "U".to_string(),
                name: "UDA".to_string(),
                details: None,
                precision: 0,
                media_file_digest: None,
                attachments_file_digests: vec![],
            },
        )
        .await;
        assert!(matches!(
            uda,
            Err(APIError::UnsupportedInExternalSignerMode(_))
        ));

        let inflate_res = inflate(
            state,
            InflateRequestData {
                asset_id: "rgb:dummy".to_string(),
                inflation_amounts: vec![1],
                fee_rate: 1,
                min_confirmations: 1,
            },
        )
        .await;
        assert!(matches!(
            inflate_res,
            Err(APIError::UnsupportedInExternalSignerMode(_))
        ));
    }
}
