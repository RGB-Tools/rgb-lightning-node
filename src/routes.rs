use amplify::{map, s};
use axum::{extract::State, Json};
use axum_extra::extract::WithRejection;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lightning::impl_writeable_tlv_based_enum;
use lightning::ln::ChannelId;
use lightning::onion_message::{Destination, OnionMessagePath};
use lightning::rgb_utils::{
    get_rgb_channel_info_path, get_rgb_payment_info_path, parse_rgb_channel_info,
    parse_rgb_payment_info,
};
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{Path as LnPath, Route, RouteHint, RouteHintHop};
use lightning::sign::EntropySource;
use lightning::util::config::ChannelConfig;
use lightning::{
    ln::{
        channelmanager::{PaymentId, RecipientOnionFields, Retry},
        PaymentHash, PaymentPreimage,
    },
    rgb_utils::{write_rgb_channel_info, write_rgb_payment_info_file, RgbInfo},
    routing::{
        gossip::NodeId,
        router::{PaymentParameters, RouteParameters},
    },
    util::config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig},
    util::IS_SWAP_SCID,
};
use lightning_invoice::payment::pay_invoice;
use lightning_invoice::{utils::create_invoice_from_channelmanager, Currency};
use lightning_invoice::{Bolt11Invoice, PaymentSecret};
use rgb_lib::wallet::{Invoice as RgbLibInvoice, Recipient, RecipientData};
use rgb_lib::{generate_keys, BitcoinNetwork as RgbLibNetwork, Error as RgbLibError};
use rgbstd::contract::{ContractId, SecretSeal};
use rgbwallet::RgbTransport;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::MutexGuard as TokioMutexGuard;

use crate::backup::{do_backup, restore_backup};
use crate::ldk::{start_ldk, stop_ldk, LdkBackgroundServices, MIN_CHANNEL_CONFIRMATIONS};
use crate::rgb::{get_bitcoin_network, get_rgb_channel_info_optional};
use crate::swap::{Swap, SwapString};
use crate::utils::{
    check_already_initialized, check_password_strength, check_password_validity,
    encrypt_and_save_mnemonic, get_max_local_rgb_amount, get_mnemonic_path, get_route, hex_str,
    hex_str_to_compressed_pubkey, hex_str_to_vec, UnlockedAppState, UserOnionMessageContents,
};
use crate::{
    disk,
    error::APIError,
    ldk::{PaymentInfo, FEE_RATE, UTXO_SIZE_SAT},
    utils::{
        connect_peer_if_necessary, get_current_timestamp, no_cancel, parse_peer_info, AppState,
    },
};

const UTXO_NUM: u8 = 4;

const OPENCHANNEL_MIN_SAT: u64 = 5506;
const OPENCHANNEL_MAX_SAT: u64 = 16777215;
const OPENCHANNEL_MIN_RGB_AMT: u64 = 1;

const DUST_LIMIT_MSAT: u64 = 546000;

pub(crate) const HTLC_MIN_MSAT: u64 = 3000000;

const INVOICE_MIN_MSAT: u64 = HTLC_MIN_MSAT;

pub(crate) const DEFAULT_FINAL_CLTV_EXPIRY_DELTA: u32 = 14;

#[derive(Deserialize, Serialize)]
pub(crate) struct AddressResponse {
    pub(crate) address: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Asset {
    pub(crate) asset_id: String,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) precision: u8,
    pub(crate) issued_supply: u64,
    pub(crate) timestamp: i64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AssetBalanceRequest {
    pub(crate) asset_id: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AssetBalanceResponse {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
    pub(crate) offchain_outbound: u64,
    pub(crate) offchain_inbound: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum AssetIface {
    RGB20,
    RGB21,
    RGB25,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BackupRequest {
    pub(crate) backup_path: String,
    pub(crate) password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl From<Network> for BitcoinNetwork {
    fn from(x: Network) -> BitcoinNetwork {
        match x {
            Network::Bitcoin => BitcoinNetwork::Mainnet,
            Network::Testnet => BitcoinNetwork::Testnet,
            Network::Regtest => BitcoinNetwork::Regtest,
            Network::Signet => BitcoinNetwork::Signet,
        }
    }
}

impl From<RgbLibNetwork> for BitcoinNetwork {
    fn from(x: RgbLibNetwork) -> BitcoinNetwork {
        match x {
            RgbLibNetwork::Mainnet => BitcoinNetwork::Mainnet,
            RgbLibNetwork::Testnet => BitcoinNetwork::Testnet,
            RgbLibNetwork::Regtest => BitcoinNetwork::Regtest,
            RgbLibNetwork::Signet => BitcoinNetwork::Signet,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BlockTime {
    pub(crate) height: u32,
    pub(crate) timestamp: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BtcBalance {
    pub(crate) settled: u64,
    pub(crate) future: u64,
    pub(crate) spendable: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BtcBalanceResponse {
    pub(crate) vanilla: BtcBalance,
    pub(crate) colored: BtcBalance,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ChangePasswordRequest {
    pub(crate) old_password: String,
    pub(crate) new_password: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct Channel {
    pub(crate) channel_id: String,
    pub(crate) funding_txid: Option<String>,
    pub(crate) peer_pubkey: String,
    pub(crate) peer_alias: Option<String>,
    pub(crate) short_channel_id: Option<u64>,
    pub(crate) ready: bool,
    pub(crate) capacity_sat: u64,
    pub(crate) local_balance_msat: u64,
    pub(crate) outbound_balance_msat: Option<u64>,
    pub(crate) inbound_balance_msat: Option<u64>,
    pub(crate) is_usable: bool,
    pub(crate) public: bool,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_local_amount: Option<u64>,
    pub(crate) asset_remote_amount: Option<u64>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct CloseChannelRequest {
    pub(crate) channel_id: String,
    pub(crate) peer_pubkey: String,
    pub(crate) force: bool,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ConnectPeerRequest {
    pub(crate) peer_pubkey_and_addr: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct CreateUtxosRequest {
    pub(crate) up_to: bool,
    pub(crate) num: Option<u8>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DecodeLNInvoiceRequest {
    pub(crate) invoice: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DecodeLNInvoiceResponse {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) expiry_sec: u64,
    pub(crate) timestamp: u64,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) payment_hash: String,
    pub(crate) payment_secret: String,
    pub(crate) payee_pubkey: Option<String>,
    pub(crate) network: BitcoinNetwork,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DecodeRGBInvoiceRequest {
    pub(crate) invoice: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DecodeRGBInvoiceResponse {
    pub(crate) recipient_id: String,
    pub(crate) asset_iface: Option<AssetIface>,
    pub(crate) asset_id: Option<String>,
    pub(crate) amount: Option<u64>,
    pub(crate) network: Option<BitcoinNetwork>,
    pub(crate) expiration_timestamp: Option<i64>,
    pub(crate) transport_endpoints: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DisconnectPeerRequest {
    pub(crate) peer_pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct EmptyResponse {}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub(crate) enum HTLCStatus {
    Pending,
    Succeeded,
    Failed,
}

impl_writeable_tlv_based_enum!(HTLCStatus,
    (0, Pending) => {},
    (1, Succeeded) => {},
    (2, Failed) => {};
);

#[derive(Deserialize, Serialize)]
pub(crate) struct InitRequest {
    pub(crate) password: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct InitResponse {
    pub(crate) mnemonic: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(crate) enum InvoiceStatus {
    Pending,
    Succeeded,
    Failed,
    Expired,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct InvoiceStatusRequest {
    pub(crate) invoice: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct InvoiceStatusResponse {
    pub(crate) status: InvoiceStatus,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct IssueAssetRequest {
    pub(crate) amounts: Vec<u64>,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) precision: u8,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct IssueAssetResponse {
    pub(crate) asset_id: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct KeysendRequest {
    pub(crate) dest_pubkey: String,
    pub(crate) amt_msat: u64,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct KeysendResponse {
    pub(crate) payment_hash: String,
    pub(crate) payment_preimage: String,
    pub(crate) status: HTLCStatus,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListAssetsResponse {
    pub(crate) assets: Vec<Asset>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListChannelsResponse {
    pub(crate) channels: Vec<Channel>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListPaymentsResponse {
    pub(crate) payments: Vec<Payment>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListPeersResponse {
    pub(crate) peers: Vec<Peer>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ListTradesResponse {
    pub(crate) maker: Vec<Trade>,
    pub(crate) taker: Vec<Trade>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListTransactionsResponse {
    pub(crate) transactions: Vec<Transaction>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListTransfersRequest {
    pub(crate) asset_id: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListTransfersResponse {
    pub(crate) transfers: Vec<Transfer>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ListUnspentsResponse {
    pub(crate) unspents: Vec<Unspent>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LNInvoiceRequest {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) expiry_sec: u32,
    pub(crate) asset_id: Option<String>,
    pub(crate) asset_amount: Option<u64>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LNInvoiceResponse {
    pub(crate) invoice: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MakerExecuteRequest {
    pub(crate) swapstring: String,
    pub(crate) payment_secret: String,
    pub(crate) taker_pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MakerInitRequest {
    pub(crate) qty_from: u64,
    pub(crate) qty_to: u64,
    pub(crate) from_asset: Option<String>,
    pub(crate) to_asset: Option<String>,
    pub(crate) timeout_sec: u32,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MakerInitResponse {
    pub(crate) payment_hash: String,
    pub(crate) payment_secret: String,
    pub(crate) swapstring: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct NetworkInfoResponse {
    pub(crate) network: BitcoinNetwork,
    pub(crate) height: u32,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct NodeInfoResponse {
    pub(crate) pubkey: String,
    pub(crate) num_channels: usize,
    pub(crate) num_usable_channels: usize,
    pub(crate) local_balance_msat: u64,
    pub(crate) num_peers: usize,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct OpenChannelRequest {
    pub(crate) peer_pubkey_and_addr: String,
    pub(crate) capacity_sat: u64,
    pub(crate) push_msat: u64,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) asset_id: Option<String>,
    pub(crate) public: bool,
    pub(crate) with_anchors: bool,
    pub(crate) fee_base_msat: Option<u32>,
    pub(crate) fee_proportional_millionths: Option<u32>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct OpenChannelResponse {
    pub(crate) temporary_channel_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Payment {
    pub(crate) amt_msat: Option<u64>,
    pub(crate) asset_amount: Option<u64>,
    pub(crate) asset_id: Option<String>,
    pub(crate) payment_hash: String,
    pub(crate) inbound: bool,
    pub(crate) status: HTLCStatus,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Peer {
    pub(crate) pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RestoreRequest {
    pub(crate) backup_path: String,
    pub(crate) password: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RgbAllocation {
    pub(crate) asset_id: Option<String>,
    pub(crate) amount: u64,
    pub(crate) settled: bool,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RgbInvoiceRequest {
    pub(crate) min_confirmations: u8,
    pub(crate) asset_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RgbInvoiceResponse {
    pub(crate) recipient_id: String,
    pub(crate) invoice: String,
    pub(crate) expiration_timestamp: Option<i64>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendAssetRequest {
    pub(crate) asset_id: String,
    pub(crate) amount: u64,
    pub(crate) blinded_utxo: String,
    pub(crate) donation: bool,
    pub(crate) min_confirmations: u8,
    pub(crate) transport_endpoints: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendAssetResponse {
    pub(crate) txid: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendBtcRequest {
    pub(crate) amount: u64,
    pub(crate) address: String,
    pub(crate) fee_rate: f32,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendBtcResponse {
    pub(crate) txid: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendOnionMessageRequest {
    pub(crate) node_ids: Vec<String>,
    pub(crate) tlv_type: u64,
    pub(crate) data: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendPaymentRequest {
    pub(crate) invoice: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendPaymentResponse {
    pub(crate) payment_hash: String,
    pub(crate) payment_secret: String,
    pub(crate) status: HTLCStatus,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SignMessageRequest {
    pub(crate) message: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SignMessageResponse {
    pub(crate) signed_message: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct TakerRequest {
    pub(crate) swapstring: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Trade {
    pub(crate) qty_from: u64,
    pub(crate) qty_to: u64,
    pub(crate) from_asset: Option<String>,
    pub(crate) to_asset: Option<String>,
    pub(crate) payment_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Transaction {
    pub(crate) transaction_type: TransactionType,
    pub(crate) txid: String,
    pub(crate) received: u64,
    pub(crate) sent: u64,
    pub(crate) fee: Option<u64>,
    pub(crate) confirmation_time: Option<BlockTime>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum TransactionType {
    RgbSend,
    Drain,
    CreateUtxos,
    User,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Transfer {
    pub(crate) idx: i32,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) status: TransferStatus,
    pub(crate) amount: u64,
    pub(crate) kind: TransferKind,
    pub(crate) txid: Option<String>,
    pub(crate) recipient_id: Option<String>,
    pub(crate) receive_utxo: Option<String>,
    pub(crate) change_utxo: Option<String>,
    pub(crate) expiration: Option<i64>,
    pub(crate) transport_endpoints: Vec<TransferTransportEndpoint>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum TransferKind {
    Issuance,
    ReceiveBlind,
    ReceiveWitness,
    Send,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum TransferStatus {
    WaitingCounterparty,
    WaitingConfirmations,
    Settled,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TransferTransportEndpoint {
    pub(crate) endpoint: String,
    pub(crate) transport_type: TransportType,
    pub(crate) used: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum TransportType {
    JsonRpc,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct UnlockRequest {
    pub(crate) password: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Unspent {
    pub(crate) utxo: Utxo,
    pub(crate) rgb_allocations: Vec<RgbAllocation>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Utxo {
    pub(crate) outpoint: String,
    pub(crate) btc_amount: u64,
    pub(crate) colorable: bool,
}

impl AppState {
    fn check_changing_state(&self) -> Result<(), APIError> {
        if *self.get_changing_state() {
            return Err(APIError::ChangingState);
        }
        Ok(())
    }

    async fn check_locked(
        &self,
    ) -> Result<TokioMutexGuard<Option<Arc<UnlockedAppState>>>, APIError> {
        let unlocked_app_state = self.get_unlocked_app_state().await;
        if unlocked_app_state.is_some() {
            Err(APIError::UnlockedNode)
        } else {
            self.check_changing_state()?;
            Ok(unlocked_app_state)
        }
    }

    async fn check_unlocked(
        &self,
    ) -> Result<TokioMutexGuard<Option<Arc<UnlockedAppState>>>, APIError> {
        let unlocked_app_state = self.get_unlocked_app_state().await;
        if unlocked_app_state.is_none() {
            Err(APIError::LockedNode)
        } else {
            self.check_changing_state()?;
            Ok(unlocked_app_state)
        }
    }

    fn update_changing_state(&self, updated: bool) {
        let mut changing_state = self.get_changing_state();
        *changing_state = updated;
    }

    fn update_ldk_background_services(&self, updated: Option<LdkBackgroundServices>) {
        let mut ldk_background_services = self.get_ldk_background_services();
        *ldk_background_services = updated;
    }

    async fn update_unlocked_app_state(&self, updated: Option<Arc<UnlockedAppState>>) {
        let mut unlocked_app_state = self.get_unlocked_app_state().await;
        *unlocked_app_state = updated;
    }

    async fn update_periodic_sweep(&self, updated: Option<tokio::task::JoinHandle<()>>) {
        let periodic_sweep = self.get_periodic_sweep();
        *periodic_sweep.await = updated;
    }
}

impl From<RgbLibError> for APIError {
    fn from(error: RgbLibError) -> Self {
        match error {
            RgbLibError::AllocationsAlreadyAvailable => APIError::AllocationsAlreadyAvailable,
            RgbLibError::AssetNotFound { .. } => APIError::UnknownContractId,
            RgbLibError::FailedIssuance { details } => APIError::FailedIssuingAsset(details),
            RgbLibError::InsufficientAllocationSlots => APIError::NoAvailableUtxos,
            RgbLibError::InsufficientBitcoins { needed, available } => {
                APIError::InsufficientFunds(needed - available)
            }
            RgbLibError::InvalidAssetID { asset_id } => APIError::InvalidAssetID(asset_id),
            RgbLibError::InvalidBlindedUTXO { details } => APIError::InvalidBlindedUTXO(details),
            RgbLibError::InvalidFeeRate { details } => APIError::InvalidFeeRate(details),
            RgbLibError::InvalidName { details } => APIError::InvalidName(details),
            RgbLibError::InvalidPrecision { details } => APIError::InvalidPrecision(details),
            RgbLibError::InvalidTicker { details } => APIError::InvalidTicker(details),
            RgbLibError::InvalidTransportEndpoints { details } => {
                APIError::InvalidTransportEndpoints(details)
            }
            RgbLibError::RecipientIDAlreadyUsed => APIError::RecipientIDAlreadyUsed,
            RgbLibError::OutputBelowDustLimit => APIError::OutputBelowDustLimit,
            _ => APIError::Unexpected,
        }
    }
}

pub(crate) async fn address(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AddressResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let address = unlocked_state.rgb_get_address()?;

    Ok(Json(AddressResponse { address }))
}

pub(crate) async fn asset_balance(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<AssetBalanceRequest>, APIError>,
) -> Result<Json<AssetBalanceResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let contract_id = ContractId::from_str(&payload.asset_id)
        .map_err(|_| APIError::InvalidAssetID(payload.asset_id))?;

    let balance = unlocked_state.rgb_get_asset_balance(contract_id)?;

    let ldk_data_dir_path = PathBuf::from(state.static_state.ldk_data_dir.clone());
    let mut offchain_outbound = 0;
    let mut offchain_inbound = 0;
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let info_file_path =
            get_rgb_channel_info_path(&chan_info.channel_id.to_hex(), &ldk_data_dir_path, false);
        if !info_file_path.exists() {
            continue;
        }
        let rgb_info = parse_rgb_channel_info(&info_file_path);
        if rgb_info.contract_id == contract_id {
            offchain_outbound += rgb_info.local_rgb_amount;
            offchain_inbound += rgb_info.remote_rgb_amount;
        }
    }

    Ok(Json(AssetBalanceResponse {
        settled: balance.settled,
        future: balance.future,
        spendable: balance.spendable,
        offchain_outbound,
        offchain_inbound,
    }))
}

pub(crate) async fn backup(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<BackupRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let _unlocked_state = state.check_locked().await?;

        let _mnemonic =
            check_password_validity(&payload.password, &state.static_state.storage_dir_path)?;

        do_backup(
            PathBuf::from(&state.static_state.storage_dir_path),
            &payload.backup_path,
            &payload.password,
        )?;

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn btc_balance(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BtcBalanceResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let btc_balance = unlocked_state.rgb_get_btc_balance()?;

    let vanilla = BtcBalance {
        settled: btc_balance.vanilla.settled,
        future: btc_balance.vanilla.future,
        spendable: btc_balance.vanilla.spendable,
    };

    let colored = BtcBalance {
        settled: btc_balance.colored.settled,
        future: btc_balance.colored.future,
        spendable: btc_balance.colored.spendable,
    };

    Ok(Json(BtcBalanceResponse { vanilla, colored }))
}

pub(crate) async fn change_password(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<ChangePasswordRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let _unlocked_state = state.check_locked().await?;

        check_password_strength(payload.new_password.clone())?;

        let mnemonic =
            check_password_validity(&payload.old_password, &state.static_state.storage_dir_path)?;

        encrypt_and_save_mnemonic(
            payload.new_password,
            mnemonic.to_string(),
            get_mnemonic_path(&state.static_state.storage_dir_path),
        )?;

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn close_channel(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<CloseChannelRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let channel_id_vec = hex_str_to_vec(&payload.channel_id);
        if channel_id_vec.is_none() || channel_id_vec.as_ref().unwrap().len() != 32 {
            return Err(APIError::InvalidChannelID);
        }
        let mut channel_id = [0; 32];
        channel_id.copy_from_slice(&channel_id_vec.unwrap());

        let peer_pubkey_vec = match hex_str_to_vec(&payload.peer_pubkey) {
            Some(peer_pubkey_vec) => peer_pubkey_vec,
            None => return Err(APIError::InvalidPubkey),
        };
        let peer_pubkey = match PublicKey::from_slice(&peer_pubkey_vec) {
            Ok(peer_pubkey) => peer_pubkey,
            Err(_) => return Err(APIError::InvalidPubkey),
        };

        if payload.force {
            match unlocked_state
                .channel_manager
                .force_close_broadcasting_latest_txn(&ChannelId(channel_id), &peer_pubkey)
            {
                Ok(()) => tracing::info!("EVENT: initiating channel force-close"),
                Err(e) => return Err(APIError::FailedClosingChannel(format!("{:?}", e))),
            }
        } else {
            match unlocked_state
                .channel_manager
                .close_channel(&ChannelId(channel_id), &peer_pubkey)
            {
                Ok(()) => tracing::info!("EVENT: initiating channel close"),
                Err(e) => return Err(APIError::FailedClosingChannel(format!("{:?}", e))),
            }
        }

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn connect_peer(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<ConnectPeerRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let (peer_pubkey, peer_addr) = parse_peer_info(payload.peer_pubkey_and_addr.to_string())?;

        connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone())
            .await?;

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn create_utxos(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<CreateUtxosRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        unlocked_state.rgb_create_utxos(
            payload.up_to,
            payload.num.unwrap_or(UTXO_NUM),
            UTXO_SIZE_SAT,
            FEE_RATE,
        )?;
        tracing::debug!("UTXO creation complete");

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn decode_ln_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<DecodeLNInvoiceRequest>, APIError>,
) -> Result<Json<DecodeLNInvoiceResponse>, APIError> {
    let _unlocked_app_state = state.get_unlocked_app_state();

    let invoice = match Bolt11Invoice::from_str(&payload.invoice) {
        Err(e) => return Err(APIError::InvalidInvoice(e.to_string())),
        Ok(v) => v,
    };

    Ok(Json(DecodeLNInvoiceResponse {
        amt_msat: invoice.amount_milli_satoshis(),
        expiry_sec: invoice.expiry_time().as_secs(),
        timestamp: invoice
            .timestamp()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        asset_id: invoice.rgb_contract_id().map(|c| c.to_string()),
        asset_amount: invoice.rgb_amount(),
        payment_hash: hex_str(&invoice.payment_hash().into_inner()),
        payment_secret: hex_str(&invoice.payment_secret().0),
        payee_pubkey: invoice.payee_pub_key().map(|p| p.to_string()),
        network: invoice.network().into(),
    }))
}

pub(crate) async fn decode_rgb_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<DecodeRGBInvoiceRequest>, APIError>,
) -> Result<Json<DecodeRGBInvoiceResponse>, APIError> {
    let _unlocked_app_state = state.get_unlocked_app_state();

    let invoice_data = match RgbLibInvoice::new(payload.invoice) {
        Err(e) => return Err(APIError::InvalidInvoice(e.to_string())),
        Ok(v) => v.invoice_data(),
    };

    Ok(Json(DecodeRGBInvoiceResponse {
        recipient_id: invoice_data.recipient_id,
        asset_iface: invoice_data.asset_iface.map(|i| match i {
            rgb_lib::wallet::AssetIface::RGB20 => AssetIface::RGB20,
            rgb_lib::wallet::AssetIface::RGB21 => AssetIface::RGB21,
            rgb_lib::wallet::AssetIface::RGB25 => AssetIface::RGB25,
        }),
        asset_id: invoice_data.asset_id,
        amount: invoice_data.amount,
        network: invoice_data.network.map(|n| n.into()),
        expiration_timestamp: invoice_data.expiration_timestamp,
        transport_endpoints: invoice_data.transport_endpoints,
    }))
}

pub(crate) async fn disconnect_peer(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<DisconnectPeerRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let peer_pubkey = match PublicKey::from_str(&payload.peer_pubkey) {
            Ok(pubkey) => pubkey,
            Err(_e) => return Err(APIError::InvalidPubkey),
        };

        //check for open channels with peer
        for channel in unlocked_state.channel_manager.list_channels() {
            if channel.counterparty.node_id == peer_pubkey {
                return Err(APIError::FailedPeerDisconnection(s!(
                    "node has an active channel with this peer, close any channels first"
                )));
            }
        }

        //check the pubkey matches a valid connected peer
        let peers = unlocked_state.peer_manager.get_peer_node_ids();
        if !peers.iter().any(|(pk, _)| &peer_pubkey == pk) {
            return Err(APIError::FailedPeerDisconnection(format!(
                "Could not find peer {}",
                peer_pubkey
            )));
        }

        unlocked_state
            .peer_manager
            .disconnect_by_node_id(peer_pubkey);

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn init(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<InitRequest>, APIError>,
) -> Result<Json<InitResponse>, APIError> {
    no_cancel(async move {
        let _unlocked_state = state.check_locked().await?;

        check_password_strength(payload.password.clone())?;

        let mnemonic_path = get_mnemonic_path(&state.static_state.storage_dir_path);
        check_already_initialized(&mnemonic_path)?;

        let keys = generate_keys(get_bitcoin_network(&state.static_state.network));

        let mnemonic = keys.mnemonic;

        encrypt_and_save_mnemonic(payload.password, mnemonic.clone(), mnemonic_path)?;

        Ok(Json(InitResponse { mnemonic }))
    })
    .await
}

pub(crate) async fn invoice_status(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<InvoiceStatusRequest>, APIError>,
) -> Result<Json<InvoiceStatusResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let invoice = match Bolt11Invoice::from_str(&payload.invoice) {
        Err(e) => return Err(APIError::InvalidInvoice(e.to_string())),
        Ok(v) => v,
    };

    let payment_hash = PaymentHash(invoice.payment_hash().into_inner());
    let status = match unlocked_state.inbound_payments().get(&payment_hash) {
        Some(v) => match v.status {
            HTLCStatus::Pending if invoice.is_expired() => InvoiceStatus::Expired,
            HTLCStatus::Pending => InvoiceStatus::Pending,
            HTLCStatus::Succeeded => InvoiceStatus::Succeeded,
            HTLCStatus::Failed => InvoiceStatus::Failed,
        },
        None => return Err(APIError::UnknownLNInvoice),
    };

    Ok(Json(InvoiceStatusResponse { status }))
}

pub(crate) async fn issue_asset(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<IssueAssetRequest>, APIError>,
) -> Result<Json<IssueAssetResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let asset = unlocked_state.rgb_issue_asset_nia(
            payload.ticker,
            payload.name,
            payload.precision,
            payload.amounts,
        )?;

        Ok(Json(IssueAssetResponse {
            asset_id: asset.asset_id,
        }))
    })
    .await
}

pub(crate) async fn keysend(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<KeysendRequest>, APIError>,
) -> Result<Json<KeysendResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let dest_pubkey = match hex_str_to_compressed_pubkey(&payload.dest_pubkey) {
            Some(pk) => pk,
            None => return Err(APIError::InvalidPubkey),
        };

        let amt_msat = payload.amt_msat;
        if amt_msat < HTLC_MIN_MSAT {
            return Err(APIError::InvalidAmount(format!(
                "amt_msat cannot be less than {HTLC_MIN_MSAT}"
            )));
        }

        let payment_preimage =
            PaymentPreimage(unlocked_state.keys_manager.get_secure_random_bytes());
        let payment_hash_inner = Sha256::hash(&payment_preimage.0[..]).into_inner();
        let payment_id = PaymentId(payment_hash_inner);
        let payment_hash = PaymentHash(payment_hash_inner);

        match (payload.asset_id, payload.asset_amount) {
            (Some(rgb_contract_id), Some(rgb_amount)) => {
                let contract_id = ContractId::from_str(&rgb_contract_id)
                    .map_err(|_| APIError::InvalidAssetID(rgb_contract_id))?;

                write_rgb_payment_info_file(
                    &PathBuf::from(&state.static_state.ldk_data_dir),
                    &payment_hash,
                    contract_id,
                    rgb_amount,
                    true,
                );
            }
            (None, None) => {}
            _ => {
                return Err(APIError::IncompleteRGBInfo);
            }
        }

        let route_params = RouteParameters::from_payment_params_and_value(
            PaymentParameters::for_keysend(dest_pubkey, 40, false),
            amt_msat,
        );
        unlocked_state.add_outbound_payment(
            payment_id,
            PaymentInfo {
                preimage: None,
                secret: None,
                status: HTLCStatus::Pending,
                amt_msat: Some(amt_msat),
            },
        );
        let status = match unlocked_state
            .channel_manager
            .send_spontaneous_payment_with_retry(
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
                HTLCStatus::Pending
            }
            Err(e) => {
                tracing::error!("ERROR: failed to send payment: {:?}", e);
                unlocked_state.update_outbound_payment_status(payment_id, HTLCStatus::Failed);
                HTLCStatus::Failed
            }
        };

        Ok(Json(KeysendResponse {
            payment_hash: hex_str(&payment_hash.0),
            payment_preimage: hex_str(&payment_preimage.0),
            status,
        }))
    })
    .await
}

pub(crate) async fn list_assets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListAssetsResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let rgb_assets = unlocked_state.rgb_list_assets()?;

    let mut assets = vec![];
    for asset in rgb_assets.nia.unwrap() {
        assets.push(Asset {
            asset_id: asset.asset_id,
            ticker: asset.ticker,
            name: asset.name,
            precision: asset.precision,
            issued_supply: asset.issued_supply,
            timestamp: asset.timestamp,
        })
    }

    Ok(Json(ListAssetsResponse { assets }))
}

pub(crate) async fn list_channels(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListChannelsResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let mut channels = vec![];
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let mut channel = Channel {
            channel_id: chan_info.channel_id.to_hex(),
            peer_pubkey: hex_str(&chan_info.counterparty.node_id.serialize()),
            ready: chan_info.is_channel_ready,
            capacity_sat: chan_info.channel_value_satoshis,
            local_balance_msat: chan_info.balance_msat,
            is_usable: chan_info.is_usable,
            public: chan_info.is_public,
            ..Default::default()
        };

        if let Some(funding_txo) = chan_info.funding_txo {
            channel.funding_txid = Some(funding_txo.txid.to_string());
        }

        if let Some(node_info) = unlocked_state
            .network_graph
            .read_only()
            .nodes()
            .get(&NodeId::from_pubkey(&chan_info.counterparty.node_id))
        {
            if let Some(announcement) = &node_info.announcement_info {
                channel.peer_alias = Some(announcement.alias.to_string());
            }
        }

        if let Some(id) = chan_info.short_channel_id {
            channel.short_channel_id = Some(id);
        }

        if chan_info.is_usable {
            channel.outbound_balance_msat = Some(chan_info.outbound_capacity_msat);
            channel.inbound_balance_msat = Some(chan_info.inbound_capacity_msat);
        }

        let ldk_data_dir_path = PathBuf::from(state.static_state.ldk_data_dir.clone());
        let info_file_path =
            get_rgb_channel_info_path(&chan_info.channel_id.to_hex(), &ldk_data_dir_path, false);
        if info_file_path.exists() {
            let rgb_info = parse_rgb_channel_info(&info_file_path);
            channel.asset_id = Some(rgb_info.contract_id.to_string());
            channel.asset_local_amount = Some(rgb_info.local_rgb_amount);
            channel.asset_remote_amount = Some(rgb_info.remote_rgb_amount);
        };

        channels.push(channel);
    }

    Ok(Json(ListChannelsResponse { channels }))
}

pub(crate) async fn list_payments(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListPaymentsResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let inbound_payments = unlocked_state.inbound_payments();
    let outbound_payments = unlocked_state.outbound_payments();
    let mut payments = vec![];
    let ldk_data_dir_path = Path::new(&state.static_state.ldk_data_dir);

    for (payment_hash, payment_info) in &inbound_payments {
        let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir_path);
        let (asset_amount, asset_id) = if rgb_payment_info_path.exists() {
            let rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_path);
            (
                Some(rgb_payment_info.amount),
                Some(rgb_payment_info.contract_id.to_string()),
            )
        } else {
            (None, None)
        };
        payments.push(Payment {
            amt_msat: payment_info.amt_msat,
            asset_amount,
            asset_id,
            payment_hash: hex_str(&payment_hash.0),
            inbound: true,
            status: payment_info.status,
        })
    }

    for (payment_id, payment_info) in &outbound_payments {
        let payment_hash = PaymentHash(payment_id.0);
        let rgb_payment_info_path = get_rgb_payment_info_path(&payment_hash, ldk_data_dir_path);
        let (asset_amount, asset_id) = if rgb_payment_info_path.exists() {
            let rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_path);
            (
                Some(rgb_payment_info.amount),
                Some(rgb_payment_info.contract_id.to_string()),
            )
        } else {
            (None, None)
        };
        payments.push(Payment {
            amt_msat: payment_info.amt_msat,
            asset_amount,
            asset_id,
            payment_hash: hex_str(&payment_hash.0),
            inbound: false,
            status: payment_info.status,
        })
    }

    Ok(Json(ListPaymentsResponse { payments }))
}

pub(crate) async fn list_peers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListPeersResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let mut peers = vec![];
    for (pubkey, _) in unlocked_state.peer_manager.get_peer_node_ids() {
        peers.push(Peer {
            pubkey: pubkey.to_string(),
        })
    }

    Ok(Json(ListPeersResponse { peers }))
}

pub(crate) async fn list_trades(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListTradesResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let map_trade = |(payment_hash, swap): (&PaymentHash, &Swap)| Trade {
        payment_hash: payment_hash.to_string(),
        qty_from: swap.qty_from,
        qty_to: swap.qty_to,
        from_asset: swap.from_asset.map(|c| c.to_string()),
        to_asset: swap.to_asset.map(|c| c.to_string()),
    };

    let taker_trades = unlocked_state.taker_trades();
    let maker_trades = unlocked_state.maker_trades();

    Ok(Json(ListTradesResponse {
        taker: taker_trades.iter().map(map_trade).collect(),
        maker: maker_trades.iter().map(map_trade).collect(),
    }))
}

pub(crate) async fn list_transactions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListTransactionsResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let mut transactions = vec![];
    for tx in unlocked_state.rgb_list_transactions()? {
        transactions.push(Transaction {
            transaction_type: match tx.transaction_type {
                rgb_lib::TransactionType::RgbSend => TransactionType::RgbSend,
                rgb_lib::TransactionType::Drain => TransactionType::Drain,
                rgb_lib::TransactionType::CreateUtxos => TransactionType::CreateUtxos,
                rgb_lib::TransactionType::User => TransactionType::User,
            },
            txid: tx.txid,
            received: tx.received,
            sent: tx.sent,
            fee: tx.fee,
            confirmation_time: tx.confirmation_time.map(|ct| BlockTime {
                height: ct.height,
                timestamp: ct.timestamp,
            }),
        })
    }

    Ok(Json(ListTransactionsResponse { transactions }))
}

pub(crate) async fn list_transfers(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<ListTransfersRequest>, APIError>,
) -> Result<Json<ListTransfersResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let mut transfers = vec![];
    for transfer in unlocked_state.rgb_list_transfers(payload.asset_id)? {
        transfers.push(Transfer {
            idx: transfer.idx,
            created_at: transfer.created_at,
            updated_at: transfer.updated_at,
            status: match transfer.status {
                rgb_lib::TransferStatus::WaitingCounterparty => TransferStatus::WaitingCounterparty,
                rgb_lib::TransferStatus::WaitingConfirmations => {
                    TransferStatus::WaitingConfirmations
                }
                rgb_lib::TransferStatus::Settled => TransferStatus::Settled,
                rgb_lib::TransferStatus::Failed => TransferStatus::Failed,
            },
            amount: transfer.amount,
            kind: match transfer.kind {
                rgb_lib::TransferKind::Issuance => TransferKind::Issuance,
                rgb_lib::TransferKind::ReceiveBlind => TransferKind::ReceiveBlind,
                rgb_lib::TransferKind::ReceiveWitness => TransferKind::ReceiveWitness,
                rgb_lib::TransferKind::Send => TransferKind::Send,
            },
            txid: transfer.txid,
            recipient_id: transfer.recipient_id,
            receive_utxo: transfer.receive_utxo.map(|u| u.to_string()),
            change_utxo: transfer.change_utxo.map(|u| u.to_string()),
            expiration: transfer.expiration,
            transport_endpoints: transfer
                .transport_endpoints
                .iter()
                .map(|tte| TransferTransportEndpoint {
                    endpoint: tte.endpoint.clone(),
                    transport_type: match tte.transport_type {
                        rgb_lib::TransportType::JsonRpc => TransportType::JsonRpc,
                    },
                    used: tte.used,
                })
                .collect(),
        })
    }
    Ok(Json(ListTransfersResponse { transfers }))
}

pub(crate) async fn list_unspents(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListUnspentsResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let mut unspents = vec![];
    for unspent in unlocked_state.rgb_list_unspents()? {
        unspents.push(Unspent {
            utxo: Utxo {
                outpoint: unspent.utxo.outpoint.to_string(),
                btc_amount: unspent.utxo.btc_amount,
                colorable: unspent.utxo.colorable,
            },
            rgb_allocations: unspent
                .rgb_allocations
                .iter()
                .map(|a| RgbAllocation {
                    asset_id: a.asset_id.clone(),
                    amount: a.amount,
                    settled: a.settled,
                })
                .collect(),
        })
    }
    Ok(Json(ListUnspentsResponse { unspents }))
}

pub(crate) async fn ln_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<LNInvoiceRequest>, APIError>,
) -> Result<Json<LNInvoiceResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let contract_id = if let Some(asset_id) = payload.asset_id {
            Some(ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?)
        } else {
            None
        };

        if payload.amt_msat.is_some() && payload.amt_msat.unwrap() < INVOICE_MIN_MSAT {
            return Err(APIError::InvalidAmount(format!(
                "amt_msat cannot be less than {INVOICE_MIN_MSAT}"
            )));
        }

        let currency = match state.static_state.network {
            Network::Bitcoin => Currency::Bitcoin,
            Network::Testnet => Currency::BitcoinTestnet,
            Network::Regtest => Currency::Regtest,
            Network::Signet => Currency::Signet,
        };
        let invoice = match create_invoice_from_channelmanager(
            &unlocked_state.channel_manager,
            unlocked_state.keys_manager.clone(),
            state.static_state.logger.clone(),
            currency,
            payload.amt_msat,
            "ldk-tutorial-node".to_string(),
            payload.expiry_sec,
            None,
            contract_id,
            payload.asset_amount,
        ) {
            Ok(inv) => inv,
            Err(e) => return Err(APIError::FailedInvoiceCreation(e.to_string())),
        };

        let payment_hash = PaymentHash((*invoice.payment_hash()).into_inner());
        unlocked_state.add_inbound_payment(
            payment_hash,
            PaymentInfo {
                preimage: None,
                secret: Some(*invoice.payment_secret()),
                status: HTLCStatus::Pending,
                amt_msat: payload.amt_msat,
            },
        );

        Ok(Json(LNInvoiceResponse {
            invoice: invoice.to_string(),
        }))
    })
    .await
}

pub(crate) async fn lock(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    tracing::info!("Lock started");
    no_cancel(async move {
        match state.check_unlocked().await {
            Ok(unlocked_state) => {
                state.update_changing_state(true);
                drop(unlocked_state);
            }
            Err(e) => {
                state.update_changing_state(false);
                return Err(e);
            }
        }

        tracing::debug!("Stopping LDK...");
        stop_ldk(state.clone()).await;
        tracing::debug!("LDK stopped");

        tracing::debug!("Waiting for periodic sweep to stop...");
        let periodic_sweep = state.get_periodic_sweep().await;
        if let Some(ps) = periodic_sweep.as_ref() {
            while !ps.is_finished() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        tracing::debug!("Periodic sweep has stopped");

        state.update_unlocked_app_state(None).await;

        state.update_ldk_background_services(None);

        state.update_changing_state(false);

        tracing::info!("Lock completed");
        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn maker_execute(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<MakerExecuteRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();
        let ldk_data_dir_path = PathBuf::from(state.static_state.ldk_data_dir.clone());

        let swapstring = SwapString::from_str(&payload.swapstring)
            .map_err(|e| APIError::InvalidSwapString(payload.swapstring.clone(), e.to_string()))?;
        let payment_secret = hex_str_to_vec(&payload.payment_secret)
            .and_then(|data| data.try_into().ok())
            .map(PaymentSecret)
            .ok_or(APIError::InvalidPaymentSecret)?;
        let taker_pk =
            PublicKey::from_str(&payload.taker_pubkey).map_err(|_| APIError::InvalidPubkey)?;

        if get_current_timestamp() > swapstring.expiry {
            return Err(APIError::ExpiredSwapOffer);
        }

        let payment_preimage = unlocked_state
            .channel_manager
            .get_payment_preimage(swapstring.payment_hash, payment_secret)
            .map_err(|_| APIError::MissingSwapPaymentPreimage)?;

        let swap = swapstring.swap;

        let receive_hints = unlocked_state
            .channel_manager
            .list_usable_channels()
            .iter()
            .filter(|details| {
                match get_rgb_channel_info_optional(&details.channel_id, &ldk_data_dir_path) {
                    _ if swap.is_from_btc() => true,
                    Some((rgb_info, _)) if Some(rgb_info.contract_id) == swap.from_asset => true,
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
                }])
            })
            .collect();

        let first_leg = get_route(
            &unlocked_state.channel_manager,
            &unlocked_state.router,
            unlocked_state.channel_manager.get_our_node_id(),
            taker_pk,
            if swap.is_to_btc() {
                Some(swap.qty_to)
            } else {
                Some(HTLC_MIN_MSAT)
            },
            swap.to_asset,
            vec![],
        );
        let second_leg = get_route(
            &unlocked_state.channel_manager,
            &unlocked_state.router,
            taker_pk,
            unlocked_state.channel_manager.get_our_node_id(),
            if swap.is_from_btc() {
                Some(swap.qty_from)
            } else {
                Some(HTLC_MIN_MSAT)
            },
            swap.from_asset,
            receive_hints,
        );

        let (mut first_leg, mut second_leg) = match (first_leg, second_leg) {
            (Some(f), Some(s)) => (f, s),
            _ => {
                return Err(APIError::NoRoute);
            }
        };

        // Set swap flag
        second_leg.paths[0].hops[0].short_channel_id |= IS_SWAP_SCID;

        // Generally in the last hop the fee_amount is set to the payment amount, so we need to
        // override it depending on what type of swap we are doing
        first_leg.paths[0]
            .hops
            .last_mut()
            .expect("Path not to be empty")
            .fee_msat = if swap.is_to_btc() { HTLC_MIN_MSAT } else { 0 };

        let fullpaths = first_leg.paths[0]
            .hops
            .clone()
            .into_iter()
            .map(|mut hop| {
                if !swap.is_to_btc() {
                    hop.rgb_amount = Some(swap.qty_to);
                    hop.payment_amount = HTLC_MIN_MSAT;
                }
                hop
            })
            .chain(second_leg.paths[0].hops.clone().into_iter().map(|mut hop| {
                if !swap.is_from_btc() {
                    hop.rgb_amount = Some(swap.qty_from);
                    hop.payment_amount = HTLC_MIN_MSAT;
                }
                hop
            }))
            .collect::<Vec<_>>();

        let route = Route {
            paths: vec![LnPath {
                hops: fullpaths,
                blinded_tail: None,
            }],
            route_params: Some(RouteParameters {
                payment_params: PaymentParameters::for_keysend(
                    unlocked_state.channel_manager.get_our_node_id(),
                    DEFAULT_FINAL_CLTV_EXPIRY_DELTA,
                    false,
                ),
                // This value is not used anywhere, it's set by the router
                // when creating a route, but here we are creating it manually
                // by composing a pre-existing list of hops
                final_value_msat: 0,
                max_total_routing_fee_msat: None,
            }),
        };

        if !swap.is_to_btc() {
            write_rgb_payment_info_file(
                &ldk_data_dir_path,
                &swapstring.payment_hash,
                swap.to_asset.unwrap(),
                swap.qty_to,
                false,
            );
        }

        let payment_id = PaymentId(swapstring.payment_hash.0);
        let amt_msat = if swap.is_to_btc() {
            swap.qty_to
        } else {
            HTLC_MIN_MSAT
        };

        let payment_info = PaymentInfo {
            preimage: None,
            secret: None,
            status: HTLCStatus::Pending,
            amt_msat: Some(amt_msat),
        };

        unlocked_state.add_outbound_payment(payment_id, payment_info.clone());

        let (status, err) = match unlocked_state.channel_manager.send_spontaneous_payment(
            &route,
            Some(payment_preimage),
            RecipientOnionFields::spontaneous_empty(),
            PaymentId(swapstring.payment_hash.0),
        ) {
            Ok(_payment_hash) => {
                tracing::debug!("EVENT: initiated swap");
                (HTLCStatus::Pending, None)
            }
            Err(e) => {
                tracing::warn!("ERROR: failed to send payment: {:?}", e);
                (HTLCStatus::Failed, Some(e))
            }
        };

        unlocked_state.add_inbound_payment(swapstring.payment_hash, payment_info);
        unlocked_state.update_outbound_payment_status(payment_id, status);

        match err {
            None => Ok(Json(EmptyResponse {})),
            Some(e) => Err(APIError::FailedPayment(format!("{:?}", e))),
        }
    })
    .await
}

pub(crate) async fn maker_init(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<MakerInitRequest>, APIError>,
) -> Result<Json<MakerInitResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();
        let ldk_data_dir_path = PathBuf::from(state.static_state.ldk_data_dir.clone());

        let from_asset = match &payload.from_asset {
            None => None,
            Some(asset) => Some(
                ContractId::from_str(asset).map_err(|_| APIError::InvalidAssetID(asset.clone()))?,
            ),
        };

        let to_asset = match &payload.to_asset {
            None => None,
            Some(asset) => Some(
                ContractId::from_str(asset).map_err(|_| APIError::InvalidAssetID(asset.clone()))?,
            ),
        };

        let qty_from = payload.qty_from;
        let qty_to = payload.qty_to;

        let swap = Swap {
            from_asset,
            to_asset,
            qty_from,
            qty_to,
        };

        // Check that we have enough assets to send
        if let Some(to_asset) = to_asset {
            let max_balance = get_max_local_rgb_amount(
                to_asset,
                &ldk_data_dir_path,
                unlocked_state.channel_manager.list_channels().iter(),
            );
            if swap.qty_to > max_balance {
                return Err(APIError::InsufficientAssets(max_balance, swap.qty_to));
            }
        }

        let (payment_hash, payment_secret) = unlocked_state
            .channel_manager
            .create_inbound_payment(Some(546000), payload.timeout_sec, None)
            .unwrap();
        unlocked_state.add_maker_trade(payment_hash, swap);

        let expiry = get_current_timestamp() + payload.timeout_sec as u64;
        let swapstring = format!(
            "{}/{}/{}/{}/{}/{}",
            qty_from,
            from_asset.map(|c| c.to_string()).unwrap_or("btc".into()),
            qty_to,
            to_asset.map(|c| c.to_string()).unwrap_or("btc".into()),
            expiry,
            payment_hash,
        );

        let payment_secret = payment_secret.0.to_hex();
        let payment_hash = payment_hash.0.to_hex();
        Ok(Json(MakerInitResponse {
            payment_hash,
            payment_secret,
            swapstring,
        }))
    })
    .await
}

pub(crate) async fn network_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkInfoResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let best_block = unlocked_state.channel_manager.current_best_block();

    Ok(Json(NetworkInfoResponse {
        network: state.static_state.network.into(),
        height: best_block.height(),
    }))
}

pub(crate) async fn node_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NodeInfoResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let chans = unlocked_state.channel_manager.list_channels();

    Ok(Json(NodeInfoResponse {
        pubkey: unlocked_state.channel_manager.get_our_node_id().to_string(),
        num_channels: chans.len(),
        num_usable_channels: chans.iter().filter(|c| c.is_usable).count(),
        local_balance_msat: chans.iter().map(|c| c.balance_msat).sum::<u64>(),
        num_peers: unlocked_state.peer_manager.get_peer_node_ids().len(),
    }))
}

pub(crate) async fn open_channel(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<OpenChannelRequest>, APIError>,
) -> Result<Json<OpenChannelResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let (peer_pubkey, peer_addr) = parse_peer_info(payload.peer_pubkey_and_addr.to_string())?;

        let colored_info = match (payload.asset_id, payload.asset_amount) {
            (Some(_), Some(amt)) if amt < OPENCHANNEL_MIN_RGB_AMT => {
                return Err(APIError::InvalidAmount(format!(
                    "Channel RGB amount must be equal or higher than {OPENCHANNEL_MIN_RGB_AMT}"
                )));
            }
            (Some(asset), Some(amt)) => {
                let asset =
                    ContractId::from_str(&asset).map_err(|_| APIError::InvalidAssetID(asset))?;
                Some((asset, amt))
            }
            (None, None) => None,
            _ => {
                return Err(APIError::IncompleteRGBInfo);
            }
        };

        if payload.capacity_sat < OPENCHANNEL_MIN_SAT {
            return Err(APIError::InvalidAmount(format!(
                "Channel amount must be equal or higher than {OPENCHANNEL_MIN_SAT}"
            )));
        }
        if payload.capacity_sat > OPENCHANNEL_MAX_SAT {
            return Err(APIError::InvalidAmount(format!(
                "Channel amount must be equal or less than {OPENCHANNEL_MAX_SAT}"
            )));
        }

        if colored_info.is_some() && payload.push_msat < DUST_LIMIT_MSAT {
            return Err(APIError::InvalidAmount(format!(
                "Push amount must be equal or higher than the dust limit ({DUST_LIMIT_MSAT})"
            )));
        }

        if !payload.with_anchors {
            return Err(APIError::AnchorsRequired);
        }

        connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone())
            .await?;

        let mut channel_config = ChannelConfig::default();
        if let Some(fee_base_msat) = payload.fee_base_msat {
            channel_config.forwarding_fee_base_msat = fee_base_msat;
        }
        if let Some(fee_proportional_millionths) = payload.fee_proportional_millionths {
            channel_config.forwarding_fee_proportional_millionths = fee_proportional_millionths;
        }
        let config = UserConfig {
            channel_handshake_limits: ChannelHandshakeLimits {
                // lnd's max to_self_delay is 2016, so we want to be compatible.
                their_to_self_delay: 2016,
                ..Default::default()
            },
            channel_handshake_config: ChannelHandshakeConfig {
                announced_channel: payload.public,
                our_htlc_minimum_msat: HTLC_MIN_MSAT,
                minimum_depth: MIN_CHANNEL_CONFIRMATIONS as u32,
                negotiate_anchors_zero_fee_htlc_tx: payload.with_anchors,
                ..Default::default()
            },
            channel_config,
            ..Default::default()
        };

        let consignment_endpoint = if let Some((contract_id, asset_amount)) = &colored_info {
            let balance = unlocked_state.rgb_get_asset_balance(*contract_id)?;
            let spendable_rgb_amount = balance.spendable;

            if *asset_amount > spendable_rgb_amount {
                return Err(APIError::InsufficientAssets(
                    spendable_rgb_amount,
                    *asset_amount,
                ));
            }

            Some(RgbTransport::from_str(&state.static_state.proxy_endpoint).unwrap())
        } else {
            None
        };
        let temporary_channel_id = unlocked_state
            .channel_manager
            .create_channel(
                peer_pubkey,
                payload.capacity_sat,
                payload.push_msat,
                0,
                Some(config),
                consignment_endpoint,
            )
            .map_err(|e| APIError::FailedOpenChannel(format!("{:?}", e)))?;
        let temporary_channel_id = temporary_channel_id.to_hex();
        tracing::info!("EVENT: initiated channel with peer {}", peer_pubkey);

        if let Some((contract_id, asset_amount)) = &colored_info {
            let peer_data_path = format!(
                "{}/channel_peer_data",
                state.static_state.ldk_data_dir.clone()
            );
            let _ = disk::persist_channel_peer(
                Path::new(&peer_data_path),
                &payload.peer_pubkey_and_addr,
            );

            let rgb_info = RgbInfo {
                contract_id: *contract_id,
                local_rgb_amount: *asset_amount,
                remote_rgb_amount: 0,
            };
            let ldk_data_dir_path = PathBuf::from(&state.static_state.ldk_data_dir);
            write_rgb_channel_info(
                &get_rgb_channel_info_path(&temporary_channel_id, &ldk_data_dir_path, true),
                &rgb_info,
            );
            write_rgb_channel_info(
                &get_rgb_channel_info_path(&temporary_channel_id, &ldk_data_dir_path, false),
                &rgb_info,
            );
        }

        Ok(Json(OpenChannelResponse {
            temporary_channel_id,
        }))
    })
    .await
}

pub(crate) async fn refresh_transfers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        tokio::task::spawn_blocking(move || unlocked_state.rgb_refresh())
            .await
            .unwrap()?;

        tracing::info!("Refresh complete");
        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn restore(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<RestoreRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let _unlocked_state = state.check_locked().await?;

        let mnemonic_path = get_mnemonic_path(&state.static_state.storage_dir_path);
        check_already_initialized(&mnemonic_path)?;

        restore_backup(
            &payload.backup_path,
            &payload.password,
            &state.static_state.storage_dir_path,
        )?;

        let _mnemonic =
            check_password_validity(&payload.password, &state.static_state.storage_dir_path)?;

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn rgb_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<RgbInvoiceRequest>, APIError>,
) -> Result<Json<RgbInvoiceResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let receive_data = unlocked_state.rgb_blind_receive(
            payload.asset_id,
            vec![state.static_state.proxy_endpoint.clone()],
            payload.min_confirmations,
        )?;

        Ok(Json(RgbInvoiceResponse {
            recipient_id: receive_data.recipient_id,
            invoice: receive_data.invoice,
            expiration_timestamp: receive_data.expiration_timestamp,
        }))
    })
    .await
}

pub(crate) async fn send_asset(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendAssetRequest>, APIError>,
) -> Result<Json<SendAssetResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let secret_seal = SecretSeal::from_str(&payload.blinded_utxo)
            .map_err(|e| APIError::InvalidBlindedUTXO(e.to_string()))?;
        let recipient_map = map! {
            payload.asset_id => vec![Recipient {
                recipient_data: RecipientData::BlindedUTXO(secret_seal),
                amount: payload.amount,
                transport_endpoints: payload.transport_endpoints,
            }]
        };

        let txid = tokio::task::spawn_blocking(move || {
            unlocked_state.rgb_send(
                recipient_map,
                payload.donation,
                FEE_RATE,
                payload.min_confirmations,
            )
        })
        .await
        .unwrap()?;

        Ok(Json(SendAssetResponse { txid }))
    })
    .await
}

pub(crate) async fn send_btc(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendBtcRequest>, APIError>,
) -> Result<Json<SendBtcResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let txid =
            unlocked_state.rgb_send_btc(payload.address, payload.amount, payload.fee_rate)?;

        Ok(Json(SendBtcResponse { txid }))
    })
    .await
}

pub(crate) async fn send_onion_message(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendOnionMessageRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        if payload.node_ids.is_empty() {
            return Err(APIError::InvalidNodeIds(s!(
                "sendonionmessage requires at least one node id for the path"
            )));
        }

        let mut intermediate_nodes = Vec::new();
        for pk_str in payload.node_ids {
            let node_pubkey_vec = match hex_str_to_vec(&pk_str) {
                Some(peer_pubkey_vec) => peer_pubkey_vec,
                None => {
                    return Err(APIError::InvalidNodeIds(format!(
                        "Couldn't parse peer_pubkey '{}'",
                        pk_str
                    )))
                }
            };
            let node_pubkey = match PublicKey::from_slice(&node_pubkey_vec) {
                Ok(peer_pubkey) => peer_pubkey,
                Err(_) => {
                    return Err(APIError::InvalidNodeIds(format!(
                        "Couldn't parse peer_pubkey '{}'",
                        pk_str
                    )))
                }
            };
            intermediate_nodes.push(node_pubkey);
        }

        if payload.tlv_type < 64 {
            return Err(APIError::InvalidTlvType(s!(
                "need an integral message type above 64"
            )));
        }

        let data = hex_str_to_vec(&payload.data)
            .ok_or(APIError::InvalidOnionData(s!("need a hex data string")))?;

        let destination = Destination::Node(intermediate_nodes.pop().unwrap());
        let message_path = OnionMessagePath {
            intermediate_nodes,
            destination,
        };

        unlocked_state
            .onion_messenger
            .send_onion_message(
                message_path,
                UserOnionMessageContents {
                    tlv_type: payload.tlv_type,
                    data,
                },
                None,
            )
            .map_err(|e| APIError::FailedSendingOnionMessage(format!("{:?}", e)))?;

        tracing::info!("SUCCESS: forwarded onion message to first hop");

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn send_payment(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendPaymentRequest>, APIError>,
) -> Result<Json<SendPaymentResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();

        let invoice = match Bolt11Invoice::from_str(&payload.invoice) {
            Err(e) => return Err(APIError::InvalidInvoice(e.to_string())),
            Ok(v) => v,
        };

        if let Some(amt_msat) = invoice.amount_milli_satoshis() {
            if amt_msat < INVOICE_MIN_MSAT {
                return Err(APIError::InvalidAmount(s!(
                    "msat amount in invoice cannot be less than {INVOICE_MIN_MSAT}"
                )));
            }
        } else {
            return Err(APIError::InvalidAmount(s!(
                "msat amount missing in invoice"
            )));
        }

        let payment_hash = PaymentHash((*invoice.payment_hash()).into_inner());
        match (invoice.rgb_contract_id(), invoice.rgb_amount()) {
            (Some(rgb_contract_id), Some(rgb_amount)) => write_rgb_payment_info_file(
                &PathBuf::from(&state.static_state.ldk_data_dir.clone()),
                &payment_hash,
                rgb_contract_id,
                rgb_amount,
                true,
            ),
            (None, None) => {}
            (Some(_), None) => {
                return Err(APIError::InvalidInvoice(s!(
                    "invoice has an RGB contract ID but not an RGB amount"
                )))
            }
            (None, Some(_)) => {
                return Err(APIError::InvalidInvoice(s!(
                    "invoice has an RGB amount but not an RGB contract ID"
                )))
            }
        }

        let payment_id = PaymentId((*invoice.payment_hash()).into_inner());
        let payment_secret = *invoice.payment_secret();
        unlocked_state.add_outbound_payment(
            payment_id,
            PaymentInfo {
                preimage: None,
                secret: Some(payment_secret),
                status: HTLCStatus::Pending,
                amt_msat: invoice.amount_milli_satoshis(),
            },
        );

        let status = match pay_invoice(
            &invoice,
            Retry::Timeout(Duration::from_secs(10)),
            &*unlocked_state.channel_manager,
        ) {
            Ok(_payment_id) => {
                let payee_pubkey = invoice.recover_payee_pub_key();
                let amt_msat = invoice.amount_milli_satoshis().unwrap();
                tracing::info!(
                    "EVENT: initiated sending {} msats to {}",
                    amt_msat,
                    payee_pubkey
                );
                HTLCStatus::Pending
            }
            Err(e) => {
                tracing::error!("ERROR: failed to send payment: {:?}", e);
                unlocked_state.update_outbound_payment_status(payment_id, HTLCStatus::Failed);
                HTLCStatus::Failed
            }
        };

        Ok(Json(SendPaymentResponse {
            payment_hash: hex_str(&payment_hash.0),
            payment_secret: hex_str(&payment_secret.0),
            status,
        }))
    })
    .await
}

pub(crate) async fn shutdown(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let _unlocked_app_state = state.get_unlocked_app_state();
        state.check_changing_state()?;

        state.cancel_token.cancel();
        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn sign_message(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SignMessageRequest>, APIError>,
) -> Result<Json<SignMessageResponse>, APIError> {
    let unlocked_state = state.check_unlocked().await?.clone().unwrap();

    let message = payload.message.trim();
    let signed_message = lightning::util::message_signing::sign(
        &message.as_bytes()[message.len()..],
        &unlocked_state.keys_manager.get_node_secret_key(),
    )
    .map_err(|e| APIError::FailedMessageSigning(e.to_string()))?;

    Ok(Json(SignMessageResponse { signed_message }))
}

pub(crate) async fn taker(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<TakerRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    no_cancel(async move {
        let unlocked_state = state.check_unlocked().await?.clone().unwrap();
        let ldk_data_dir_path = PathBuf::from(state.static_state.ldk_data_dir.clone());
        let swapstring = SwapString::from_str(&payload.swapstring)
            .map_err(|e| APIError::InvalidSwapString(payload.swapstring.clone(), e.to_string()))?;

        if get_current_timestamp() > swapstring.expiry {
            return Err(APIError::ExpiredSwapOffer);
        }

        // We are selling assets, check if we have enough
        if let Some(from_asset) = swapstring.swap.from_asset {
            let max_balance = get_max_local_rgb_amount(
                from_asset,
                &ldk_data_dir_path,
                unlocked_state.channel_manager.list_channels().iter(),
            );
            if swapstring.swap.qty_from > max_balance {
                return Err(APIError::InsufficientAssets(
                    max_balance,
                    swapstring.swap.qty_from,
                ));
            }
        }

        unlocked_state.add_taker_trade(swapstring.payment_hash, swapstring.swap);

        Ok(Json(EmptyResponse {}))
    })
    .await
}

pub(crate) async fn unlock(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<UnlockRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    tracing::info!("Unlock started");
    no_cancel(async move {
        match state.check_locked().await {
            Ok(unlocked_state) => {
                state.update_changing_state(true);
                drop(unlocked_state);
            }
            Err(e) => {
                return Err(e);
            }
        }

        let mnemonic = match check_password_validity(
            &payload.password,
            &state.static_state.storage_dir_path,
        ) {
            Ok(mnemonic) => mnemonic,
            Err(e) => {
                state.update_changing_state(false);
                return Err(e);
            }
        };

        tracing::debug!("Starting LDK...");
        let (new_ldk_background_services, new_unlocked_app_state, new_periodic_sweep) =
            match start_ldk(state.clone(), mnemonic).await {
                Ok((nlbs, nuap, ps)) => (nlbs, nuap, ps),
                Err(e) => {
                    state.update_changing_state(false);
                    return Err(e);
                }
            };
        tracing::debug!("LDK started");

        state
            .update_unlocked_app_state(Some(new_unlocked_app_state))
            .await;

        state.update_ldk_background_services(Some(new_ldk_background_services));

        state.update_changing_state(false);

        state.update_periodic_sweep(Some(new_periodic_sweep)).await;

        tracing::info!("Unlock completed");
        Ok(Json(EmptyResponse {}))
    })
    .await
}
