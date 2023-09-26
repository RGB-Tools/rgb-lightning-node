use amplify::{map, s};
use axum::{extract::State, Json};
use axum_extra::extract::WithRejection;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lightning::chain::keysinterface::EntropySource;
use lightning::onion_message::{Destination, OnionMessageContents};
use lightning::rgb_utils::{get_rgb_payment_info_path, parse_rgb_payment_info};
use lightning::{
    ln::{
        channelmanager::{PaymentId, RecipientOnionFields, Retry},
        PaymentHash, PaymentPreimage,
    },
    rgb_utils::{
        get_rgb_channel_info, write_rgb_channel_info, write_rgb_payment_info_file, RgbInfo,
    },
    routing::{
        gossip::NodeId,
        router::{PaymentParameters, RouteParameters},
    },
    util::config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig},
};
use lightning_invoice::payment::pay_invoice;
use lightning_invoice::Invoice;
use lightning_invoice::{utils::create_invoice_from_channelmanager, Currency};
use rgb_lib::generate_keys;
use rgb_lib::wallet::{Recipient, RecipientData};
use rgbstd::contract::{ContractId, SecretSeal};
use rgbwallet::RgbTransport;
use serde::{Deserialize, Serialize};
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::backup::{do_backup, restore_backup};
use crate::ldk::{start_ldk, stop_ldk, MIN_CHANNEL_CONFIRMATIONS};
use crate::rgb::match_rgb_lib_error;
use crate::utils::{
    check_already_initialized, check_locked, check_password_strength, check_password_validity,
    check_unlocked, encrypt_and_save_mnemonic, get_mnemonic_path, hex_str,
    hex_str_to_compressed_pubkey, hex_str_to_vec, UserOnionMessageContents,
};
use crate::{
    disk,
    error::APIError,
    ldk::{PaymentInfo, FEE_RATE, UTXO_SIZE_SAT},
    utils::{connect_peer_if_necessary, parse_peer_info, AppState},
};

const UTXO_NUM: u8 = 4;

const OPENCHANNEL_MIN_SAT: u64 = 5506;
const OPENCHANNEL_MAX_SAT: u64 = 16777215;
const OPENCHANNEL_MIN_RGB_AMT: u64 = 1;

const DUST_LIMIT_MSAT: u64 = 546000;

const HTLC_MIN_MSAT: u64 = 3000000;

const INVOICE_MIN_MSAT: u64 = HTLC_MIN_MSAT;

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

#[derive(Deserialize, Serialize)]
pub(crate) struct BackupRequest {
    pub(crate) backup_path: String,
    pub(crate) password: String,
}

#[derive(Deserialize, Serialize)]
pub enum BitcoinNetwork {
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
pub(crate) struct DisconnectPeerRequest {
    pub(crate) peer_pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct EmptyResponse {}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(crate) enum HTLCStatus {
    Pending,
    Succeeded,
    Failed,
}

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
    pub(crate) asset_id: String,
    pub(crate) asset_amount: u64,
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
    pub(crate) asset_amount: u64,
    pub(crate) asset_id: String,
    pub(crate) public: bool,
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
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RgbInvoiceResponse {
    pub(crate) blinded_utxo: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendAssetRequest {
    pub(crate) asset_id: String,
    pub(crate) amount: u64,
    pub(crate) blinded_utxo: String,
    pub(crate) donation: bool,
    pub(crate) min_confirmations: u8,
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

pub(crate) async fn address(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AddressResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let address = unlocked_state.get_rgb_wallet().get_address();

    Ok(Json(AddressResponse { address }))
}

pub(crate) async fn asset_balance(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<AssetBalanceRequest>, APIError>,
) -> Result<Json<AssetBalanceResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let contract_id = ContractId::from_str(&payload.asset_id)
        .map_err(|_| APIError::InvalidAssetID(payload.asset_id))?;

    let balance = unlocked_state
        .get_rgb_wallet()
        .get_asset_balance(contract_id.to_string())
        .map_err(|_| APIError::Unexpected)?;

    let ldk_data_dir_path = PathBuf::from(state.static_state.ldk_data_dir.clone());
    let mut offchain_outbound = 0;
    let mut offchain_inbound = 0;
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let info_file_path = ldk_data_dir_path.join(hex::encode(chan_info.channel_id));
        if !info_file_path.exists() {
            continue;
        }
        let (rgb_info, _) = get_rgb_channel_info(&chan_info.channel_id, &ldk_data_dir_path);
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
    let _unlocked_state = check_locked(&state)?;

    let _mnemonic =
        check_password_validity(&payload.password, &state.static_state.storage_dir_path)?;

    do_backup(
        PathBuf::from(&state.static_state.storage_dir_path),
        &payload.backup_path,
        &payload.password,
    )?;

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn btc_balance(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BtcBalanceResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let btc_balance = unlocked_state
        .get_rgb_wallet()
        .get_btc_balance(unlocked_state.rgb_online.clone())
        .map_err(|_| APIError::Unexpected)?;

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
    let _unlocked_state = check_locked(&state)?;

    check_password_strength(payload.new_password.clone())?;

    let mnemonic =
        check_password_validity(&payload.old_password, &state.static_state.storage_dir_path)?;

    encrypt_and_save_mnemonic(
        payload.new_password,
        mnemonic.to_string(),
        get_mnemonic_path(&state.static_state.storage_dir_path),
    )?;

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn close_channel(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<CloseChannelRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

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
            .force_close_broadcasting_latest_txn(&channel_id, &peer_pubkey)
        {
            Ok(()) => tracing::info!("EVENT: initiating channel force-close"),
            Err(e) => return Err(APIError::FailedClosingChannel(format!("{:?}", e))),
        }
    } else {
        match unlocked_state
            .channel_manager
            .close_channel(&channel_id, &peer_pubkey)
        {
            Ok(()) => tracing::info!("EVENT: initiating channel close"),
            Err(e) => return Err(APIError::FailedClosingChannel(format!("{:?}", e))),
        }
    }

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn connect_peer(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<ConnectPeerRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let (peer_pubkey, peer_addr) = parse_peer_info(payload.peer_pubkey_and_addr.to_string())?;

    connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone()).await?;

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn create_utxos(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<CreateUtxosRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    unlocked_state
        .get_rgb_wallet()
        .create_utxos(
            unlocked_state.rgb_online.clone(),
            payload.up_to,
            Some(UTXO_NUM),
            Some(UTXO_SIZE_SAT),
            FEE_RATE,
        )
        .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))?;
    tracing::debug!("UTXO creation complete");

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn decode_ln_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<DecodeLNInvoiceRequest>, APIError>,
) -> Result<Json<DecodeLNInvoiceResponse>, APIError> {
    let _unlocked_app_state = state.get_unlocked_app_state();

    let invoice = match Invoice::from_str(&payload.invoice) {
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

pub(crate) async fn lock(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    match check_unlocked(&state) {
        Ok(unlocked_state) => {
            *state.get_changing_state() = true;
            drop(unlocked_state);
        }
        Err(e) => {
            *state.get_changing_state() = false;
            return Err(e);
        }
    }

    stop_ldk(state.clone()).await;

    let mut unlocked_app_state = state.get_unlocked_app_state();
    *unlocked_app_state = None;

    let mut ldk_background_services = state.get_ldk_background_services();
    *ldk_background_services = None;

    *state.get_changing_state() = false;

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn disconnect_peer(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<DisconnectPeerRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let peer_pubkey = match bitcoin::secp256k1::PublicKey::from_str(&payload.peer_pubkey) {
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
}

pub(crate) async fn init(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<InitRequest>, APIError>,
) -> Result<Json<InitResponse>, APIError> {
    let _unlocked_state = check_locked(&state)?;

    check_password_strength(payload.password.clone())?;

    let mnemonic_path = get_mnemonic_path(&state.static_state.storage_dir_path);
    check_already_initialized(&mnemonic_path)?;

    let keys = generate_keys(state.static_state.network.into());

    let mnemonic = keys.mnemonic;

    encrypt_and_save_mnemonic(payload.password, mnemonic.clone(), mnemonic_path)?;

    Ok(Json(InitResponse { mnemonic }))
}

pub(crate) async fn invoice_status(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<InvoiceStatusRequest>, APIError>,
) -> Result<Json<InvoiceStatusResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let invoice = match Invoice::from_str(&payload.invoice) {
        Err(e) => return Err(APIError::InvalidInvoice(e.to_string())),
        Ok(v) => v,
    };

    let inbound = unlocked_state.get_inbound_payments();

    let payment_hash = PaymentHash(invoice.payment_hash().into_inner());
    let status = match inbound.get(&payment_hash) {
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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let asset = unlocked_state
        .get_rgb_wallet()
        .issue_asset_nia(
            unlocked_state.rgb_online.clone(),
            payload.ticker,
            payload.name,
            payload.precision,
            payload.amounts,
        )
        .map_err(|e| match_rgb_lib_error(&e, APIError::FailedIssuingAsset(e.to_string())))?;

    Ok(Json(IssueAssetResponse {
        asset_id: asset.asset_id,
    }))
}

pub(crate) async fn keysend(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<KeysendRequest>, APIError>,
) -> Result<Json<KeysendResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

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

    let contract_id = ContractId::from_str(&payload.asset_id)
        .map_err(|_| APIError::InvalidAssetID(payload.asset_id))?;

    let payment_preimage = PaymentPreimage(unlocked_state.keys_manager.get_secure_random_bytes());
    let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
    write_rgb_payment_info_file(
        &PathBuf::from(&state.static_state.ldk_data_dir),
        &payment_hash,
        contract_id,
        payload.asset_amount,
    );

    let route_params = RouteParameters {
        payment_params: PaymentParameters::for_keysend(dest_pubkey, 40),
        final_value_msat: amt_msat,
    };
    let status = match unlocked_state
        .channel_manager
        .send_spontaneous_payment_with_retry(
            Some(payment_preimage),
            RecipientOnionFields::spontaneous_empty(),
            PaymentId(payment_hash.0),
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
            HTLCStatus::Failed
        }
    };

    let mut payments = unlocked_state.get_outbound_payments();
    payments.insert(
        payment_hash,
        PaymentInfo {
            preimage: None,
            secret: None,
            status,
            amt_msat: Some(amt_msat),
        },
    );

    Ok(Json(KeysendResponse {
        payment_hash: hex_str(&payment_hash.0),
        payment_preimage: hex_str(&payment_preimage.0),
        status,
    }))
}

pub(crate) async fn list_assets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListAssetsResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let rgb_assets = unlocked_state
        .get_rgb_wallet()
        .list_assets(vec![])
        .map_err(|_| APIError::Unexpected)?;

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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let mut channels = vec![];
    for chan_info in unlocked_state.channel_manager.list_channels() {
        let mut channel = Channel {
            channel_id: hex_str(&chan_info.channel_id[..]),
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
        let info_file_path = ldk_data_dir_path.join(hex::encode(chan_info.channel_id));
        if info_file_path.exists() {
            let (rgb_info, _) = get_rgb_channel_info(&chan_info.channel_id, &ldk_data_dir_path);
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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let inbound = unlocked_state.get_inbound_payments();
    let outbound = unlocked_state.get_outbound_payments();
    let mut payments = vec![];
    let ldk_data_dir_path = Path::new(&state.static_state.ldk_data_dir);

    for (payment_hash, payment_info) in inbound.deref() {
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

    for (payment_hash, payment_info) in outbound.deref() {
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
            inbound: false,
            status: payment_info.status,
        })
    }

    Ok(Json(ListPaymentsResponse { payments }))
}

pub(crate) async fn list_peers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListPeersResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let mut peers = vec![];
    for (pubkey, _) in unlocked_state.peer_manager.get_peer_node_ids() {
        peers.push(Peer {
            pubkey: pubkey.to_string(),
        })
    }

    Ok(Json(ListPeersResponse { peers }))
}

pub(crate) async fn list_transactions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListTransactionsResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let mut transactions = vec![];
    for tx in unlocked_state
        .get_rgb_wallet()
        .list_transactions(Some(unlocked_state.rgb_online.clone()))
        .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))?
    {
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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let rgb_wallet = unlocked_state.get_rgb_wallet();
    let mut transfers = vec![];
    for transfer in rgb_wallet
        .list_transfers(payload.asset_id)
        .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))?
    {
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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let rgb_wallet = unlocked_state.get_rgb_wallet();
    let mut unspents = vec![];
    for unspent in rgb_wallet
        .list_unspents(Some(unlocked_state.rgb_online.clone()), false)
        .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))?
    {
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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

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

    let mut payments = unlocked_state.get_inbound_payments();
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
    payments.insert(
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
}

pub(crate) async fn network_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkInfoResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let best_block = unlocked_state.channel_manager.current_best_block();

    Ok(Json(NetworkInfoResponse {
        network: state.static_state.network.into(),
        height: best_block.height(),
    }))
}

pub(crate) async fn node_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NodeInfoResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

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
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let (peer_pubkey, peer_addr) = parse_peer_info(payload.peer_pubkey_and_addr.to_string())?;

    let contract_id = ContractId::from_str(&payload.asset_id)
        .map_err(|_| APIError::InvalidAssetID(payload.asset_id))?;

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

    if payload.push_msat < DUST_LIMIT_MSAT {
        return Err(APIError::InvalidAmount(format!(
            "Push amount must be equal or higher than the dust limit ({DUST_LIMIT_MSAT})"
        )));
    }

    if payload.asset_amount < OPENCHANNEL_MIN_RGB_AMT {
        return Err(APIError::InvalidAmount(format!(
            "Channel RGB amount must be equal or higher than {OPENCHANNEL_MIN_RGB_AMT}"
        )));
    }

    connect_peer_if_necessary(peer_pubkey, peer_addr, unlocked_state.peer_manager.clone()).await?;

    let balance = unlocked_state
        .get_rgb_wallet()
        .get_asset_balance(contract_id.to_string())
        .map_err(|_| APIError::Unexpected)?;

    let spendable_rgb_amount = balance.spendable;

    if payload.asset_amount > spendable_rgb_amount {
        return Err(APIError::InsufficientAssets(spendable_rgb_amount));
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
            ..Default::default()
        },
        ..Default::default()
    };

    let consignment_endpoint = RgbTransport::from_str(&state.static_state.proxy_endpoint).unwrap();
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
    tracing::info!("EVENT: initiated channel with peer {}", peer_pubkey);

    let peer_data_path = format!(
        "{}/channel_peer_data",
        state.static_state.ldk_data_dir.clone()
    );
    let _ = disk::persist_channel_peer(Path::new(&peer_data_path), &payload.peer_pubkey_and_addr);

    let temporary_channel_id = hex::encode(temporary_channel_id);
    let channel_rgb_info_path = format!(
        "{}/{}",
        state.static_state.ldk_data_dir.clone(),
        temporary_channel_id,
    );
    let rgb_info = RgbInfo {
        contract_id,
        local_rgb_amount: payload.asset_amount,
        remote_rgb_amount: 0,
    };
    write_rgb_channel_info(&PathBuf::from(&channel_rgb_info_path), &rgb_info);

    Ok(Json(OpenChannelResponse {
        temporary_channel_id,
    }))
}

pub(crate) async fn refresh_transfers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    tokio::task::spawn_blocking(move || {
        unlocked_state
            .get_rgb_wallet()
            .refresh(unlocked_state.rgb_online.clone(), None, vec![])
            .map_err(|_| APIError::Unexpected)
    })
    .await
    .unwrap()?;

    tracing::info!("Refresh complete");

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn restore(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<RestoreRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let _unlocked_state = check_locked(&state)?;

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
}

pub(crate) async fn rgb_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<RgbInvoiceRequest>, APIError>,
) -> Result<Json<RgbInvoiceResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let receive_data = unlocked_state
        .get_rgb_wallet()
        .blind_receive(
            None,
            None,
            None,
            vec![state.static_state.proxy_endpoint.clone()],
            payload.min_confirmations,
        )
        .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))?;
    let blinded_utxo = receive_data.recipient_id;

    Ok(Json(RgbInvoiceResponse { blinded_utxo }))
}

pub(crate) async fn send_asset(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendAssetRequest>, APIError>,
) -> Result<Json<SendAssetResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let secret_seal = SecretSeal::from_str(&payload.blinded_utxo)
        .map_err(|e| APIError::InvalidBlindedUTXO(e.to_string()))?;
    let recipient_map = map! {
        payload.asset_id => vec![Recipient {
            recipient_data: RecipientData::BlindedUTXO(secret_seal),
            amount: payload.amount,
            transport_endpoints: vec![state.static_state.proxy_endpoint.clone()]
        }]
    };

    let txid = tokio::task::spawn_blocking(move || {
        unlocked_state
            .get_rgb_wallet()
            .send(
                unlocked_state.rgb_online.clone(),
                recipient_map,
                payload.donation,
                FEE_RATE,
                payload.min_confirmations,
            )
            .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))
    })
    .await
    .unwrap()?;

    Ok(Json(SendAssetResponse { txid }))
}

pub(crate) async fn send_btc(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendBtcRequest>, APIError>,
) -> Result<Json<SendBtcResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let txid = unlocked_state
        .get_rgb_wallet()
        .send_btc(
            unlocked_state.rgb_online.clone(),
            payload.address,
            payload.amount,
            payload.fee_rate,
        )
        .map_err(|e| match_rgb_lib_error(&e, APIError::Unexpected))?;

    Ok(Json(SendBtcResponse { txid }))
}

pub(crate) async fn send_onion_message(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendOnionMessageRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    if payload.node_ids.is_empty() {
        return Err(APIError::InvalidNodeIds(s!(
            "sendonionmessage requires at least one node id for the path"
        )));
    }

    let mut node_pks = Vec::new();
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
        node_pks.push(node_pubkey);
    }

    if payload.tlv_type < 64 {
        return Err(APIError::InvalidTlvType(s!(
            "need an integral message type above 64"
        )));
    }

    let data = hex_str_to_vec(&payload.data)
        .ok_or(APIError::InvalidOnionData(s!("need a hex data string")))?;

    let destination_pk = node_pks.pop().unwrap();
    unlocked_state
        .onion_messenger
        .send_onion_message(
            &node_pks,
            Destination::Node(destination_pk),
            OnionMessageContents::Custom(UserOnionMessageContents {
                tlv_type: payload.tlv_type,
                data,
            }),
            None,
        )
        .map_err(|e| APIError::FailedSendingOnionMessage(format!("{:?}", e)))?;

    tracing::info!("SUCCESS: forwarded onion message to first hop");

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn send_payment(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendPaymentRequest>, APIError>,
) -> Result<Json<SendPaymentResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let invoice = match Invoice::from_str(&payload.invoice) {
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
    let status = match pay_invoice(
        &invoice,
        Retry::Timeout(Duration::from_secs(10)),
        &unlocked_state.channel_manager,
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
            HTLCStatus::Failed
        }
    };
    let payment_secret = *invoice.payment_secret();

    let mut payments = unlocked_state.get_outbound_payments();
    payments.insert(
        payment_hash,
        PaymentInfo {
            preimage: None,
            secret: Some(payment_secret),
            status,
            amt_msat: invoice.amount_milli_satoshis(),
        },
    );

    Ok(Json(SendPaymentResponse {
        payment_hash: hex_str(&payment_hash.0),
        payment_secret: hex_str(&payment_secret.0),
        status,
    }))
}

pub(crate) async fn shutdown(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    let _unlocked_app_state = state.get_unlocked_app_state();
    if *state.get_changing_state() {
        return Err(APIError::ChangingState);
    }

    state.cancel_token.cancel();
    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn sign_message(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SignMessageRequest>, APIError>,
) -> Result<Json<SignMessageResponse>, APIError> {
    let unlocked_state = check_unlocked(&state)?.clone().unwrap();

    let signed_message = lightning::util::message_signing::sign(
        &payload.message.as_bytes()[payload.message.len()..],
        &unlocked_state.keys_manager.get_node_secret_key(),
    )
    .map_err(|e| APIError::FailedMessageSigning(e.to_string()))?;

    Ok(Json(SignMessageResponse { signed_message }))
}

pub(crate) async fn unlock(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<UnlockRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    match check_locked(&state) {
        Ok(unlocked_state) => {
            *state.get_changing_state() = true;
            drop(unlocked_state);
        }
        Err(e) => {
            return Err(e);
        }
    }

    let mnemonic =
        match check_password_validity(&payload.password, &state.static_state.storage_dir_path) {
            Ok(mnemonic) => mnemonic,
            Err(e) => {
                *state.get_changing_state() = false;
                return Err(e);
            }
        };

    let (new_ldk_background_services, new_unlocked_app_state) =
        match start_ldk(state.clone(), mnemonic).await {
            Ok((nlbs, nuap)) => (nlbs, nuap),
            Err(e) => {
                *state.get_changing_state() = false;
                return Err(e);
            }
        };

    let mut unlocked_app_state = state.get_unlocked_app_state();
    *unlocked_app_state = Some(new_unlocked_app_state);

    let mut ldk_background_services = state.get_ldk_background_services();
    *ldk_background_services = Some(new_ldk_background_services);

    *state.get_changing_state() = false;

    Ok(Json(EmptyResponse {}))
}
