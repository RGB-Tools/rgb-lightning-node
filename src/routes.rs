use amplify::{none, s};
use axum::{extract::State, Json};
use axum_extra::extract::WithRejection;
use bdk::{FeeRate, KeychainKind as BdkKeychainKind, SignOptions};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{hashes::Hash, Txid};
use bitcoin::{Network, OutPoint};
use lightning::chain::keysinterface::EntropySource;
use lightning::onion_message::{Destination, OnionMessageContents};
use lightning::{
    ln::{
        channelmanager::{PaymentId, RecipientOnionFields, Retry},
        PaymentHash, PaymentPreimage,
    },
    rgb_utils::{
        drop_rgb_runtime, get_rgb_channel_info, get_rgb_runtime, write_rgb_channel_info,
        write_rgb_payment_info_file, RgbInfo, RgbUtxo, RgbUtxos,
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
use rgb_core::validation::Validity;
use rgbstd::containers::Bindle;
use rgbstd::containers::Transfer as RgbTransfer;
use rgbstd::interface::TypedState;
use rgbstd::persistence::Inventory;
use rgbstd::Txid as RgbTxid;
use rgbstd::{
    containers::BuilderSeal,
    contract::{ContractId, GraphSeal, SecretSeal},
};
use rgbwallet::RgbTransport;
use seals::txout::{CloseMethod, ExplicitSeal};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    process::{id, Command},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use strict_encoding::{FieldName, TypeName};

use crate::proxy::get_consignment;
use crate::rgb::BlindedInfo;
use crate::utils::{
    hex_str, hex_str_to_compressed_pubkey, hex_str_to_vec, UserOnionMessageContents,
};
use crate::{
    bdk::{broadcast_tx, sync_wallet},
    disk,
    error::APIError,
    ldk::{PaymentInfo, FEE_RATE, MAX_LEN_NAME, MAX_LEN_TICKER, MAX_PRECISION, UTXO_SIZE_SAT},
    proxy::post_consignment,
    rgb::{
        check_uncolored_utxos, get_asset_owned_values, get_rgb_total_amount, get_utxo, RgbUtilities,
    },
    utils::{connect_peer_if_necessary, parse_peer_info},
    AppState,
};

const MIN_CREATE_UTXOS_SATS: u64 = 10000;
const UTXO_NUM: u8 = 4;

const OPENCHANNEL_MIN_SAT: u64 = 5506;
const OPENCHANNEL_MAX_SAT: u64 = 16777215;

const DUST_LIMIT_MSAT: u64 = 546000;

const HTLC_MIN_MSAT: u64 = 3000000;

const INVOICE_MIN_MSAT: u64 = HTLC_MIN_MSAT;

#[derive(Deserialize, Serialize)]
pub(crate) struct AddressResponse {
    pub(crate) address: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AssetBalanceRequest {
    pub(crate) asset_id: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AssetBalanceResponse {
    pub(crate) amount: u64,
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
    pub(crate) amount: u64,
    pub(crate) ticker: String,
    pub(crate) name: String,
    pub(crate) precision: u8,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct IssueAssetResponse {
    pub(crate) asset_id: String,
}

#[derive(Serialize, Deserialize)]
pub enum KeychainKind {
    External,
    Internal,
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

#[derive(Serialize)]
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
    pub(crate) payment_hash: String,
    pub(crate) inbound: bool,
    pub(crate) status: HTLCStatus,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Peer {
    pub(crate) pubkey: String,
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
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SendAssetResponse {
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
pub(crate) struct TxOut {
    pub(crate) value: u64,
    pub(crate) script_pubkey: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Unspent {
    pub(crate) outpoint: String,
    pub(crate) txout: TxOut,
    pub(crate) keychain: KeychainKind,
    pub(crate) is_spent: bool,
}

pub(crate) async fn address(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AddressResponse>, APIError> {
    let wallet = state.wallet.lock().unwrap();
    let address = wallet
        .get_address(bdk::wallet::AddressIndex::New)
        .expect("valid address")
        .address
        .to_string();
    Ok(Json(AddressResponse { address }))
}

pub(crate) async fn asset_balance(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<AssetBalanceRequest>, APIError>,
) -> Result<Json<AssetBalanceResponse>, APIError> {
    let asset_id = payload.asset_id;

    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;

    let runtime = get_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));
    let total_rgb_amount = get_rgb_total_amount(
        contract_id,
        &runtime,
        state.wallet.clone(),
        state.electrum_url.clone(),
    )?;

    drop(runtime);
    drop_rgb_runtime(&PathBuf::from(&state.ldk_data_dir));

    Ok(Json(AssetBalanceResponse {
        amount: total_rgb_amount,
    }))
}

pub(crate) async fn close_channel(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<CloseChannelRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let channel_id_str = payload.channel_id;
    let peer_pubkey_str = payload.peer_pubkey;
    let force = payload.force;

    let channel_id_vec = hex_str_to_vec(&channel_id_str);
    if channel_id_vec.is_none() || channel_id_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidChannelID);
    }
    let mut channel_id = [0; 32];
    channel_id.copy_from_slice(&channel_id_vec.unwrap());

    let peer_pubkey_vec = match hex_str_to_vec(&peer_pubkey_str) {
        Some(peer_pubkey_vec) => peer_pubkey_vec,
        None => return Err(APIError::InvalidPubkey),
    };
    let peer_pubkey = match PublicKey::from_slice(&peer_pubkey_vec) {
        Ok(peer_pubkey) => peer_pubkey,
        Err(_) => return Err(APIError::InvalidPubkey),
    };

    if force {
        match state
            .channel_manager
            .force_close_broadcasting_latest_txn(&channel_id, &peer_pubkey)
        {
            Ok(()) => tracing::info!("EVENT: initiating channel force-close"),
            Err(e) => return Err(APIError::FailedClosingChannel(format!("{:?}", e))),
        }
    } else {
        match state
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
    let peer_pubkey_and_addr = payload.peer_pubkey_and_addr;

    let (peer_pubkey, peer_addr) = parse_peer_info(peer_pubkey_and_addr.to_string())?;

    connect_peer_if_necessary(peer_pubkey, peer_addr, state.peer_manager.clone()).await?;

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn create_utxos(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmptyResponse>, APIError> {
    let wallet = state.wallet.lock().unwrap();
    sync_wallet(&wallet, state.electrum_url.clone());

    let rgb_utxos_path = format!("{}/rgb_utxos", state.ldk_data_dir.clone());
    let serialized_utxos =
        fs::read_to_string(&rgb_utxos_path).expect("able to read rgb utxos file");
    let mut rgb_utxos: RgbUtxos = serde_json::from_str(&serialized_utxos).expect("valid rgb utxos");
    let unspendable_utxos: Vec<OutPoint> = rgb_utxos.utxos.iter().map(|u| u.outpoint).collect();

    let unspendable_amt: u64 = wallet
        .list_unspent()
        .expect("unspents")
        .iter()
        .filter(|u| unspendable_utxos.contains(&u.outpoint))
        .map(|u| u.txout.value)
        .sum();
    let available = wallet.get_balance().expect("wallet balance").get_total() - unspendable_amt;
    if available < MIN_CREATE_UTXOS_SATS {
        return Err(APIError::InsufficientFunds(
            MIN_CREATE_UTXOS_SATS - available,
        ));
    }

    let mut tx_builder = wallet.build_tx();
    tx_builder
        .unspendable(unspendable_utxos)
        .fee_rate(FeeRate::from_sat_per_vb(FEE_RATE))
        .ordering(bdk::wallet::tx_builder::TxOrdering::Untouched);
    for _i in 0..UTXO_NUM {
        tx_builder.add_recipient(
            wallet
                .get_address(bdk::wallet::AddressIndex::New)
                .expect("address")
                .script_pubkey(),
            UTXO_SIZE_SAT,
        );
    }
    let (mut psbt, _details) = tx_builder.finish().expect("successful psbt creation");

    wallet
        .sign(&mut psbt, SignOptions::default())
        .expect("successful sign");

    let tx = psbt.extract_tx();
    broadcast_tx(&tx, state.electrum_url.clone());

    for i in 0..UTXO_NUM {
        rgb_utxos.utxos.push(RgbUtxo {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout: i as u32,
            },
            colored: false,
        });
    }
    let serialized_utxos = serde_json::to_string(&rgb_utxos).expect("valid rgb utxos");
    fs::write(rgb_utxos_path, serialized_utxos).expect("able to write rgb utxos file");

    sync_wallet(&wallet, state.electrum_url.clone());
    tracing::debug!("UTXO creation complete");

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn disconnect_peer(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<DisconnectPeerRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let peer_pubkey_str = payload.peer_pubkey;

    let peer_pubkey = match bitcoin::secp256k1::PublicKey::from_str(&peer_pubkey_str) {
        Ok(pubkey) => pubkey,
        Err(_e) => return Err(APIError::InvalidPubkey),
    };

    //check for open channels with peer
    for channel in state.channel_manager.list_channels() {
        if channel.counterparty.node_id == peer_pubkey {
            return Err(APIError::FailedPeerDisconnection(s!(
                "node has an active channel with this peer, close any channels first"
            )));
        }
    }

    //check the pubkey matches a valid connected peer
    let peers = state.peer_manager.get_peer_node_ids();
    if !peers.iter().any(|(pk, _)| &peer_pubkey == pk) {
        return Err(APIError::FailedPeerDisconnection(format!(
            "Could not find peer {}",
            peer_pubkey
        )));
    }

    state.peer_manager.disconnect_by_node_id(peer_pubkey);

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn invoice_status(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<InvoiceStatusRequest>, APIError>,
) -> Result<Json<InvoiceStatusResponse>, APIError> {
    let invoice_str = payload.invoice;

    let invoice = match Invoice::from_str(&invoice_str) {
        Err(e) => return Err(APIError::InvalidInvoice(e.to_string())),
        Ok(v) => v,
    };

    let inbound = state.inbound_payments.lock().unwrap();

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
    let amount = payload.amount;
    let ticker = payload.ticker;
    let name = payload.name;
    let precision = payload.precision;

    if ticker.is_empty() {
        return Err(APIError::InvalidTicker(s!("ticker cannot be empty")));
    }
    if !ticker.is_ascii() {
        return Err(APIError::InvalidTicker(s!(
            "ticker cannot contain non-ASCII characters"
        )));
    }
    if ticker.len() > MAX_LEN_TICKER {
        return Err(APIError::InvalidName(s!("ticker too long")));
    }
    if ticker.to_ascii_uppercase() != *ticker {
        return Err(APIError::InvalidTicker(s!(
            "ticker needs to be all uppercase"
        )));
    }

    if name.is_empty() {
        return Err(APIError::InvalidName(s!("name cannot be empty")));
    }
    if !name.is_ascii() {
        return Err(APIError::InvalidName(s!(
            "name cannot contain non-ASCII characters"
        )));
    }
    if name.len() > MAX_LEN_NAME {
        return Err(APIError::InvalidName(s!("name too long")));
    }

    if precision > MAX_PRECISION {
        return Err(APIError::InvalidPrecision(s!("precision is too high")));
    }

    check_uncolored_utxos(&state.ldk_data_dir).await?;
    let outpoint = get_utxo(&state.ldk_data_dir).await.outpoint;
    let rgb_utxos_path = format!("{}/rgb_utxos", state.ldk_data_dir.clone());
    let serialized_utxos =
        fs::read_to_string(&rgb_utxos_path).expect("able to read rgb utxos file");
    let mut rgb_utxos: RgbUtxos = serde_json::from_str(&serialized_utxos).expect("valid rgb utxos");
    rgb_utxos
        .utxos
        .iter_mut()
        .find(|u| u.outpoint == outpoint)
        .expect("UTXO found")
        .colored = true;
    let serialized_utxos = serde_json::to_string(&rgb_utxos).expect("valid rgb utxos");
    fs::write(rgb_utxos_path, serialized_utxos).expect("able to write rgb utxos file");

    let mut runtime = get_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));
    let contract_id = runtime.issue_contract(amount, outpoint, ticker, name, precision);
    drop(runtime);
    drop_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

    Ok(Json(IssueAssetResponse {
        asset_id: contract_id.to_string(),
    }))
}

pub(crate) async fn keysend(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<KeysendRequest>, APIError>,
) -> Result<Json<KeysendResponse>, APIError> {
    let asset_id = payload.asset_id;

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

    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;

    let payment_preimage = PaymentPreimage(state.keys_manager.get_secure_random_bytes());
    let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
    write_rgb_payment_info_file(
        &PathBuf::from(&state.ldk_data_dir),
        &payment_hash,
        contract_id,
        payload.asset_amount,
    );

    let route_params = RouteParameters {
        payment_params: PaymentParameters::for_keysend(dest_pubkey, 40),
        final_value_msat: amt_msat,
    };
    let status = match state.channel_manager.send_spontaneous_payment_with_retry(
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

    let mut payments = state.outbound_payments.lock().unwrap();
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

pub(crate) async fn list_channels(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListChannelsResponse>, APIError> {
    let mut channels = vec![];
    for chan_info in state.channel_manager.list_channels() {
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

        if let Some(node_info) = state
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

        let ldk_data_dir_path = PathBuf::from(state.ldk_data_dir.clone());
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
    let inbound = state.inbound_payments.lock().unwrap();
    let outbound = state.outbound_payments.lock().unwrap();
    let mut payments = vec![];

    for (payment_hash, payment_info) in inbound.deref() {
        payments.push(Payment {
            amt_msat: payment_info.amt_msat,
            payment_hash: hex_str(&payment_hash.0),
            inbound: true,
            status: payment_info.status,
        })
    }

    for (payment_hash, payment_info) in outbound.deref() {
        payments.push(Payment {
            amt_msat: payment_info.amt_msat,
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
    let mut peers = vec![];
    for (pubkey, _) in state.peer_manager.get_peer_node_ids() {
        peers.push(Peer {
            pubkey: pubkey.to_string(),
        })
    }

    Ok(Json(ListPeersResponse { peers }))
}

pub(crate) async fn list_unspents(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListUnspentsResponse>, APIError> {
    let wallet = state.wallet.lock().unwrap();
    sync_wallet(&wallet, state.electrum_url.clone());
    let local_utxos = wallet.list_unspent().expect("unspents");
    let mut unspents = vec![];
    for local_utxo in local_utxos {
        unspents.push(Unspent {
            outpoint: local_utxo.outpoint.to_string(),
            txout: TxOut {
                value: local_utxo.txout.value,
                script_pubkey: local_utxo.txout.script_pubkey.to_string(),
            },
            keychain: match local_utxo.keychain {
                BdkKeychainKind::External => KeychainKind::External,
                BdkKeychainKind::Internal => KeychainKind::Internal,
            },
            is_spent: local_utxo.is_spent,
        })
    }
    Ok(Json(ListUnspentsResponse { unspents }))
}

pub(crate) async fn ln_invoice(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<LNInvoiceRequest>, APIError>,
) -> Result<Json<LNInvoiceResponse>, APIError> {
    let amt_msat = payload.amt_msat;
    let expiry_sec = payload.expiry_sec;
    let asset_amount = payload.asset_amount;

    let contract_id = if let Some(asset_id) = payload.asset_id {
        Some(ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?)
    } else {
        None
    };

    if amt_msat.is_some() && amt_msat.unwrap() < INVOICE_MIN_MSAT {
        return Err(APIError::InvalidAmount(format!(
            "amt_msat cannot be less than {INVOICE_MIN_MSAT}"
        )));
    }

    let mut payments = state.inbound_payments.lock().unwrap();
    let currency = match state.network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Regtest => Currency::Regtest,
        Network::Signet => Currency::Signet,
    };
    let invoice = match create_invoice_from_channelmanager(
        &state.channel_manager,
        state.keys_manager.clone(),
        state.logger.clone(),
        currency,
        amt_msat,
        "ldk-tutorial-node".to_string(),
        expiry_sec,
        None,
        contract_id,
        asset_amount,
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
            amt_msat,
        },
    );

    Ok(Json(LNInvoiceResponse {
        invoice: invoice.to_string(),
    }))
}

pub(crate) async fn node_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NodeInfoResponse>, APIError> {
    let chans = state.channel_manager.list_channels();

    Ok(Json(NodeInfoResponse {
        pubkey: state.channel_manager.get_our_node_id().to_string(),
        num_channels: chans.len(),
        num_usable_channels: chans.iter().filter(|c| c.is_usable).count(),
        local_balance_msat: chans.iter().map(|c| c.balance_msat).sum::<u64>(),
        num_peers: state.peer_manager.get_peer_node_ids().len(),
    }))
}

pub(crate) async fn open_channel(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<OpenChannelRequest>, APIError>,
) -> Result<Json<OpenChannelResponse>, APIError> {
    let peer_pubkey_and_addr = payload.peer_pubkey_and_addr;
    let chan_amt_sat = payload.capacity_sat;
    let push_amt_msat = payload.push_msat;
    let chan_amt_rgb = payload.asset_amount;
    let asset_id = payload.asset_id;
    let announced_channel = payload.public;

    let (peer_pubkey, peer_addr) = parse_peer_info(peer_pubkey_and_addr.to_string())?;

    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;

    if chan_amt_sat < OPENCHANNEL_MIN_SAT {
        return Err(APIError::InvalidAmount(format!(
            "Channel amount must be equal or higher than {OPENCHANNEL_MIN_SAT}"
        )));
    }
    if chan_amt_sat > OPENCHANNEL_MAX_SAT {
        return Err(APIError::InvalidAmount(format!(
            "Channel amount must be equal or less than {OPENCHANNEL_MAX_SAT}"
        )));
    }

    if push_amt_msat < DUST_LIMIT_MSAT {
        return Err(APIError::InvalidAmount(format!(
            "Push amount must be equal or higher than the dust limit ({DUST_LIMIT_MSAT})"
        )));
    }

    let runtime = get_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

    let total_rgb_amount = get_rgb_total_amount(
        contract_id,
        &runtime,
        state.wallet.clone(),
        state.electrum_url.clone(),
    )?;

    drop(runtime);
    drop_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

    if chan_amt_rgb > total_rgb_amount {
        return Err(APIError::InsufficientAssets(total_rgb_amount));
    }

    connect_peer_if_necessary(peer_pubkey, peer_addr, state.peer_manager.clone()).await?;

    let config = UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            // lnd's max to_self_delay is 2016, so we want to be compatible.
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            announced_channel,
            our_htlc_minimum_msat: HTLC_MIN_MSAT,
            ..Default::default()
        },
        ..Default::default()
    };

    let consignment_endpoint = RgbTransport::from_str(&state.proxy_endpoint).unwrap();
    let temporary_channel_id = state
        .channel_manager
        .create_channel(
            peer_pubkey,
            chan_amt_sat,
            push_amt_msat,
            0,
            Some(config),
            consignment_endpoint,
        )
        .map_err(|e| APIError::FailedOpenChannel(format!("{:?}", e)))?;
    tracing::info!("EVENT: initiated channel with peer {}", peer_pubkey);

    let peer_data_path = format!("{}/channel_peer_data", state.ldk_data_dir.clone());
    let _ = disk::persist_channel_peer(Path::new(&peer_data_path), &peer_pubkey_and_addr);

    let temporary_channel_id = hex::encode(temporary_channel_id);
    let channel_rgb_info_path = format!("{}/{}", state.ldk_data_dir.clone(), temporary_channel_id,);
    let rgb_info = RgbInfo {
        contract_id,
        local_rgb_amount: chan_amt_rgb,
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
    let blinded_dir = PathBuf::from_str(&state.ldk_data_dir)
        .expect("valid data dir")
        .join("blinded_utxos");
    let blinded_files = fs::read_dir(blinded_dir).expect("successfult dir read");

    for bf in blinded_files {
        let serialized_info =
            fs::read_to_string(bf.as_ref().unwrap().path()).expect("valid blinded info file");
        let blinded_info: BlindedInfo =
            serde_json::from_str(&serialized_info).expect("valid blinded data");
        if blinded_info.consumed {
            continue;
        }

        let blinded_utxo = blinded_info.seal.to_concealed_seal().to_string();

        let proxy_ref = (*state.proxy_client).clone();
        let res = get_consignment(proxy_ref, &state.proxy_url, blinded_utxo.clone()).await;
        if res.is_err() || res.as_ref().unwrap().result.is_none() {
            tracing::warn!("WARNING: unable to get consignment");
            continue;
        }
        let consignment = res.unwrap().result.unwrap();
        let consignment_bytes = base64::decode(consignment).expect("valid consignment");
        let consignment_path = format!(
            "{}/consignment_{}",
            state.ldk_data_dir.clone(),
            blinded_utxo
        );
        fs::write(consignment_path.clone(), consignment_bytes).expect("unable to write file");
        let consignment =
            Bindle::<RgbTransfer>::load(consignment_path).expect("successful consignment load");
        let transfer: RgbTransfer = consignment.clone().unbindle();

        let mut runtime = get_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

        let mut minimal_contract = transfer.clone().into_contract();
        minimal_contract.bundles = none!();
        minimal_contract.terminals = none!();
        let minimal_contract_validated = match minimal_contract.clone().validate(runtime.resolver())
        {
            Ok(consignment) => consignment,
            Err(consignment) => consignment,
        };
        runtime
            .import_contract(minimal_contract_validated)
            .expect("failure importing issued contract");

        let validated_transfer = transfer
            .validate(runtime.resolver())
            .expect("invalid contract");
        let status = runtime
            .accept_transfer(validated_transfer, true)
            .expect("valid transfer");
        drop(runtime);
        drop_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));
        let validity = status.validity();
        if !matches!(validity, Validity::Valid) {
            tracing::warn!("WARNING: error accepting transfer");
            continue;
        }

        let wallet = state.wallet.lock().unwrap();
        sync_wallet(&wallet, state.electrum_url.clone());

        fs::remove_file(bf.unwrap().path()).expect("successful file remove");
    }

    tracing::info!("Refresh complete");

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn rgb_invoice(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RgbInvoiceResponse>, APIError> {
    check_uncolored_utxos(&state.ldk_data_dir).await?;
    let outpoint = get_utxo(&state.ldk_data_dir).await.outpoint;
    let rgb_utxos_path = format!("{}/rgb_utxos", state.ldk_data_dir.clone());
    let serialized_utxos =
        fs::read_to_string(&rgb_utxos_path).expect("able to read rgb utxos file");
    let mut rgb_utxos: RgbUtxos = serde_json::from_str(&serialized_utxos).expect("valid rgb utxos");
    rgb_utxos
        .utxos
        .iter_mut()
        .find(|u| u.outpoint == outpoint)
        .expect("UTXO found")
        .colored = true;
    let serialized_utxos = serde_json::to_string(&rgb_utxos).expect("valid rgb utxos");
    fs::write(rgb_utxos_path, serialized_utxos).expect("able to write rgb utxos file");

    let seal = ExplicitSeal::with(
        CloseMethod::OpretFirst,
        RgbTxid::from_str(&outpoint.txid.to_string())
            .unwrap()
            .into(),
        outpoint.vout,
    );
    let seal = GraphSeal::from(seal);

    let mut runtime = get_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));
    runtime
        .store_seal_secret(seal)
        .expect("successful seal store");
    drop(runtime);
    drop_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

    let concealed_seal = seal.to_concealed_seal();
    let blinded_utxo = concealed_seal.to_string();

    let blinded_dir = PathBuf::from_str(&state.ldk_data_dir.clone())
        .expect("valid data dir")
        .join("blinded_utxos");
    let blinded_path = blinded_dir.join(&blinded_utxo);
    let blinded_info = BlindedInfo {
        contract_id: None,
        seal,
        consumed: false,
    };
    let serialized_info = serde_json::to_string(&blinded_info).expect("valid rgb info");
    fs::write(blinded_path, serialized_info).expect("successful file write");

    Ok(Json(RgbInvoiceResponse { blinded_utxo }))
}

pub(crate) async fn send_asset(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendAssetRequest>, APIError>,
) -> Result<Json<SendAssetResponse>, APIError> {
    let asset_id = payload.asset_id;
    let rgb_amt = payload.amount;
    let blinded_utxo = payload.blinded_utxo;

    let contract_id =
        ContractId::from_str(&asset_id).map_err(|_| APIError::InvalidAssetID(asset_id))?;

    let mut runtime = get_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

    let total_rgb_amount = get_rgb_total_amount(
        contract_id,
        &runtime,
        state.wallet.clone(),
        state.electrum_url.clone(),
    )?;

    if rgb_amt > total_rgb_amount {
        return Err(APIError::InsufficientAssets(total_rgb_amount));
    }

    let concealed_seal = SecretSeal::from_str(&blinded_utxo)
        .map_err(|_| APIError::InvalidBlindedUTXO(blinded_utxo.clone()))?;

    let asset_owned_values = get_asset_owned_values(
        contract_id,
        &runtime,
        state.wallet.clone(),
        state.electrum_url.clone(),
    )
    .expect("known contract");

    let mut asset_transition_builder = runtime
        .transition_builder(
            contract_id,
            TypeName::try_from("RGB20").unwrap(),
            None::<&str>,
        )
        .expect("ok");
    let assignment_id = asset_transition_builder
        .assignments_type(&FieldName::from("beneficiary"))
        .expect("valid assignment");
    let mut beneficiaries = vec![];

    let mut rgb_inputs = vec![];
    let mut input_amount: u64 = 0;
    for (_opout, (outpoint, amount)) in asset_owned_values {
        if input_amount >= rgb_amt {
            break;
        }
        rgb_inputs.push(OutPoint {
            txid: Txid::from_str(&outpoint.txid.to_string()).unwrap(),
            vout: outpoint.vout.into_u32(),
        });
        input_amount += amount;
    }

    let rgb_change_amount = input_amount - rgb_amt;
    if rgb_change_amount > 0 {
        check_uncolored_utxos(&state.ldk_data_dir).await?;
        let rgb_change_outpoint = get_utxo(&state.ldk_data_dir).await.outpoint;
        let rgb_utxos_path = format!("{}/rgb_utxos", state.ldk_data_dir.clone());
        let serialized_utxos =
            fs::read_to_string(&rgb_utxos_path).expect("able to read rgb utxos file");
        let mut rgb_utxos: RgbUtxos =
            serde_json::from_str(&serialized_utxos).expect("valid rgb utxos");
        rgb_utxos
            .utxos
            .iter_mut()
            .find(|u| u.outpoint == rgb_change_outpoint)
            .expect("UTXO found")
            .colored = true;
        let serialized_utxos = serde_json::to_string(&rgb_utxos).expect("valid rgb utxos");
        fs::write(rgb_utxos_path, serialized_utxos).expect("able to write rgb utxos file");
        let seal = ExplicitSeal::with(
            CloseMethod::OpretFirst,
            RgbTxid::from_str(&rgb_change_outpoint.txid.to_string())
                .unwrap()
                .into(),
            rgb_change_outpoint.vout,
        );
        let seal = GraphSeal::from(seal);
        let change = TypedState::Amount(rgb_change_amount);
        asset_transition_builder = asset_transition_builder
            .add_raw_state(assignment_id, seal, change)
            .unwrap();
    }

    let psbt = {
        let wallet = state.wallet.lock().unwrap();
        let mut builder = wallet.build_tx();
        let address = wallet
            .get_address(bdk::wallet::AddressIndex::New)
            .expect("valid address")
            .address;
        builder
            .add_utxos(&rgb_inputs)
            .expect("valid utxos")
            .add_data(&[1])
            .fee_rate(FeeRate::from_sat_per_vb(FEE_RATE))
            .manually_selected_only()
            .drain_to(address.script_pubkey());
        builder.finish().expect("valid psbt finish").0
    };

    asset_transition_builder = asset_transition_builder
        .add_raw_state(assignment_id, concealed_seal, TypedState::Amount(rgb_amt))
        .expect("ok");
    beneficiaries.push(BuilderSeal::Concealed(concealed_seal));

    let (mut psbt, consignment) =
        runtime.send_rgb(contract_id, psbt, asset_transition_builder, beneficiaries);

    let consignment_path = format!("{}/consignment", state.ldk_data_dir.clone());
    consignment
        .save(&consignment_path)
        .expect("successful save");

    let proxy_ref = (*state.proxy_client).clone();
    let res = post_consignment(
        proxy_ref,
        &state.proxy_url,
        blinded_utxo.to_string(),
        consignment_path.into(),
    )
    .await;
    if res.is_err() || res.as_ref().unwrap().result.is_none() {
        if let Ok(res) = res {
            if let Some(err) = res.error {
                if err.code == -101 {
                    return Err(APIError::BlindedUTXOAlreadyUsed)?;
                }
            }
        }
        return Err(APIError::FailedPostingConsignment);
    }

    let wallet = state.wallet.lock().unwrap();
    wallet
        .sign(&mut psbt, SignOptions::default())
        .expect("able to sign");
    let tx = psbt.extract_tx();
    broadcast_tx(&tx, state.electrum_url.clone());

    let transfer = consignment
        .unbindle()
        .validate(runtime.resolver())
        .unwrap_or_else(|c| c);
    let _status = runtime
        .accept_transfer(transfer, true)
        .expect("valid transfer");
    drop(runtime);
    drop_rgb_runtime(&PathBuf::from(state.ldk_data_dir.clone()));

    sync_wallet(&wallet, state.electrum_url.clone());
    let txid = tx.txid().to_string();

    Ok(Json(SendAssetResponse { txid }))
}

pub(crate) async fn send_onion_message(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SendOnionMessageRequest>, APIError>,
) -> Result<Json<EmptyResponse>, APIError> {
    let node_ids = payload.node_ids;
    let tlv_type = payload.tlv_type;

    if node_ids.is_empty() {
        return Err(APIError::InvalidNodeIds(s!(
            "sendonionmessage requires at least one node id for the path"
        )));
    }

    let mut node_pks = Vec::new();
    for pk_str in node_ids {
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

    if tlv_type < 64 {
        return Err(APIError::InvalidTlvType(s!(
            "need an integral message type above 64"
        )));
    }

    let data = hex_str_to_vec(&payload.data)
        .ok_or(APIError::InvalidOnionData(s!("need a hex data string")))?;

    let destination_pk = node_pks.pop().unwrap();
    state
        .onion_messenger
        .send_onion_message(
            &node_pks,
            Destination::Node(destination_pk),
            OnionMessageContents::Custom(UserOnionMessageContents { tlv_type, data }),
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
    let invoice_str = payload.invoice;

    let invoice = match Invoice::from_str(&invoice_str) {
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
            &PathBuf::from(&state.ldk_data_dir),
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
        &state.channel_manager,
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

    let mut payments = state.outbound_payments.lock().unwrap();
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

pub(crate) async fn shutdown() -> Result<Json<EmptyResponse>, APIError> {
    let mut kill = Command::new("kill")
        .args(["-s", "INT", &id().to_string()])
        .spawn()?;
    kill.wait()?;

    Ok(Json(EmptyResponse {}))
}

pub(crate) async fn sign_message(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<SignMessageRequest>, APIError>,
) -> Result<Json<SignMessageResponse>, APIError> {
    let message = payload.message;
    let signed_message = lightning::util::message_signing::sign(
        &message.as_bytes()[message.len()..],
        &state.keys_manager.get_node_secret_key(),
    )
    .map_err(|e| APIError::FailedMessageSigning(e.to_string()))?;

    Ok(Json(SignMessageResponse { signed_message }))
}
