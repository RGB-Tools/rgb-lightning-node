use amplify::s;
use electrum_client::ElectrumApi;
use lazy_static::lazy_static;
use lightning_invoice::Bolt11Invoice;
use once_cell::sync::Lazy;
use reqwest::Response;
use rgb_lib::BitcoinNetwork;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Mutex, Once, RwLock};
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing_test::traced_test;

use crate::error::APIErrorResponse;
use crate::ldk::FEE_RATE;
use crate::routes::{
    AddressResponse, AssetBalanceRequest, AssetBalanceResponse, AssetCFA,
    AssetIdFromHexBytesRequest, AssetIdFromHexBytesResponse, AssetIdToHexBytesRequest,
    AssetIdToHexBytesResponse, AssetNIA, AssetUDA, BackupRequest, BtcBalanceRequest,
    BtcBalanceResponse, ChangePasswordRequest, Channel, CloseChannelRequest, ConnectPeerRequest,
    CreateUtxosRequest, DecodeLNInvoiceRequest, DecodeLNInvoiceResponse, DecodeRGBInvoiceRequest,
    DecodeRGBInvoiceResponse, DisconnectPeerRequest, EmptyResponse, FailTransfersRequest,
    FailTransfersResponse, GetAssetMediaRequest, GetAssetMediaResponse, GetChannelIdRequest,
    GetChannelIdResponse, GetPaymentRequest, GetPaymentResponse, GetSwapRequest, GetSwapResponse,
    HTLCStatus, InitRequest, InitResponse, InvoiceStatus, InvoiceStatusRequest,
    InvoiceStatusResponse, IssueAssetCFARequest, IssueAssetCFAResponse, IssueAssetNIARequest,
    IssueAssetNIAResponse, IssueAssetUDARequest, IssueAssetUDAResponse, KeysendRequest,
    KeysendResponse, LNInvoiceRequest, LNInvoiceResponse, ListAssetsRequest, ListAssetsResponse,
    ListChannelsResponse, ListPaymentsResponse, ListPeersResponse, ListSwapsResponse,
    ListTransactionsRequest, ListTransactionsResponse, ListTransfersRequest, ListTransfersResponse,
    ListUnspentsRequest, ListUnspentsResponse, MakerExecuteRequest, MakerInitRequest,
    MakerInitResponse, NetworkInfoResponse, NodeInfoResponse, OpenChannelRequest,
    OpenChannelResponse, Payment, Peer, PostAssetMediaResponse, RefreshRequest, RestoreRequest,
    RgbInvoiceRequest, RgbInvoiceResponse, SendAssetRequest, SendAssetResponse, SendBtcRequest,
    SendBtcResponse, SendPaymentRequest, SendPaymentResponse, Swap, SwapStatus, TakerRequest,
    Transaction, Transfer, UnlockRequest, Unspent,
};
use crate::utils::{hex_str_to_vec, ELECTRUM_URL_REGTEST, PROXY_ENDPOINT_LOCAL};

use super::*;

const ELECTRUM_URL: &str = "127.0.0.1:50001";
const NODE1_PEER_PORT: u16 = 9801;
const NODE2_PEER_PORT: u16 = 9802;
const NODE3_PEER_PORT: u16 = 9803;
const NODE4_PEER_PORT: u16 = 9804;

static INIT: Once = Once::new();

static MINER: Lazy<RwLock<Miner>> = Lazy::new(|| RwLock::new(Miner { no_mine_count: 0 }));

#[cfg(test)]
impl Default for LdkUserInfo {
    fn default() -> Self {
        Self {
            network: BitcoinNetwork::Regtest,
            storage_dir_path: PathBuf::from("tmp/test_name/nodeN"),
            daemon_listening_port: 3001,
            ldk_peer_listening_port: 9735,
            max_media_upload_size_mb: 3,
        }
    }
}

fn _bitcoin_cli() -> [String; 7] {
    [
        s!("exec"),
        s!("-T"),
        s!("-u"),
        s!("blits"),
        s!("bitcoind"),
        s!("bitcoin-cli"),
        s!("-regtest"),
    ]
}

async fn _check_response_is_ok(res: Response) -> Response {
    if res.status() != reqwest::StatusCode::OK {
        panic!("reqwest response is not OK: {:?}", res.text().await);
    }
    res
}

async fn check_response_is_nok(
    res: Response,
    expected_status: reqwest::StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    assert_eq!(res.status(), expected_status);
    let api_error_response = res.json::<APIErrorResponse>().await.unwrap();
    assert_eq!(api_error_response.code, expected_status.as_u16());
    assert!(api_error_response.error.contains(expected_message));
    assert_eq!(api_error_response.name, expected_name);
}

fn _fund_wallet(address: String) {
    let status = Command::new("docker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("compose")
        .args(_bitcoin_cli())
        .arg("-rpcwallet=miner")
        .arg("sendtoaddress")
        .arg(address)
        .arg("1")
        .status()
        .expect("failed to fund wallet");
    assert!(status.success());
}

fn _get_txout(txid: &str) -> String {
    String::from_utf8(
        Command::new("docker")
            .stdin(Stdio::null())
            .arg("compose")
            .args(_bitcoin_cli())
            .arg("-rpcwallet=miner")
            .arg("gettxout")
            .arg(txid)
            .arg("0")
            .output()
            .expect("failed get txout")
            .stdout,
    )
    .unwrap()
}

async fn start_daemon(node_test_dir: &str, node_peer_port: u16) -> SocketAddr {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let node_address = listener.local_addr().unwrap();
    std::fs::create_dir_all(node_test_dir).unwrap();
    let args = LdkUserInfo {
        storage_dir_path: node_test_dir.into(),
        ldk_peer_listening_port: node_peer_port,
        ..Default::default()
    };
    tokio::spawn(async move {
        let (router, app_state) = app(args).await.unwrap();
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal(app_state))
            .await
            .unwrap();
    });
    node_address
}

async fn start_node(
    node_test_dir: &str,
    node_peer_port: u16,
    keep_node_dir: bool,
) -> (SocketAddr, String) {
    println!("starting node with peer port {node_peer_port}");
    if !keep_node_dir && Path::new(&node_test_dir).is_dir() {
        std::fs::remove_dir_all(node_test_dir).unwrap();
    }
    let node_address = start_daemon(node_test_dir, node_peer_port).await;

    let password = format!("{node_test_dir}.{node_peer_port}");

    if !keep_node_dir {
        let payload = InitRequest {
            password: password.clone(),
        };
        let res = reqwest::Client::new()
            .post(format!("http://{}/init", node_address))
            .json(&payload)
            .send()
            .await
            .unwrap();
        _check_response_is_ok(res)
            .await
            .json::<InitResponse>()
            .await
            .unwrap();
    }

    unlock(node_address, &password).await;

    println!("node on peer port {node_peer_port} started with address {node_address:?}");
    (node_address, password)
}

async fn address(node_address: SocketAddr) -> String {
    println!("getting address for node {node_address}");
    let res = reqwest::Client::new()
        .post(format!("http://{}/address", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<AddressResponse>()
        .await
        .unwrap()
        .address
}

async fn asset_balance(node_address: SocketAddr, asset_id: &str) -> AssetBalanceResponse {
    println!("getting balance for asset {asset_id} on node {node_address}");
    let payload = AssetBalanceRequest {
        asset_id: asset_id.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/assetbalance", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<AssetBalanceResponse>()
        .await
        .unwrap()
}

async fn asset_balance_offchain_outbound(node_address: SocketAddr, asset_id: &str) -> u64 {
    asset_balance(node_address, asset_id)
        .await
        .offchain_outbound
}

async fn asset_balance_spendable(node_address: SocketAddr, asset_id: &str) -> u64 {
    asset_balance(node_address, asset_id).await.spendable
}

async fn asset_id_from_hex_bytes(
    node_address: SocketAddr,
    hex_bytes: String,
) -> AssetIdFromHexBytesResponse {
    println!("converting hex bytes {hex_bytes} to asset ID for node {node_address}");
    let payload = AssetIdFromHexBytesRequest { hex_bytes };
    let res = reqwest::Client::new()
        .post(format!("http://{}/assetidfromhexbytes", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<AssetIdFromHexBytesResponse>()
        .await
        .unwrap()
}

async fn asset_id_to_hex_bytes(
    node_address: SocketAddr,
    asset_id: String,
) -> AssetIdToHexBytesResponse {
    println!("converting asset ID {asset_id} to hex bytes for node {node_address}");
    let payload = AssetIdToHexBytesRequest { asset_id };
    let res = reqwest::Client::new()
        .post(format!("http://{}/assetidtohexbytes", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<AssetIdToHexBytesResponse>()
        .await
        .unwrap()
}

async fn backup(node_address: SocketAddr, backup_path: &str, password: &str) {
    println!("performing backup for node {node_address} on {backup_path}");
    let payload = BackupRequest {
        backup_path: backup_path.to_string(),
        password: password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/backup", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn btc_balance(node_address: SocketAddr) -> BtcBalanceResponse {
    println!("getting BTC balance for node {node_address}");
    let payload = BtcBalanceRequest { skip_sync: false };
    let res = reqwest::Client::new()
        .post(format!("http://{}/btcbalance", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<BtcBalanceResponse>()
        .await
        .unwrap()
}

async fn change_password(node_address: SocketAddr, old_password: &str, new_password: &str) {
    println!("changing password for node {node_address}");
    let payload = ChangePasswordRequest {
        old_password: old_password.to_string(),
        new_password: new_password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/changepassword", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn check_payment_status(
    node_address: SocketAddr,
    payment_hash: &str,
    expected_status: HTLCStatus,
) -> Option<Payment> {
    println!("checking payment {payment_hash} is {expected_status:?} on node {node_address}");
    let payments = list_payments(node_address).await;
    if let Some(payment) = payments.iter().find(|p| p.payment_hash == payment_hash) {
        if payment.status == expected_status {
            return Some(payment.clone());
        }
        println!("payment found but with status: {:?}", payment.status);
    }
    None
}

async fn close_channel(node_address: SocketAddr, channel_id: &str, peer_pubkey: &str, force: bool) {
    println!(
        "{}closing channel {channel_id} from node {node_address}",
        if force { "force-" } else { "cooperatively " }
    );
    stop_mining();
    let payload = CloseChannelRequest {
        channel_id: channel_id.to_string(),
        peer_pubkey: peer_pubkey.to_string(),
        force,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/closechannel", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node_address).await;
        if !channels.iter().any(|c| c.channel_id == channel_id) {
            let block_num = match force {
                true => 144,
                false => 6,
            };
            mine_n_blocks(true, block_num);
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("channel is taking too long to close")
        }
    }
}

async fn connect_peer(node_address: SocketAddr, peer_pubkey: &str, peer_addr: &str) {
    println!("connecting peer {peer_pubkey} from node {node_address}");
    let payload = ConnectPeerRequest {
        peer_pubkey_and_addr: format!("{peer_pubkey}@{peer_addr}"),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/connectpeer", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn create_utxos(node_address: SocketAddr, up_to: bool, num: Option<u8>, size: Option<u32>) {
    println!(
        "creating{}{} UTXOs{} for node {node_address}",
        if up_to { " up to" } else { "" },
        if num.is_some() {
            format!(" {}", num.unwrap())
        } else {
            s!("")
        },
        if size.is_some() {
            format!(" of size {}", size.unwrap())
        } else {
            s!("")
        },
    );

    let num = if num.is_some() { num } else { Some(10) };
    let payload = CreateUtxosRequest {
        up_to,
        num,
        size,
        fee_rate: FEE_RATE,
        skip_sync: false,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/createutxos", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn decode_ln_invoice(node_address: SocketAddr, invoice: &str) -> DecodeLNInvoiceResponse {
    println!("decoding LN invoice {invoice} for node {node_address}");
    let payload = DecodeLNInvoiceRequest {
        invoice: invoice.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/decodelninvoice", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<DecodeLNInvoiceResponse>()
        .await
        .unwrap()
}

async fn decode_rgb_invoice(node_address: SocketAddr, invoice: &str) -> DecodeRGBInvoiceResponse {
    println!("decoding RGB invoice {invoice} for node {node_address}");
    let payload = DecodeRGBInvoiceRequest {
        invoice: invoice.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/decodergbinvoice", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<DecodeRGBInvoiceResponse>()
        .await
        .unwrap()
}

async fn disconnect_peer(node_address: SocketAddr, peer_pubkey: &str) {
    println!("disconnecting peer {peer_pubkey} from node {node_address}");
    let payload = DisconnectPeerRequest {
        peer_pubkey: peer_pubkey.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/disconnectpeer", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn fail_transfers(node_address: SocketAddr, batch_transfer_idx: Option<i32>) -> bool {
    println!(
        "failing transfers, batch_transfer_idx {batch_transfer_idx:?} from node {node_address}"
    );
    let payload = FailTransfersRequest {
        batch_transfer_idx,
        no_asset_only: false,
        skip_sync: false,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/failtransfers", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<FailTransfersResponse>()
        .await
        .unwrap()
        .transfers_changed
}

async fn fund_and_create_utxos(node_address: SocketAddr, num: Option<u8>) {
    println!("funding wallet for node {node_address}");
    let addr = address(node_address).await;

    _fund_wallet(addr);
    mine(false);

    create_utxos(node_address, false, Some(num.unwrap_or(10)), None).await;
    mine(false);
}

async fn get_asset_media(node_address: SocketAddr, digest: &str) -> String {
    println!("requesting media for digest {digest} from node {node_address}");
    let payload = GetAssetMediaRequest {
        digest: digest.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/getassetmedia", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<GetAssetMediaResponse>()
        .await
        .unwrap()
        .bytes_hex
}

async fn get_channel_id(node_address: SocketAddr, temp_chan_id: &str) -> String {
    println!("requesting channel ID for temporary ID {temp_chan_id} from node {node_address}");
    let payload = GetChannelIdRequest {
        temporary_channel_id: temp_chan_id.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/getchannelid", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<GetChannelIdResponse>()
        .await
        .unwrap()
        .channel_id
}

async fn invoice_status(node_address: SocketAddr, invoice: &str) -> InvoiceStatus {
    println!("getting status of invoice {invoice} for node {node_address}");
    let payload = InvoiceStatusRequest {
        invoice: invoice.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/invoicestatus", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<InvoiceStatusResponse>()
        .await
        .unwrap()
        .status
}

async fn issue_asset_cfa(node_address: SocketAddr, file_path: Option<&str>) -> AssetCFA {
    println!("issuing CFA asset on node {node_address}");
    let mut file_digest = None;
    if let Some(fp) = file_path {
        file_digest = Some(post_asset_media(node_address, fp).await);
    }
    let payload = IssueAssetCFARequest {
        amounts: vec![2000],
        name: s!("Collectible"),
        details: None,
        precision: 0,
        file_digest,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/issueassetcfa", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<IssueAssetCFAResponse>()
        .await
        .unwrap()
        .asset
}

async fn issue_asset_nia(node_address: SocketAddr) -> AssetNIA {
    println!("issuing NIA asset on node {node_address}");
    let payload = IssueAssetNIARequest {
        amounts: vec![1000],
        ticker: s!("USDT"),
        name: s!("Tether"),
        precision: 0,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/issueassetnia", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<IssueAssetNIAResponse>()
        .await
        .unwrap()
        .asset
}

async fn issue_asset_uda(node_address: SocketAddr, file_path: Option<&str>) -> AssetUDA {
    println!("issuing UDA asset on node {node_address}");
    let mut media_file_digest = None;
    if let Some(fp) = file_path {
        media_file_digest = Some(post_asset_media(node_address, fp).await);
    }
    let payload = IssueAssetUDARequest {
        ticker: s!("UNI"),
        name: s!("Unique"),
        details: None,
        precision: 0,
        media_file_digest,
        attachments_file_digests: vec![],
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/issueassetuda", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<IssueAssetUDAResponse>()
        .await
        .unwrap()
        .asset
}

async fn _with_ln_balance_checks(
    node_address: SocketAddr,
    counterparty_node_address: SocketAddr,
    asset_id: Option<String>,
    asset_amount: Option<u64>,
    initial_ln_balance_rgb: Option<u64>,
    counterparty_initial_ln_balance_rgb: Option<u64>,
    payment_hash: &str,
) {
    check_payment_status(node_address, payment_hash, HTLCStatus::Pending)
        .await
        .unwrap();

    if let Some(asset_id) = &asset_id {
        let final_ln_balance_rgb = initial_ln_balance_rgb.unwrap() - asset_amount.unwrap();
        wait_for_ln_balance(node_address, asset_id, final_ln_balance_rgb).await;
    }
    wait_for_ln_payment(node_address, payment_hash, HTLCStatus::Succeeded).await;
    if let Some(asset_id) = &asset_id {
        let counterparty_final_ln_balance =
            counterparty_initial_ln_balance_rgb.unwrap() + asset_amount.unwrap();
        wait_for_ln_balance(
            counterparty_node_address,
            asset_id,
            counterparty_final_ln_balance,
        )
        .await;
    }
    wait_for_ln_payment(
        counterparty_node_address,
        payment_hash,
        HTLCStatus::Succeeded,
    )
    .await;
}

async fn _keysend_raw(
    node_address: SocketAddr,
    dest_pubkey: &str,
    amt_msat: Option<u64>,
    asset_id: Option<&str>,
    asset_amount: Option<u64>,
) -> KeysendResponse {
    println!(
        "sending spontaneously {asset_amount:?} of asset {asset_id:?} from node {node_address} \
         to {dest_pubkey}"
    );
    let amt_msat = amt_msat.unwrap_or(3000000);
    let payload = KeysendRequest {
        dest_pubkey: dest_pubkey.to_string(),
        amt_msat,
        asset_id: asset_id.map(|a| a.to_string()),
        asset_amount,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/keysend", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<KeysendResponse>()
        .await
        .unwrap()
}

async fn keysend(
    node_address: SocketAddr,
    dest_pubkey: &str,
    amt_msat: Option<u64>,
    asset_id: Option<&str>,
    asset_amount: Option<u64>,
) -> Payment {
    let keysend = _keysend_raw(node_address, dest_pubkey, amt_msat, asset_id, asset_amount).await;
    wait_for_ln_payment(node_address, &keysend.payment_hash, HTLCStatus::Succeeded).await
}

#[allow(clippy::too_many_arguments)]
async fn keysend_with_ln_balance(
    node_address: SocketAddr,
    counterparty_node_address: SocketAddr,
    dest_pubkey: &str,
    amt_msat: Option<u64>,
    asset_id: Option<&str>,
    asset_amount: Option<u64>,
    initial_ln_balance_rgb: Option<u64>,
    counterparty_initial_ln_balance_rgb: Option<u64>,
) {
    let res = _keysend_raw(node_address, dest_pubkey, amt_msat, asset_id, asset_amount).await;

    _with_ln_balance_checks(
        node_address,
        counterparty_node_address,
        asset_id.map(|a| a.to_string()),
        asset_amount,
        initial_ln_balance_rgb,
        counterparty_initial_ln_balance_rgb,
        &res.payment_hash,
    )
    .await;
}

async fn list_assets(node_address: SocketAddr) -> ListAssetsResponse {
    println!("listing assets for node {node_address}");
    let payload = ListAssetsRequest {
        filter_asset_schemas: vec![],
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/listassets", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListAssetsResponse>()
        .await
        .unwrap()
}

async fn list_channels(node_address: SocketAddr) -> Vec<Channel> {
    println!("listing channels for node {node_address}");
    let res = reqwest::Client::new()
        .get(format!("http://{}/listchannels", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListChannelsResponse>()
        .await
        .unwrap()
        .channels
}

async fn list_payments(node_address: SocketAddr) -> Vec<Payment> {
    println!("listing payments for node {node_address}");
    let res = reqwest::Client::new()
        .get(format!("http://{}/listpayments", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListPaymentsResponse>()
        .await
        .unwrap()
        .payments
}
async fn get_payment(node_address: SocketAddr, payment_hash: &str) -> Payment {
    println!("getting payment for node {node_address}");
    let payload = GetPaymentRequest {
        payment_hash: payment_hash.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/getpayment", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<GetPaymentResponse>()
        .await
        .unwrap()
        .payment
}

async fn list_peers(node_address: SocketAddr) -> Vec<Peer> {
    println!("listing peers for node {node_address}");
    let res = reqwest::Client::new()
        .get(format!("http://{}/listpeers", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListPeersResponse>()
        .await
        .unwrap()
        .peers
}

async fn list_swaps(node_address: SocketAddr) -> ListSwapsResponse {
    println!("listing swaps for node {node_address}");
    let res = reqwest::Client::new()
        .get(format!("http://{}/listswaps", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res).await.json().await.unwrap()
}

async fn get_swap(node_address: SocketAddr, payment_hash: &str, taker: bool) -> Swap {
    println!("getting swap with payment hash {payment_hash} for node {node_address}");
    let payload = GetSwapRequest {
        payment_hash: payment_hash.to_string(),
        taker,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/getswap", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<GetSwapResponse>()
        .await
        .unwrap()
        .swap
}

async fn list_transactions(node_address: SocketAddr) -> Vec<Transaction> {
    println!("listing transactions for node {node_address}");
    let payload = ListTransactionsRequest { skip_sync: false };
    let res = reqwest::Client::new()
        .post(format!("http://{}/listtransactions", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListTransactionsResponse>()
        .await
        .unwrap()
        .transactions
}

async fn list_transfers(node_address: SocketAddr, asset_id: &str) -> Vec<Transfer> {
    println!("listing transfers for asset {asset_id} on node {node_address}");
    let payload = ListTransfersRequest {
        asset_id: asset_id.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/listtransfers", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListTransfersResponse>()
        .await
        .unwrap()
        .transfers
}

async fn list_unspents(node_address: SocketAddr) -> Vec<Unspent> {
    println!("listing unspents for node {node_address}");
    let payload = ListUnspentsRequest { skip_sync: false };
    let res = reqwest::Client::new()
        .post(format!("http://{}/listunspents", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListUnspentsResponse>()
        .await
        .unwrap()
        .unspents
}

async fn ln_invoice(
    node_address: SocketAddr,
    amt_msat: Option<u64>,
    asset_id: Option<&str>,
    asset_amount: Option<u64>,
    expiry_sec: u32,
) -> LNInvoiceResponse {
    println!(
        "generating invoice for {asset_amount:?} of asset {asset_id:?} for node {node_address}"
    );
    let payload = LNInvoiceRequest {
        amt_msat: Some(amt_msat.unwrap_or(3000000)),
        expiry_sec,
        asset_id: asset_id.map(|a| a.to_string()),
        asset_amount,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/lninvoice", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<LNInvoiceResponse>()
        .await
        .unwrap()
}

async fn lock(node_address: SocketAddr) {
    println!("locking node {node_address}");
    let res = reqwest::Client::new()
        .post(format!("http://{}/lock", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn maker_execute(
    node_address: SocketAddr,
    swapstring: String,
    payment_secret: String,
    taker_pubkey: String,
) {
    let res = maker_execute_raw(node_address, swapstring, payment_secret, taker_pubkey).await;
    let _ = _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await;
}

async fn maker_execute_raw(
    node_address: SocketAddr,
    swapstring: String,
    payment_secret: String,
    taker_pubkey: String,
) -> Response {
    println!("executing swap {swapstring} from node {node_address}");
    let payload = MakerExecuteRequest {
        swapstring,
        payment_secret,
        taker_pubkey,
    };
    reqwest::Client::new()
        .post(format!("http://{}/makerexecute", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
}

async fn maker_init(
    node_address: SocketAddr,
    qty_from: u64,
    from_asset: Option<&str>,
    qty_to: u64,
    to_asset: Option<&str>,
    timeout_sec: u32,
) -> MakerInitResponse {
    println!(
        "initializing swap from {qty_from} of {from_asset:?} \
        to {qty_to} of {to_asset:?} on node {node_address}"
    );
    let payload = MakerInitRequest {
        qty_from,
        qty_to,
        from_asset: from_asset.map(|a| a.into()),
        to_asset: to_asset.map(|a| a.into()),
        timeout_sec,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/makerinit", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<MakerInitResponse>()
        .await
        .unwrap()
}

async fn network_info(node_address: SocketAddr) -> NetworkInfoResponse {
    println!("getting network info for node {node_address}");
    let res = reqwest::Client::new()
        .get(format!("http://{}/networkinfo", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<NetworkInfoResponse>()
        .await
        .unwrap()
}

async fn node_info(node_address: SocketAddr) -> NodeInfoResponse {
    println!("getting node info for {node_address}");
    let res = reqwest::Client::new()
        .get(format!("http://{}/nodeinfo", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<NodeInfoResponse>()
        .await
        .unwrap()
}

async fn open_channel(
    node_address: SocketAddr,
    dest_peer_pubkey: &str,
    dest_peer_port: Option<u16>,
    capacity_sat: Option<u64>,
    push_msat: Option<u64>,
    asset_amount: Option<u64>,
    asset_id: Option<&str>,
) -> Channel {
    open_channel_with_custom_data(
        node_address,
        dest_peer_pubkey,
        dest_peer_port,
        capacity_sat,
        push_msat,
        asset_amount,
        asset_id,
        None,
        None,
        None,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn open_channel_with_custom_data(
    node_address: SocketAddr,
    dest_peer_pubkey: &str,
    dest_peer_port: Option<u16>,
    capacity_sat: Option<u64>,
    push_msat: Option<u64>,
    asset_amount: Option<u64>,
    asset_id: Option<&str>,
    fee_base_msat: Option<u32>,
    fee_proportional_millionths: Option<u32>,
    temporary_channel_id: Option<&str>,
    with_anchors: bool,
) -> Channel {
    println!(
        "opening channel with {asset_amount:?} of asset {asset_id:?} from node {node_address} \
              to {dest_peer_pubkey}"
    );
    stop_mining();
    let peer_pubkey_and_opt_addr = if let Some(p) = dest_peer_port {
        format!("{}@127.0.0.1:{}", dest_peer_pubkey, p)
    } else {
        dest_peer_pubkey.to_string()
    };
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr,
        capacity_sat: capacity_sat.unwrap_or(100_000),
        push_msat: push_msat.unwrap_or(0),
        asset_amount,
        asset_id: asset_id.map(|a| a.to_string()),
        public: true,
        with_anchors,
        fee_base_msat,
        fee_proportional_millionths,
        temporary_channel_id: temporary_channel_id.map(|t| t.to_string()),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<OpenChannelResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    let mut channel_id = None;
    let mut channel_funded = false;
    while !channel_funded {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node_address).await;
        if let Some(channel) = channels.iter().find(|c| {
            !c.ready
                && c.peer_pubkey == dest_peer_pubkey
                && c.asset_id == asset_id.map(|id| id.to_string())
                && c.asset_local_amount == asset_amount
        }) {
            if channel.funding_txid.is_some() {
                let txout = _get_txout(channel.funding_txid.as_ref().unwrap());
                if !txout.is_empty() {
                    mine_n_blocks(true, 6);
                    channel_id = Some(channel.channel_id.clone());
                    channel_funded = true;
                    continue;
                }
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 50.0 {
            panic!("cannot find funding TX")
        }
    }
    let channel_id = channel_id.unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node_address).await;
        let channel = channels
            .iter()
            .find(|c| c.channel_id == channel_id)
            .unwrap();
        if channel.ready {
            return channel.clone();
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("channel is taking too long to be ready")
        }
    }
}

async fn post_asset_media(node_address: SocketAddr, file_path: &str) -> String {
    println!("posting asset media on node {node_address}");
    let file_bytes = tokio::fs::read(file_path).await.unwrap();
    let form =
        reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(file_bytes));
    let res = reqwest::Client::new()
        .post(format!("http://{}/postassetmedia", node_address))
        .multipart(form)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<PostAssetMediaResponse>()
        .await
        .unwrap()
        .digest
}

async fn refresh_transfers(node_address: SocketAddr) {
    println!("refreshing transfers for node {node_address}");
    let payload = RefreshRequest { skip_sync: false };
    let res = reqwest::Client::new()
        .post(format!("http://{}/refreshtransfers", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn restore(node_address: SocketAddr, backup_path: &str, password: &str) {
    println!("restoring backup for node {node_address} from {backup_path}");
    let payload = RestoreRequest {
        backup_path: backup_path.to_string(),
        password: password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/restore", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn rgb_invoice(node_address: SocketAddr, asset_id: Option<String>) -> RgbInvoiceResponse {
    println!(
        "generating RGB invoice{} for node {node_address}",
        if let Some(id) = asset_id.as_ref() {
            format!(" for asset {}", id)
        } else {
            s!("")
        }
    );
    let payload = RgbInvoiceRequest {
        min_confirmations: 1,
        asset_id,
        duration_seconds: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/rgbinvoice", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<RgbInvoiceResponse>()
        .await
        .unwrap()
}

async fn send_asset(node_address: SocketAddr, asset_id: &str, amount: u64, recipient_id: String) {
    println!(
        "sending on-chain {amount} of asset {asset_id} from node {node_address} to {recipient_id}"
    );
    let payload = SendAssetRequest {
        asset_id: asset_id.to_string(),
        amount,
        recipient_id,
        donation: true,
        fee_rate: FEE_RATE,
        min_confirmations: 1,
        transport_endpoints: vec![PROXY_ENDPOINT_LOCAL.to_string()],
        skip_sync: false,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/sendasset", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<SendAssetResponse>()
        .await
        .unwrap();
}

async fn send_btc(node_address: SocketAddr, amount: u64, address: &str) -> String {
    println!("sending {amount} on-chain BTC from node {node_address} to address {address}");
    let payload = SendBtcRequest {
        amount,
        address: address.to_string(),
        fee_rate: FEE_RATE,
        skip_sync: false,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/sendbtc", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<SendBtcResponse>()
        .await
        .unwrap()
        .txid
}

async fn send_payment_raw(node_address: SocketAddr, invoice: String) -> SendPaymentResponse {
    println!("sending LN payment for invoice {invoice} from node {node_address}");
    let payload = SendPaymentRequest {
        invoice,
        amt_msat: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/sendpayment", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<SendPaymentResponse>()
        .await
        .unwrap()
}

async fn send_payment(node_address: SocketAddr, invoice: String) -> Payment {
    send_payment_with_status(node_address, invoice, HTLCStatus::Succeeded).await
}

async fn send_payment_with_ln_balance(
    node_address: SocketAddr,
    counterparty_node_address: SocketAddr,
    invoice: String,
    initial_ln_balance_rgb: Option<u64>,
    counterparty_initial_ln_balance_rgb: Option<u64>,
) {
    let bolt11_invoice = Bolt11Invoice::from_str(&invoice).unwrap();

    let res = send_payment_raw(node_address, invoice).await;

    _with_ln_balance_checks(
        node_address,
        counterparty_node_address,
        bolt11_invoice.rgb_contract_id().map(|c| c.to_string()),
        bolt11_invoice.rgb_amount(),
        initial_ln_balance_rgb,
        counterparty_initial_ln_balance_rgb,
        // TODO: remove unwrap once RGB offers are enabled
        &res.payment_hash.unwrap(),
    )
    .await;
}

async fn send_payment_with_status(
    node_address: SocketAddr,
    invoice: String,
    expected_status: HTLCStatus,
) -> Payment {
    let send_payment = send_payment_raw(node_address, invoice).await;
    wait_for_ln_payment(
        node_address,
        // TODO: remove unwrap once RGB offers are enabled
        &send_payment.payment_hash.unwrap(),
        expected_status,
    )
    .await
}

async fn shutdown(node_sockets: &[SocketAddr]) {
    // shutdown nodes
    for node_address in node_sockets {
        println!("shutting down node {node_address}");
        let res = reqwest::Client::new()
            .post(format!("http://{}/shutdown", node_address))
            .send()
            .await
            .unwrap();
        _check_response_is_ok(res).await;
    }
    // check node sockets have been released
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut all_sockets_available = true;
        let mut last_checked = node_sockets[0];
        for node_socket in node_sockets {
            last_checked = *node_socket;
            if TcpListener::bind(*node_socket).await.is_err() {
                all_sockets_available = false;
            }
        }
        if all_sockets_available {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("node sockets not becoming available (last checked: {last_checked})")
        }
    }
}

async fn taker(node_address: SocketAddr, swapstring: String) -> EmptyResponse {
    println!("taking swap {swapstring} on node {node_address}");
    let payload = TakerRequest { swapstring };
    let res = reqwest::Client::new()
        .post(format!("http://{}/taker", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap()
}

async fn unlock_res(node_address: SocketAddr, password: &str) -> Response {
    println!("unlocking node {node_address}");
    let payload = UnlockRequest {
        password: password.to_string(),
        bitcoind_rpc_username: s!("user"),
        bitcoind_rpc_password: s!("password"),
        bitcoind_rpc_host: s!("localhost"),
        bitcoind_rpc_port: 18443,
        indexer_url: Some(ELECTRUM_URL_REGTEST.to_string()),
        proxy_endpoint: Some(PROXY_ENDPOINT_LOCAL.to_string()),
        announce_addresses: vec![],
        announce_alias: Some(s!("RLN_alias")),
    };
    reqwest::Client::new()
        .post(format!("http://{}/unlock", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
}

async fn unlock(node_address: SocketAddr, password: &str) {
    println!("unlocking node {node_address}");
    let res = unlock_res(node_address, password).await;
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn wait_for_balance(node_address: SocketAddr, asset_id: &str, expected_balance: u64) {
    println!(
        "waiting for balance of asset {asset_id} to become {expected_balance} \
              on node {node_address}"
    );
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let balance = asset_balance_spendable(node_address, asset_id).await;
        if balance == expected_balance {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 70.0 {
            panic!("balance ({balance}) is not becoming the expected one ({expected_balance})");
        }
        refresh_transfers(node_address).await;
    }
}

async fn wait_for_ln_balance(node_address: SocketAddr, asset_id: &str, expected_balance: u64) {
    println!(
        "waiting for LN balance for asset {asset_id} to become {expected_balance} \
              on node {node_address}"
    );
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let balance = asset_balance_offchain_outbound(node_address, asset_id).await;
        if balance == expected_balance {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 70.0 {
            panic!("balance ({balance}) is not becoming the expected one ({expected_balance})");
        }
    }
}

async fn wait_for_usable_channels(node_address: SocketAddr, expected_num_usable_channels: usize) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let node_info = node_info(node_address).await;
        let num_usable_channels = node_info.num_usable_channels;
        if num_usable_channels == expected_num_usable_channels {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!(
                "num of usable channels ({num_usable_channels:?}) is not becoming the expected \
                one ({expected_num_usable_channels:?})"
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn wait_for_ln_payment(
    node_address: SocketAddr,
    payment_hash: &str,
    expected_status: HTLCStatus,
) -> Payment {
    println!(
        "waiting for LN payment {payment_hash} to become {expected_status:?} on node {node_address}"
    );
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Some(payment) =
            check_payment_status(node_address, payment_hash, expected_status).await
        {
            return payment;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 40.0 {
            panic!("cannot find payment in status {expected_status}")
        }
    }
}

async fn wait_for_swap_status(
    node_address: SocketAddr,
    payment_hash: &str,
    expected_status: SwapStatus,
) {
    println!(
        "waiting for status for swap with payment hash {payment_hash} to become \
        {expected_status:?} on node {node_address}",
    );
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let swaps = list_swaps(node_address).await;
        let swap = swaps
            .maker
            .iter()
            .chain(swaps.taker.iter())
            .find(|s| s.payment_hash == payment_hash)
            .unwrap();
        let status = &swap.status;
        if status == &expected_status {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 70.0 {
            panic!("status ({status:?}) is not becoming the expected one ({expected_status:?})");
        }
        tokio::time::sleep(std::time::Duration::from_secs_f32(0.5)).await;
    }
}

#[derive(Clone, Debug)]
struct Miner {
    no_mine_count: u32,
}

impl Miner {
    fn mine(&self, num_blocks: u16) -> bool {
        if self.no_mine_count > 0 {
            return false;
        }
        let status = Command::new("docker")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg("compose")
            .args(_bitcoin_cli())
            .arg("-rpcwallet=miner")
            .arg("-generate")
            .arg(num_blocks.to_string())
            .status()
            .expect("failed to mine");
        assert!(status.success());
        true
    }

    fn stop_mining(&mut self) {
        self.no_mine_count += 1;
    }

    fn resume_mining(&mut self) {
        if self.no_mine_count > 0 {
            self.no_mine_count -= 1;
        }
    }
}

fn mine(resume: bool) {
    mine_n_blocks(resume, 1)
}

fn mine_n_blocks(resume: bool, num_blocks: u16) {
    let t_0 = OffsetDateTime::now_utc();
    if resume {
        resume_mining();
    }
    let mut last_result = false;
    while !last_result {
        let miner = MINER.read();
        last_result = miner
            .as_ref()
            .expect("MINER has been initialized")
            .mine(num_blocks);
        drop(miner);
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 120.0 {
            eprintln!("forcibly breaking mining wait");
            resume_mining();
        }
        if !last_result {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    wait_electrs_sync();
}

fn stop_mining() {
    MINER
        .write()
        .expect("MINER has been initialized")
        .stop_mining()
}

fn resume_mining() {
    MINER
        .write()
        .expect("MINER has been initialized")
        .resume_mining()
}

fn wait_electrs_sync() {
    let t_0 = OffsetDateTime::now_utc();
    let output = Command::new("docker")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .arg("compose")
        .args(_bitcoin_cli())
        .arg("getblockcount")
        .output()
        .expect("failed to call getblockcount");
    assert!(output.status.success());
    let blockcount_str =
        std::str::from_utf8(&output.stdout).expect("could not parse blockcount output");
    let blockcount = blockcount_str
        .trim()
        .parse::<u32>()
        .expect("could not parse blockcount");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut all_synced = true;
        let electrum =
            electrum_client::Client::new(ELECTRUM_URL).expect("cannot get electrum client");
        if electrum.block_header(blockcount as usize).is_err() {
            all_synced = false;
        }
        if all_synced {
            break;
        };
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("electrs not syncing with bitcoind");
        }
    }
}

pub(crate) fn initialize() {
    INIT.call_once(|| {
        if std::env::var("SKIP_INIT").is_ok() {
            println!("skipping services initialization");
            return;
        }
        println!("starting test services...");
        let output = Command::new("./regtest.sh")
            .args(["start"])
            .output()
            .expect("failed to start test services");
        if !output.status.success() {
            println!("{output:?}");
            panic!("failed to start test services");
        }
    });
}

lazy_static! {
    static ref MOCK_FEE: Mutex<Option<u32>> = Mutex::new(None);
}

pub fn mock_fee(fee: u32) -> u32 {
    let mock = MOCK_FEE.lock().unwrap().take();
    if let Some(fee) = mock {
        println!("mocking fee");
        fee
    } else {
        fee
    }
}

mod asset_id_hex_bytes;
mod backup_and_restore;
mod close_coop_nobtc_acceptor;
mod close_coop_other_side;
mod close_coop_standard;
mod close_coop_vanilla;
mod close_coop_zero_balance;
mod close_force_nobtc_acceptor;
mod close_force_other_side;
mod close_force_standard;
mod concurrent_btc_payments;
mod fail_transfers;
mod getchannelid;
mod htlc_amount_checks;
mod invoice;
mod issue;
mod lock_unlock_changepassword;
mod multi_hop;
mod multi_open_close;
mod open_after_double_send;
mod openchannel_fail;
mod openchannel_optional_addr;
mod payment;
mod refuse_high_fees;
mod restart;
mod send_receive;
mod swap_reverse_same_channel;
mod swap_roundtrip_assets;
mod swap_roundtrip_buy;
mod swap_roundtrip_buy_same_channel;
mod swap_roundtrip_fail_amount_maker;
mod swap_roundtrip_fail_amount_taker;
mod swap_roundtrip_fail_btc2btc;
mod swap_roundtrip_fail_invalid_asset_from;
mod swap_roundtrip_fail_invalid_asset_to;
mod swap_roundtrip_fail_same_asset;
mod swap_roundtrip_fail_timeout;
mod swap_roundtrip_fail_whitelist;
mod swap_roundtrip_multihop_asset_asset;
mod swap_roundtrip_multihop_buy;
mod swap_roundtrip_multihop_sell;
mod swap_roundtrip_sell;
mod upload_asset_media;
mod vanilla_payment_on_rgb_channel;
