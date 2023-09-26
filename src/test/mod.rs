use amplify::s;
use bitcoin::Network;
use electrum_client::ElectrumApi;
use once_cell::sync::Lazy;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Once, RwLock};
use time::OffsetDateTime;
use tracing_test::traced_test;

use crate::routes::{
    AddressResponse, Asset, AssetBalanceRequest, AssetBalanceResponse, BackupRequest, Channel,
    CloseChannelRequest, ConnectPeerRequest, CreateUtxosRequest, DecodeLNInvoiceRequest,
    DecodeLNInvoiceResponse, DisconnectPeerRequest, EmptyResponse, HTLCStatus, InitRequest,
    InitResponse, InvoiceStatus, InvoiceStatusRequest, InvoiceStatusResponse, IssueAssetRequest,
    IssueAssetResponse, KeysendRequest, KeysendResponse, LNInvoiceRequest, LNInvoiceResponse,
    ListAssetsResponse, ListChannelsResponse, ListPaymentsResponse, ListPeersResponse,
    ListUnspentsResponse, NodeInfoResponse, OpenChannelRequest, OpenChannelResponse, Payment, Peer,
    RestoreRequest, RgbInvoiceRequest, RgbInvoiceResponse, SendAssetRequest, SendAssetResponse,
    SendPaymentRequest, SendPaymentResponse, UnlockRequest, Unspent,
};

use super::*;

const ELECTRUM_URL: &str = "127.0.0.1:50001";

static INIT: Once = Once::new();

static MINER: Lazy<RwLock<Miner>> = Lazy::new(|| RwLock::new(Miner { no_mine_count: 0 }));

#[cfg(test)]
impl Default for LdkUserInfo {
    fn default() -> Self {
        Self {
            bitcoind_rpc_username: s!("user"),
            bitcoind_rpc_password: s!("password"),
            bitcoind_rpc_host: s!("localhost"),
            bitcoind_rpc_port: 18443,
            ldk_announced_listen_addr: vec![],
            ldk_announced_node_name: [0; 32],
            network: Network::Regtest,
            storage_dir_path: s!("tmp/test_name/nodeN"),
            daemon_listening_port: 3001,
            ldk_peer_listening_port: 9735,
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

async fn _check_response_is_ok(res: reqwest::Response) -> reqwest::Response {
    if res.status() != reqwest::StatusCode::OK {
        panic!("reqwest response is not OK: {:?}", res.text().await);
    }
    res
}

fn fund_wallet(address: String) {
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

fn get_txout(txid: &str) -> String {
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

fn get_ldk_sockets(peer_ports: &[u16]) -> Vec<SocketAddr> {
    peer_ports
        .iter()
        .map(|p| {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                *p,
            )
        })
        .collect::<Vec<SocketAddr>>()
}

async fn start_daemon(node_test_dir: &str, node_peer_port: u16) -> SocketAddr {
    let listener = TcpListener::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).unwrap();
    let node_address = listener.local_addr().unwrap();
    std::fs::create_dir_all(node_test_dir.clone()).unwrap();
    let args = LdkUserInfo {
        storage_dir_path: node_test_dir.to_string(),
        ldk_peer_listening_port: node_peer_port,
        ..Default::default()
    };
    tokio::spawn(async move {
        let (router, app_state) = app(args).await.unwrap();
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(router.into_make_service())
            .with_graceful_shutdown(shutdown_signal(app_state))
            .await
            .unwrap();
    });
    node_address
}

async fn start_node(
    node_test_dir: String,
    node_peer_port: u16,
    keep_node_dir: bool,
) -> (SocketAddr, String) {
    if !keep_node_dir && Path::new(&node_test_dir).is_dir() {
        std::fs::remove_dir_all(node_test_dir.clone()).unwrap();
    }
    let node_address = start_daemon(&node_test_dir, node_peer_port).await;

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

    unlock(node_address, password.clone()).await;

    (node_address, password)
}

async fn asset_balance(node_address: SocketAddr, asset_id: &str) -> u64 {
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
        .spendable
}

async fn backup(node_address: SocketAddr, backup_path: &str, password: &str) {
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

async fn connect_peer(node_address: SocketAddr, peer_pubkey: &str, peer_addr: &str) {
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

async fn close_channel(node_address: SocketAddr, channel_id: &str, peer_pubkey: &str, force: bool) {
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

async fn decode_ln_invoice(node_address: SocketAddr, invoice: &str) -> DecodeLNInvoiceResponse {
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

async fn disconnect_peer(node_address: SocketAddr, peer_pubkey: &str) {
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

async fn fund_and_create_utxos(node_address: SocketAddr) {
    let res = reqwest::Client::new()
        .post(format!("http://{}/address", node_address))
        .send()
        .await
        .unwrap();
    let address = _check_response_is_ok(res)
        .await
        .json::<AddressResponse>()
        .await
        .unwrap()
        .address;

    fund_wallet(address.to_string());

    mine(false);

    let payload = CreateUtxosRequest { up_to: false };
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

    mine(false);
}

async fn invoice_status(node_address: SocketAddr, invoice: &str) -> InvoiceStatus {
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

async fn issue_asset(node_address: SocketAddr) -> String {
    let payload = IssueAssetRequest {
        amounts: vec![1000],
        ticker: s!("USDT"),
        name: s!("Tether"),
        precision: 0,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/issueasset", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<IssueAssetResponse>()
        .await
        .unwrap()
        .asset_id
}

async fn list_peers(node_address: SocketAddr) -> Vec<Peer> {
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

async fn ln_invoice(
    node_address: SocketAddr,
    asset_id: &str,
    asset_amount: u64,
    expiry_sec: u32,
) -> LNInvoiceResponse {
    let payload = LNInvoiceRequest {
        amt_msat: Some(3000000),
        expiry_sec,
        asset_id: Some(asset_id.to_string()),
        asset_amount: Some(asset_amount),
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

async fn keysend(
    node_address: SocketAddr,
    dest_pubkey: &str,
    asset_id: &str,
    asset_amount: u64,
) -> Payment {
    let payload = KeysendRequest {
        dest_pubkey: dest_pubkey.to_string(),
        amt_msat: 3000000,
        asset_id: asset_id.to_string(),
        asset_amount,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/keysend", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let keysend = _check_response_is_ok(res)
        .await
        .json::<KeysendResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let payments = list_payments(node_address).await;
        if let Some(payment) = payments
            .iter()
            .find(|p| p.payment_hash == keysend.payment_hash)
        {
            if matches!(payment.status, HTLCStatus::Succeeded) {
                return payment.clone();
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find successful payment")
        }
    }
}

async fn node_info(node_address: SocketAddr) -> NodeInfoResponse {
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
    dest_peer_port: u16,
    asset_amount: u64,
    asset_id: &str,
) -> Channel {
    stop_mining();
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", dest_peer_pubkey, dest_peer_port),
        capacity_sat: 30010,
        push_msat: 2130000,
        asset_amount,
        asset_id: asset_id.to_string(),
        public: true,
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
        if let Some(channel) = channels.iter().find(|c| c.peer_pubkey == dest_peer_pubkey) {
            if channel.funding_txid.is_some() {
                let txout = get_txout(channel.funding_txid.as_ref().unwrap());
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

async fn list_assets(node_address: SocketAddr) -> Vec<Asset> {
    let res = reqwest::Client::new()
        .get(format!("http://{}/listassets", node_address))
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<ListAssetsResponse>()
        .await
        .unwrap()
        .assets
}

async fn list_channels(node_address: SocketAddr) -> Vec<Channel> {
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

async fn list_unspents(node_address: SocketAddr) -> Vec<Unspent> {
    let res = reqwest::Client::new()
        .get(format!("http://{}/listunspents", node_address))
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

async fn lock(node_address: SocketAddr) {
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

async fn rgb_invoice(node_address: SocketAddr) -> String {
    let payload = RgbInvoiceRequest {
        min_confirmations: 1,
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
        .recipient_id
}

async fn refresh_transfers(node_address: SocketAddr) {
    let res = reqwest::Client::new()
        .post(format!("http://{}/refreshtransfers", node_address))
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

async fn send_asset(node_address: SocketAddr, asset_id: &str, amount: u64, blinded_utxo: String) {
    let payload = SendAssetRequest {
        asset_id: asset_id.to_string(),
        amount,
        blinded_utxo,
        donation: true,
        min_confirmations: 1,
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

async fn send_payment(node_address: SocketAddr, invoice: String) -> Payment {
    let payload = SendPaymentRequest { invoice };
    let res = reqwest::Client::new()
        .post(format!("http://{}/sendpayment", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let send_payment = _check_response_is_ok(res)
        .await
        .json::<SendPaymentResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let payments = list_payments(node_address).await;
        if let Some(payment) = payments
            .iter()
            .find(|p| p.payment_hash == send_payment.payment_hash)
        {
            if matches!(payment.status, HTLCStatus::Succeeded) {
                return payment.clone();
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find successful payment")
        }
    }
}

async fn unlock(node_address: SocketAddr, password: String) {
    let payload = UnlockRequest { password };
    let res = reqwest::Client::new()
        .post(format!("http://{}/unlock", node_address))
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

async fn wait_for_balance(node_address: SocketAddr, asset_id: &str, expected_balance: u64) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if asset_balance(node_address, asset_id).await == expected_balance {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("balance is not becoming the expected one");
        }
    }
}

async fn shutdown(node_sockets: &[SocketAddr], ldk_sockets: &[SocketAddr]) {
    // shutdown nodes
    for node_address in node_sockets {
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
            if TcpListener::bind(*node_socket).is_err() {
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
    // connect to LDK peer ports so they can stop listening
    for ldk_socket in ldk_sockets {
        let _ = std::net::TcpStream::connect(ldk_socket);
    }
    // check LDK sockets have been released
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut all_sockets_available = true;
        let mut last_checked = ldk_sockets[0];
        for ldk_socket in ldk_sockets {
            last_checked = *ldk_socket;
            if TcpListener::bind(*ldk_socket).is_err() {
                all_sockets_available = false;
            }
        }
        if all_sockets_available {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("LDK sockets not becoming available (last checked: {last_checked})")
        }
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

pub fn initialize() {
    INIT.call_once(|| {
        println!("starting test services...");
        let status = Command::new("./regtest.sh")
            .args(["start"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to start test services");
        assert!(status.success());
    });
}

mod backup_and_restore;
mod close_coop_nobtc_acceptor;
mod close_coop_other_side;
mod close_coop_standard;
mod close_coop_zero_balance;
mod close_force_nobtc_acceptor;
mod close_force_other_side;
mod close_force_standard;
mod multi_hop;
mod multi_open_close;
mod open_after_double_send;
mod payment;
mod restart;
mod send_receive;
