use amplify::s;
use once_cell::sync::Lazy;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Once, RwLock};
use time::OffsetDateTime;

use crate::routes::{
    AddressResponse, AssetBalanceRequest, AssetBalanceResponse, Channel, CloseChannelRequest,
    EmptyResponse, HTLCStatus, IssueAssetRequest, IssueAssetResponse, KeysendRequest,
    KeysendResponse, ListChannelsResponse, ListPaymentsResponse, NodeInfoResponse,
    OpenChannelRequest, OpenChannelResponse, Payment, RgbInvoiceResponse, SendAssetRequest,
    SendAssetResponse,
};

use super::*;

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

fn start_node(node_test_dir: String, node_peer_port: u16) -> SocketAddr {
    let listener = TcpListener::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).unwrap();
    let node_address = listener.local_addr().unwrap();
    if Path::new(&node_test_dir).is_dir() {
        std::fs::remove_dir_all(node_test_dir.clone()).unwrap();
    }
    std::fs::create_dir_all(node_test_dir.clone()).unwrap();
    let args = LdkUserInfo {
        storage_dir_path: node_test_dir,
        ldk_peer_listening_port: node_peer_port,
        ..Default::default()
    };
    tokio::spawn(async move {
        let (router, _ldk_background_services) = app(args).await.unwrap();
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(router.into_make_service())
            .await
            .unwrap();
    });
    node_address
}

async fn asset_balance(node_address: SocketAddr, asset_id: &str) -> u64 {
    let payload = AssetBalanceRequest {
        asset_id: asset_id.to_string(),
    };
    reqwest::Client::new()
        .post(format!("http://{}/assetbalance", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<AssetBalanceResponse>()
        .await
        .unwrap()
        .amount
}

async fn close_channel(node_address: SocketAddr, channel_id: &str, peer_pubkey: &str, force: bool) {
    let payload = CloseChannelRequest {
        channel_id: channel_id.to_string(),
        peer_pubkey: peer_pubkey.to_string(),
        force,
    };
    reqwest::Client::new()
        .post(format!("http://{}/closechannel", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<EmptyResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let channels = list_channels(node_address).await;
        if channels
            .iter()
            .find(|c| c.channel_id == channel_id)
            .is_none()
        {
            mine_n_blocks(true, 6);
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("channel is taking too long to close")
        }
    }
}

async fn fund_and_create_utxos(node_address: SocketAddr) {
    let address = reqwest::Client::new()
        .post(format!("http://{}/address", node_address))
        .send()
        .await
        .unwrap()
        .json::<AddressResponse>()
        .await
        .unwrap()
        .address;

    fund_wallet(address.to_string());

    mine(false);

    reqwest::Client::new()
        .post(format!("http://{}/createutxos", node_address))
        .send()
        .await
        .unwrap()
        .json::<EmptyResponse>()
        .await
        .unwrap();

    mine(false);
}

async fn issue_asset(node_address: SocketAddr) -> String {
    let payload = IssueAssetRequest {
        amount: 1000,
        ticker: s!("USDT"),
        name: s!("Tether"),
        precision: 0,
    };
    reqwest::Client::new()
        .post(format!("http://{}/issueasset", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<IssueAssetResponse>()
        .await
        .unwrap()
        .asset_id
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
    let keysend = reqwest::Client::new()
        .post(format!("http://{}/keysend", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<KeysendResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
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
    reqwest::Client::new()
        .get(format!("http://{}/nodeinfo", node_address))
        .send()
        .await
        .unwrap()
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
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", dest_peer_pubkey, dest_peer_port),
        capacity_sat: 30010,
        push_msat: 1394000,
        asset_amount,
        asset_id: asset_id.to_string(),
        public: true,
    };
    reqwest::Client::new()
        .post(format!("http://{}/openchannel", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<OpenChannelResponse>()
        .await
        .unwrap();

    let t_0 = OffsetDateTime::now_utc();
    let mut channel_id = None;
    let mut channel_funded = false;
    while !channel_funded {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let channels = list_channels(node_address).await;
        if let Some(channel) = channels.iter().find(|c| c.peer_pubkey == dest_peer_pubkey) {
            if channel.funding_txid.is_some() {
                let txout = get_txout(&channel.funding_txid.as_ref().unwrap());
                if !txout.is_empty() {
                    mine_n_blocks(true, 6);
                    channel_id = Some(channel.channel_id.clone());
                    channel_funded = true;
                    continue;
                }
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
            panic!("cannot find funding TX")
        }
    }
    let channel_id = channel_id.unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
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

async fn list_channels(node_address: SocketAddr) -> Vec<Channel> {
    reqwest::Client::new()
        .get(format!("http://{}/listchannels", node_address))
        .send()
        .await
        .unwrap()
        .json::<ListChannelsResponse>()
        .await
        .unwrap()
        .channels
}

async fn list_payments(node_address: SocketAddr) -> Vec<Payment> {
    reqwest::Client::new()
        .get(format!("http://{}/listpayments", node_address))
        .send()
        .await
        .unwrap()
        .json::<ListPaymentsResponse>()
        .await
        .unwrap()
        .payments
}

async fn rgb_invoice(node_address: SocketAddr) -> String {
    reqwest::Client::new()
        .post(format!("http://{}/rgbinvoice", node_address))
        .send()
        .await
        .unwrap()
        .json::<RgbInvoiceResponse>()
        .await
        .unwrap()
        .blinded_utxo
}

async fn refresh_transfers(node_address: SocketAddr) {
    reqwest::Client::new()
        .post(format!("http://{}/refreshtransfers", node_address))
        .send()
        .await
        .unwrap()
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

async fn send_asset(node_address: SocketAddr, asset_id: &str, amount: u64, blinded_utxo: String) {
    let payload = SendAssetRequest {
        asset_id: asset_id.to_string(),
        amount,
        blinded_utxo,
    };
    reqwest::Client::new()
        .post(format!("http://{}/sendasset", node_address))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<SendAssetResponse>()
        .await
        .unwrap();
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

mod close_coop;
