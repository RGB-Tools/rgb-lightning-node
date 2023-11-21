use amplify::s;
use bdk::keys::bip39::Mnemonic;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use futures::Future;
use lightning::ln::channelmanager::ChannelDetails;
use lightning::ln::msgs::SocketAddress;
use lightning::rgb_utils::{get_rgb_channel_info, BITCOIN_NETWORK_FNAME, ELECTRUM_URL_FNAME};
use lightning::routing::router::{
    Payee, PaymentParameters, Route, RouteHint, RouteParameters, Router as _,
    DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
};
use lightning::{
    onion_message::OnionMessageContents,
    sign::KeysManager,
    util::ser::{Writeable, Writer},
};
use lightning_persister::fs_store::FilesystemStore;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use reqwest::Client as RestClient;
use rgb_core::ContractId;
use rgb_lib::wallet::{Online, Wallet as RgbLibWallet};
use std::{
    fmt::Write,
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};
use tokio::sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard};
use tokio_util::sync::CancellationToken;

use crate::ldk::Router;
use crate::routes::{DEFAULT_FINAL_CLTV_EXPIRY_DELTA, HTLC_MIN_MSAT};
use crate::{
    args::LdkUserInfo,
    bitcoind::BitcoindClient,
    disk::FilesystemLogger,
    error::{APIError, AppError},
    ldk::{
        BumpTxEventHandler, ChannelManager, InboundPaymentInfoStorage, LdkBackgroundServices,
        NetworkGraph, OnionMessenger, OutboundPaymentInfoStorage, PeerManager, TradeMap,
    },
    rgb::get_bitcoin_network,
};

pub(crate) const LOGS_DIR: &str = "logs";
const ELECTRUM_URL_REGTEST: &str = "127.0.0.1:50001";
const ELECTRUM_URL_TESTNET: &str = "ssl://electrum.iriswallet.com:50013";
pub(crate) const PROXY_ENDPOINT_REGTEST: &str = "rpc://127.0.0.1:3000/json-rpc";
const PROXY_URL_REGTEST: &str = "http://127.0.0.1:3000/json-rpc";
const PROXY_ENDPOINT_TESTNET: &str = "rpcs://proxy.iriswallet.com/0.2/json-rpc";
const PROXY_URL_TESTNET: &str = "https://proxy.iriswallet.com/0.2/json-rpc";
const PROXY_TIMEOUT: u8 = 90;
const PASSWORD_MIN_LENGTH: u8 = 8;

pub(crate) struct AppState {
    pub(crate) static_state: Arc<StaticState>,
    pub(crate) cancel_token: CancellationToken,
    pub(crate) unlocked_app_state: Arc<TokioMutex<Option<Arc<UnlockedAppState>>>>,
    pub(crate) ldk_background_services: Arc<Mutex<Option<LdkBackgroundServices>>>,
    pub(crate) changing_state: Mutex<bool>,
}

impl AppState {
    pub(crate) fn get_changing_state(&self) -> MutexGuard<bool> {
        self.changing_state.lock().unwrap()
    }

    pub(crate) fn get_ldk_background_services(&self) -> MutexGuard<Option<LdkBackgroundServices>> {
        self.ldk_background_services.lock().unwrap()
    }

    pub(crate) async fn get_unlocked_app_state(
        &self,
    ) -> TokioMutexGuard<Option<Arc<UnlockedAppState>>> {
        self.unlocked_app_state.lock().await
    }
}

pub(crate) struct StaticState {
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) ldk_announced_listen_addr: Vec<SocketAddress>,
    pub(crate) ldk_announced_node_name: [u8; 32],
    pub(crate) network: Network,
    pub(crate) storage_dir_path: String,
    pub(crate) ldk_data_dir: String,
    pub(crate) logger: Arc<FilesystemLogger>,
    pub(crate) electrum_url: String,
    pub(crate) proxy_endpoint: String,
    pub(crate) proxy_url: String,
    pub(crate) proxy_client: Arc<RestClient>,
    pub(crate) bitcoind_client: Arc<BitcoindClient>,
}

pub(crate) struct UnlockedAppState {
    pub(crate) channel_manager: Arc<ChannelManager>,
    pub(crate) inbound_payments: Arc<Mutex<InboundPaymentInfoStorage>>,
    pub(crate) keys_manager: Arc<KeysManager>,
    pub(crate) network_graph: Arc<NetworkGraph>,
    pub(crate) onion_messenger: Arc<OnionMessenger>,
    pub(crate) outbound_payments: Arc<Mutex<OutboundPaymentInfoStorage>>,
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) fs_store: Arc<FilesystemStore>,
    pub(crate) persister: Arc<FilesystemStore>,
    pub(crate) bump_tx_event_handler: Arc<BumpTxEventHandler>,
    pub(crate) maker_trades: Arc<Mutex<TradeMap>>,
    pub(crate) taker_trades: Arc<Mutex<TradeMap>>,
    pub(crate) rgb_wallet: Arc<Mutex<RgbLibWallet>>,
    pub(crate) rgb_online: Online,
    pub(crate) router: Arc<Router>,
}

impl UnlockedAppState {
    pub(crate) fn get_inbound_payments(&self) -> MutexGuard<InboundPaymentInfoStorage> {
        self.inbound_payments.lock().unwrap()
    }

    pub(crate) fn get_outbound_payments(&self) -> MutexGuard<OutboundPaymentInfoStorage> {
        self.outbound_payments.lock().unwrap()
    }

    pub(crate) fn get_maker_trades(&self) -> MutexGuard<TradeMap> {
        self.maker_trades.lock().unwrap()
    }

    pub(crate) fn get_taker_trades(&self) -> MutexGuard<TradeMap> {
        self.taker_trades.lock().unwrap()
    }

    pub(crate) fn get_rgb_wallet(&self) -> MutexGuard<RgbLibWallet> {
        self.rgb_wallet.lock().unwrap()
    }
}

pub(crate) struct UserOnionMessageContents {
    pub(crate) tlv_type: u64,
    pub(crate) data: Vec<u8>,
}

impl OnionMessageContents for UserOnionMessageContents {
    fn tlv_type(&self) -> u64 {
        self.tlv_type
    }
}

impl Writeable for UserOnionMessageContents {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(&self.data)
    }
}

pub(crate) fn check_already_initialized(mnemonic_path: &str) -> Result<(), APIError> {
    if Path::new(&mnemonic_path).exists() {
        return Err(APIError::AlreadyInitialized);
    }
    Ok(())
}

pub(crate) fn check_password_strength(password: String) -> Result<(), APIError> {
    if password.len() < PASSWORD_MIN_LENGTH as usize {
        return Err(APIError::InvalidPassword(format!(
            "must have at least {PASSWORD_MIN_LENGTH} chars"
        )));
    }
    Ok(())
}

pub(crate) fn check_password_validity(
    password: &str,
    storage_dir_path: &str,
) -> Result<Mnemonic, APIError> {
    let mnemonic_path = get_mnemonic_path(storage_dir_path);
    if let Ok(encrypted_mnemonic) = fs::read_to_string(mnemonic_path) {
        let mcrypt = new_magic_crypt!(password, 256);
        let mnemonic_str = mcrypt
            .decrypt_base64_to_string(encrypted_mnemonic)
            .map_err(|_| APIError::WrongPassword)?;
        Ok(Mnemonic::from_str(&mnemonic_str).expect("valid mnemonic"))
    } else {
        Err(APIError::NotInitialized)
    }
}

pub(crate) fn get_mnemonic_path(storage_dir_path: &str) -> String {
    format!("{}/mnemonic", storage_dir_path)
}

pub(crate) fn encrypt_and_save_mnemonic(
    password: String,
    mnemonic: String,
    mnemonic_path: String,
) -> Result<(), APIError> {
    let mcrypt = new_magic_crypt!(password, 256);
    let encrypted_mnemonic = mcrypt.encrypt_str_to_base64(mnemonic);
    match fs::write(mnemonic_path.clone(), encrypted_mnemonic) {
        Ok(()) => {
            tracing::info!("Created a new wallet");
            Ok(())
        }
        Err(e) => Err(APIError::FailedKeysCreation(mnemonic_path, e.to_string())),
    }
}

pub(crate) async fn connect_peer_if_necessary(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), APIError> {
    for (node_pubkey, _) in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(());
        }
    }
    do_connect_peer(pubkey, peer_addr, peer_manager).await?;
    Ok(())
}

pub(crate) async fn do_connect_peer(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), APIError> {
    match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr).await
    {
        Some(connection_closed_future) => {
            let mut connection_closed_future = Box::pin(connection_closed_future);
            loop {
                tokio::select! {
                    _ = &mut connection_closed_future => return Err(APIError::FailedPeerConnection),
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                };
                if peer_manager
                    .get_peer_node_ids()
                    .iter()
                    .any(|(id, _)| *id == pubkey)
                {
                    return Ok(());
                }
            }
        }
        None => Err(APIError::FailedPeerConnection),
    }
}

#[inline]
pub(crate) fn hex_str(value: &[u8]) -> String {
    let mut res = String::with_capacity(2 * value.len());
    for v in value {
        write!(&mut res, "{:02x}", v).expect("Unable to write");
    }
    res
}

pub(crate) fn hex_str_to_compressed_pubkey(hex: &str) -> Option<PublicKey> {
    if hex.len() != 33 * 2 {
        return None;
    }
    let data = match hex_str_to_vec(&hex[0..33 * 2]) {
        Some(bytes) => bytes,
        None => return None,
    };
    match PublicKey::from_slice(&data) {
        Ok(pk) => Some(pk),
        Err(_) => None,
    }
}

pub(crate) fn hex_str_to_vec(hex: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(hex.len() / 2);

    let mut b = 0;
    for (idx, c) in hex.as_bytes().iter().enumerate() {
        b <<= 4;
        match *c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return None,
        }
        if (idx & 1) == 1 {
            out.push(b);
            b = 0;
        }
    }

    Some(out)
}

pub(crate) async fn no_cancel<Fut>(fut: Fut) -> Fut::Output
where
    Fut: 'static + Future + Send,
    Fut::Output: Send,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = fut.await;
        let _ = tx.send(result);
    });
    rx.await.unwrap()
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), APIError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next();
    let peer_addr_str = pubkey_and_addr.next();
    if peer_addr_str.is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`"
        )));
    }

    let peer_addr = peer_addr_str
        .unwrap()
        .to_socket_addrs()
        .map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "couldn't parse pubkey@host:port into a socket address"
        )));
    }

    let pubkey = hex_str_to_compressed_pubkey(pubkey.unwrap());
    if pubkey.is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "unable to parse given pubkey for node"
        )));
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}

pub(crate) async fn start_daemon(args: LdkUserInfo) -> Result<Arc<AppState>, AppError> {
    // Initialize the Logger (creates ldk_data_dir and its logs directory)
    let ldk_data_dir = format!("{}/.ldk", args.storage_dir_path);
    let logger = Arc::new(FilesystemLogger::new(ldk_data_dir.clone()));

    // Initialize our bitcoind client.
    let bitcoind_client = match BitcoindClient::new(
        args.bitcoind_rpc_host.clone(),
        args.bitcoind_rpc_port,
        args.bitcoind_rpc_username.clone(),
        args.bitcoind_rpc_password.clone(),
        tokio::runtime::Handle::current(),
        Arc::clone(&logger),
    )
    .await
    {
        Ok(client) => Arc::new(client),
        Err(e) => {
            return Err(AppError::FailedBitcoindConnection(e.to_string()));
        }
    };

    // Check that the bitcoind we've connected to is running the network we expect
    let network = args.network;
    let bitcoind_chain = bitcoind_client.get_blockchain_info().await.chain;
    if bitcoind_chain
        != match network {
            bitcoin::Network::Bitcoin => "main",
            bitcoin::Network::Testnet => "test",
            bitcoin::Network::Regtest => "regtest",
            bitcoin::Network::Signet => "signet",
        }
    {
        return Err(AppError::InvalidBitcoinNetwork(network, bitcoind_chain));
    }

    // RGB setup
    let (electrum_url, proxy_url, proxy_endpoint) = match network {
        bitcoin::Network::Testnet => (
            ELECTRUM_URL_TESTNET,
            PROXY_URL_TESTNET,
            PROXY_ENDPOINT_TESTNET,
        ),
        bitcoin::Network::Regtest => (
            ELECTRUM_URL_REGTEST,
            PROXY_URL_REGTEST,
            PROXY_ENDPOINT_REGTEST,
        ),
        _ => {
            return Err(AppError::UnsupportedBitcoinNetwork);
        }
    };
    fs::write(
        format!("{}/{ELECTRUM_URL_FNAME}", args.storage_dir_path),
        electrum_url,
    )
    .expect("able to write");
    let bitcoin_network = get_bitcoin_network(&network);
    fs::write(
        format!("{}/{BITCOIN_NETWORK_FNAME}", args.storage_dir_path),
        bitcoin_network.to_string(),
    )
    .expect("able to write");
    let rest_client = RestClient::builder()
        .timeout(Duration::from_secs(PROXY_TIMEOUT as u64))
        .connection_verbose(true)
        .build()
        .expect("valid proxy");
    let proxy_client = Arc::new(rest_client);

    let cancel_token = CancellationToken::new();

    let static_state = Arc::new(StaticState {
        ldk_peer_listening_port: args.ldk_peer_listening_port,
        ldk_announced_listen_addr: args.ldk_announced_listen_addr,
        ldk_announced_node_name: args.ldk_announced_node_name,
        network,
        storage_dir_path: args.storage_dir_path,
        ldk_data_dir,
        logger,
        electrum_url: electrum_url.to_string(),
        proxy_endpoint: proxy_endpoint.to_string(),
        proxy_url: proxy_url.to_string(),
        proxy_client,
        bitcoind_client,
    });

    Ok(Arc::new(AppState {
        static_state,
        cancel_token,
        unlocked_app_state: Arc::new(TokioMutex::new(None)),
        ldk_background_services: Arc::new(Mutex::new(None)),
        changing_state: Mutex::new(false),
    }))
}

pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn get_max_local_rgb_amount<'r>(
    contract_id: ContractId,
    ldk_data_dir_path: &Path,
    channels: impl Iterator<Item = &'r ChannelDetails>,
) -> u64 {
    let mut max_balance = 0;
    for chan_info in channels {
        let info_file_path = ldk_data_dir_path.join(chan_info.channel_id.to_hex());
        if !info_file_path.exists() {
            continue;
        }
        let (rgb_info, _) = get_rgb_channel_info(&chan_info.channel_id, ldk_data_dir_path);
        if rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount > max_balance {
            max_balance = rgb_info.local_rgb_amount;
        }
    }

    max_balance
}

pub(crate) fn get_route(
    channel_manager: &crate::ldk::ChannelManager,
    router: &crate::ldk::Router,
    start: PublicKey,
    dest: PublicKey,
    final_value_msat: Option<u64>,
    asset_id: Option<ContractId>,
    hints: Vec<RouteHint>,
) -> Option<Route> {
    let inflight_htlcs = channel_manager.compute_inflight_htlcs();
    let payment_params = PaymentParameters {
        payee: Payee::Clear {
            node_id: dest,
            route_hints: hints,
            features: None,
            final_cltv_expiry_delta: DEFAULT_FINAL_CLTV_EXPIRY_DELTA,
        },
        expiry_time: None,
        max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
        max_path_count: 1,
        max_channel_saturation_power_of_half: 2,
        previously_failed_channels: vec![],
    };
    let route = router.find_route(
        &start,
        &RouteParameters {
            payment_params,
            final_value_msat: final_value_msat.unwrap_or(HTLC_MIN_MSAT),
            max_total_routing_fee_msat: None,
        },
        None,
        inflight_htlcs,
        asset_id,
    );

    route.ok()
}
