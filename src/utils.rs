use amplify::s;
use bdk::keys::bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lightning::ln::msgs::NetAddress;
use lightning::rgb_utils::{BITCOIN_NETWORK_FNAME, ELECTRUM_URL_FNAME};
use lightning::{chain::keysinterface::KeysManager, ln::PaymentHash};
use lightning::{
    onion_message::CustomOnionMessageContents,
    util::ser::{Writeable, Writer},
};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use reqwest::Client as RestClient;
use rgb_lib::wallet::{Online, Wallet as RgbLibWallet};
use rgb_lib::BitcoinNetwork;
use std::{
    collections::HashMap,
    fmt::Write,
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

use crate::{
    args::LdkUserInfo,
    bitcoind::BitcoindClient,
    disk::FilesystemLogger,
    error::{APIError, AppError},
    ldk::{
        ChannelManager, LdkBackgroundServices, NetworkGraph, OnionMessenger, PaymentInfo,
        PeerManager,
    },
};

pub(crate) const LOGS_DIR: &str = "logs";
const ELECTRUM_URL_REGTEST: &str = "127.0.0.1:50001";
const ELECTRUM_URL_TESTNET: &str = "ssl://electrum.iriswallet.com:50013";
const PROXY_ENDPOINT_REGTEST: &str = "rpc://127.0.0.1:3000/json-rpc";
const PROXY_URL_REGTEST: &str = "http://127.0.0.1:3000/json-rpc";
const PROXY_ENDPOINT_TESTNET: &str = "rpcs://proxy.iriswallet.com/0.2/json-rpc";
const PROXY_URL_TESTNET: &str = "https://proxy.iriswallet.com/0.2/json-rpc";
const PROXY_TIMEOUT: u8 = 90;
const PASSWORD_MIN_LENGTH: u8 = 8;

pub(crate) struct AppState {
    pub(crate) static_state: Arc<StaticState>,
    pub(crate) cancel_token: CancellationToken,
    pub(crate) unlocked_app_state: Arc<Mutex<Option<Arc<UnlockedAppState>>>>,
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

    pub(crate) fn get_unlocked_app_state(&self) -> MutexGuard<Option<Arc<UnlockedAppState>>> {
        self.unlocked_app_state.lock().unwrap()
    }
}

pub(crate) struct StaticState {
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) ldk_announced_listen_addr: Vec<NetAddress>,
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
    pub(crate) inbound_payments: Arc<Mutex<HashMap<PaymentHash, PaymentInfo>>>,
    pub(crate) keys_manager: Arc<KeysManager>,
    pub(crate) network_graph: Arc<NetworkGraph>,
    pub(crate) onion_messenger: Arc<OnionMessenger>,
    pub(crate) outbound_payments: Arc<Mutex<HashMap<PaymentHash, PaymentInfo>>>,
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) rgb_wallet: Arc<Mutex<RgbLibWallet>>,
    pub(crate) rgb_online: Online,
}

impl UnlockedAppState {
    pub(crate) fn get_inbound_payments(&self) -> MutexGuard<HashMap<PaymentHash, PaymentInfo>> {
        self.inbound_payments.lock().unwrap()
    }

    pub(crate) fn get_outbound_payments(&self) -> MutexGuard<HashMap<PaymentHash, PaymentInfo>> {
        self.outbound_payments.lock().unwrap()
    }

    pub(crate) fn get_rgb_wallet(&self) -> MutexGuard<RgbLibWallet> {
        self.rgb_wallet.lock().unwrap()
    }
}

pub(crate) struct UserOnionMessageContents {
    pub(crate) tlv_type: u64,
    pub(crate) data: Vec<u8>,
}

impl CustomOnionMessageContents for UserOnionMessageContents {
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

pub(crate) fn check_locked(
    state: &Arc<AppState>,
) -> Result<MutexGuard<Option<Arc<UnlockedAppState>>>, APIError> {
    let unlocked_app_state = state.unlocked_app_state.lock().unwrap();
    if unlocked_app_state.is_some() {
        Err(APIError::UnlockedNode)
    } else if *state.get_changing_state() {
        Err(APIError::ChangingState)
    } else {
        Ok(unlocked_app_state)
    }
}

pub(crate) fn check_unlocked(
    state: &Arc<AppState>,
) -> Result<MutexGuard<Option<Arc<UnlockedAppState>>>, APIError> {
    let unlocked_app_state = state.unlocked_app_state.lock().unwrap();
    if unlocked_app_state.is_none() {
        Err(APIError::LockedNode)
    } else if *state.get_changing_state() {
        Err(APIError::ChangingState)
    } else {
        Ok(unlocked_app_state)
    }
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
    let bitcoin_network: BitcoinNetwork = network.into();
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
        unlocked_app_state: Arc::new(Mutex::new(None)),
        ldk_background_services: Arc::new(Mutex::new(None)),
        changing_state: Mutex::new(false),
    }))
}
