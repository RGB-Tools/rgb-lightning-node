use amplify::s;
use bitcoin::io;
use bitcoin::secp256k1::PublicKey;
use futures::Future;
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::types::ChannelId;
use lightning::routing::router::{
    Payee, PaymentParameters, Route, RouteHint, RouteParameters, Router as _,
    DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, MAX_PATH_LENGTH_ESTIMATE,
};
use lightning::{
    onion_message::packet::OnionMessageContents,
    sign::KeysManager,
    util::ser::{Writeable, Writer},
};
use lightning_persister::fs_store::FilesystemStore;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rgb_lib::{bdk_wallet::keys::bip39::Mnemonic, BitcoinNetwork, ContractId};
use std::{
    fmt::Write,
    fs,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};
use tokio::sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard};
use tokio_util::sync::CancellationToken;

use crate::ldk::{ChannelIdsMap, Router};
use crate::rgb::{get_rgb_channel_info_optional, RgbLibWalletWrapper};
use crate::routes::{DEFAULT_FINAL_CLTV_EXPIRY_DELTA, HTLC_MIN_MSAT};
use crate::{
    args::LdkUserInfo,
    disk::FilesystemLogger,
    error::{APIError, AppError},
    ldk::{
        BumpTxEventHandler, ChainMonitor, ChannelManager, InboundPaymentInfoStorage,
        LdkBackgroundServices, NetworkGraph, OnionMessenger, OutboundPaymentInfoStorage,
        OutputSweeper, PeerManager, SwapMap,
    },
};

pub(crate) const LDK_DIR: &str = ".ldk";
pub(crate) const LOGS_DIR: &str = "logs";
pub(crate) const ELECTRUM_URL_REGTEST: &str = "127.0.0.1:50001";
pub(crate) const ELECTRUM_URL_SIGNET: &str = "ssl://electrum.iriswallet.com:50033";
pub(crate) const ELECTRUM_URL_TESTNET: &str = "ssl://electrum.iriswallet.com:50013";
pub(crate) const PROXY_ENDPOINT_LOCAL: &str = "rpc://127.0.0.1:3000/json-rpc";
pub(crate) const PROXY_ENDPOINT_PUBLIC: &str = "rpcs://proxy.iriswallet.com/0.2/json-rpc";
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
    pub(crate) network: BitcoinNetwork,
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) ldk_data_dir: PathBuf,
    pub(crate) logger: Arc<FilesystemLogger>,
    pub(crate) max_media_upload_size_mb: u16,
}

pub(crate) struct UnlockedAppState {
    pub(crate) channel_manager: Arc<ChannelManager>,
    pub(crate) inbound_payments: Arc<Mutex<InboundPaymentInfoStorage>>,
    pub(crate) keys_manager: Arc<KeysManager>,
    pub(crate) network_graph: Arc<NetworkGraph>,
    pub(crate) chain_monitor: Arc<ChainMonitor>,
    pub(crate) onion_messenger: Arc<OnionMessenger>,
    pub(crate) outbound_payments: Arc<Mutex<OutboundPaymentInfoStorage>>,
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) fs_store: Arc<FilesystemStore>,
    pub(crate) bump_tx_event_handler: Arc<BumpTxEventHandler>,
    pub(crate) maker_swaps: Arc<Mutex<SwapMap>>,
    pub(crate) taker_swaps: Arc<Mutex<SwapMap>>,
    pub(crate) rgb_wallet_wrapper: Arc<RgbLibWalletWrapper>,
    pub(crate) router: Arc<Router>,
    pub(crate) output_sweeper: Arc<OutputSweeper>,
    pub(crate) rgb_send_lock: Arc<Mutex<bool>>,
    pub(crate) channel_ids_map: Arc<Mutex<ChannelIdsMap>>,
    pub(crate) proxy_endpoint: String,
}

impl UnlockedAppState {
    pub(crate) fn get_inbound_payments(&self) -> MutexGuard<InboundPaymentInfoStorage> {
        self.inbound_payments.lock().unwrap()
    }

    pub(crate) fn get_outbound_payments(&self) -> MutexGuard<OutboundPaymentInfoStorage> {
        self.outbound_payments.lock().unwrap()
    }

    pub(crate) fn get_maker_swaps(&self) -> MutexGuard<SwapMap> {
        self.maker_swaps.lock().unwrap()
    }

    pub(crate) fn get_taker_swaps(&self) -> MutexGuard<SwapMap> {
        self.taker_swaps.lock().unwrap()
    }

    pub(crate) fn get_channel_ids_map(&self) -> MutexGuard<ChannelIdsMap> {
        self.channel_ids_map.lock().unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct UserOnionMessageContents {
    pub(crate) tlv_type: u64,
    pub(crate) data: Vec<u8>,
}

impl OnionMessageContents for UserOnionMessageContents {
    fn tlv_type(&self) -> u64 {
        self.tlv_type
    }
    fn msg_type(&self) -> &'static str {
        "RLNCustomMessageType"
    }
}

impl Writeable for UserOnionMessageContents {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
        w.write_all(&self.data)
    }
}

pub(crate) fn check_already_initialized(mnemonic_path: &Path) -> Result<(), APIError> {
    if mnemonic_path.exists() {
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
    storage_dir_path: &Path,
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

pub(crate) fn check_channel_id(channel_id_str: &str) -> Result<ChannelId, APIError> {
    if let Some(channel_id_bytes) = hex_str_to_vec(channel_id_str) {
        if channel_id_bytes.len() != 32 {
            return Err(APIError::InvalidChannelID);
        }
        Ok(ChannelId::from_bytes(channel_id_bytes.try_into().unwrap()))
    } else {
        Err(APIError::InvalidChannelID)
    }
}

pub(crate) fn check_port_is_available(port: u16) -> Result<(), AppError> {
    if TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).is_ok() {
        return Err(AppError::UnavailablePort(port));
    }
    Ok(())
}

pub(crate) fn get_mnemonic_path(storage_dir_path: &Path) -> PathBuf {
    storage_dir_path.join("mnemonic")
}

pub(crate) fn encrypt_and_save_mnemonic(
    password: String,
    mnemonic: String,
    mnemonic_path: &Path,
) -> Result<(), APIError> {
    let mcrypt = new_magic_crypt!(password, 256);
    let encrypted_mnemonic = mcrypt.encrypt_str_to_base64(mnemonic);
    match fs::write(mnemonic_path, encrypted_mnemonic) {
        Ok(()) => {
            tracing::info!("Created a new wallet");
            Ok(())
        }
        Err(e) => Err(APIError::FailedKeysCreation(
            mnemonic_path.to_string_lossy().to_string(),
            e.to_string(),
        )),
    }
}

pub(crate) async fn connect_peer_if_necessary(
    pubkey: PublicKey,
    address: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), APIError> {
    for peer_details in peer_manager.list_peers() {
        if peer_details.counterparty_node_id == pubkey {
            return Ok(());
        }
    }
    do_connect_peer(pubkey, address, peer_manager).await?;
    tracing::info!("connected to peer (pubkey: {pubkey}, addr: {address})");
    Ok(())
}

pub(crate) async fn do_connect_peer(
    pubkey: PublicKey,
    address: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), APIError> {
    match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, address).await {
        Some(connection_closed_future) => {
            let mut connection_closed_future = Box::pin(connection_closed_future);
            loop {
                tokio::select! {
                    _ = &mut connection_closed_future => return Err(APIError::FailedPeerConnection),
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                };
                if peer_manager.peer_by_node_id(&pubkey).is_some() {
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
    let data = hex_str_to_vec(&hex[0..33 * 2])?;
    PublicKey::from_slice(&data).ok()
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
) -> Result<(PublicKey, Option<SocketAddr>), APIError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next();

    let peer_addr = if let Some(peer_addr_str) = pubkey_and_addr.next() {
        let peer_addr = peer_addr_str.to_socket_addrs().map(|mut r| r.next());
        if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
            return Err(APIError::InvalidPeerInfo(s!(
                "couldn't parse pubkey@host:port into a socket address"
            )));
        }
        peer_addr.unwrap()
    } else {
        None
    };

    let pubkey = hex_str_to_compressed_pubkey(pubkey.unwrap());
    if pubkey.is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "unable to parse given pubkey for node"
        )));
    }

    Ok((pubkey.unwrap(), peer_addr))
}

pub(crate) async fn start_daemon(args: &LdkUserInfo) -> Result<Arc<AppState>, AppError> {
    // Initialize the Logger (creates ldk_data_dir and its logs directory)
    let ldk_data_dir = args.storage_dir_path.join(LDK_DIR);
    let logger = Arc::new(FilesystemLogger::new(ldk_data_dir.clone()));

    let cancel_token = CancellationToken::new();

    let static_state = Arc::new(StaticState {
        ldk_peer_listening_port: args.ldk_peer_listening_port,
        network: args.network,
        storage_dir_path: args.storage_dir_path.clone(),
        ldk_data_dir,
        logger,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
    });

    Ok(Arc::new(AppState {
        static_state,
        cancel_token,
        unlocked_app_state: Arc::new(TokioMutex::new(None)),
        ldk_background_services: Arc::new(Mutex::new(None)),
        changing_state: Mutex::new(false),
    }))
}

pub(crate) fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn get_max_local_rgb_amount<'r>(
    contract_id: ContractId,
    ldk_data_dir_path: &Path,
    channels: impl Iterator<Item = &'r ChannelDetails>,
) -> u64 {
    let mut max_balance = 0;
    for chan_info in channels {
        if let Some((rgb_info, _)) =
            get_rgb_channel_info_optional(&chan_info.channel_id, ldk_data_dir_path, false)
        {
            if rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount > max_balance {
                max_balance = rgb_info.local_rgb_amount;
            }
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
    rgb_payment: Option<(ContractId, u64)>,
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
        max_path_length: MAX_PATH_LENGTH_ESTIMATE,
        max_channel_saturation_power_of_half: 2,
        previously_failed_channels: vec![],
        previously_failed_blinded_path_idxs: vec![],
    };
    let route = router.find_route(
        &start,
        &RouteParameters {
            payment_params,
            final_value_msat: final_value_msat.unwrap_or(HTLC_MIN_MSAT),
            max_total_routing_fee_msat: None,
            rgb_payment,
        },
        None,
        inflight_htlcs,
    );

    route.ok()
}
