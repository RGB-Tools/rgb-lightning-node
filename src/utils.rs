use crate::database::RlnDatabase;
use crate::synced_kv_store::SyncedKvStore;
use amplify::s;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
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
    types::payment::{PaymentHash, PaymentPreimage},
    util::persist::KVStoreSync,
    util::ser::{Writeable, Writer},
};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rgb_lib::{bdk_wallet::keys::bip39::Mnemonic, BitcoinNetwork, ContractId};
use rln_migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::{
    collections::HashSet,
    fmt::Write,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{Duration, SystemTime},
};
use tokio::sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard};
use tokio_util::sync::CancellationToken;

use crate::async_order::{AsyncOrderMessageHandler, AsyncPaymentsPreimageRoot};
use crate::core_types::{DEFAULT_FINAL_CLTV_EXPIRY_DELTA, HTLC_MIN_MSAT};
use crate::ldk::{ChannelIdsMap, Router, VirtualChannelDraftStore, VirtualChannelSessionStore};
use crate::rgb::{get_rgb_channel_info_optional, RgbLibWalletWrapper};
use crate::{
    args::UserArgs,
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
pub(crate) const ELECTRUM_URL_TESTNET4: &str = "ssl://electrum.iriswallet.com:50053";
pub(crate) const ELECTRUM_URL_MAINNET: &str = "ssl://electrum.iriswallet.com:50003";
pub(crate) const PROXY_ENDPOINT_LOCAL: &str = "rpc://127.0.0.1:3000/json-rpc";
pub(crate) const PROXY_ENDPOINT_PUBLIC: &str = "rpcs://proxy.iriswallet.com/0.2/json-rpc";
const PASSWORD_MIN_LENGTH: u8 = 8;

pub(crate) struct AppState {
    pub(crate) static_state: Arc<StaticState>,
    pub(crate) cancel_token: CancellationToken,
    pub(crate) unlocked_app_state: Arc<TokioMutex<Option<Arc<UnlockedAppState>>>>,
    pub(crate) ldk_background_services: Arc<Mutex<Option<LdkBackgroundServices>>>,
    pub(crate) changing_state: Mutex<bool>,
    pub(crate) root_public_key: Option<biscuit_auth::PublicKey>,
    pub(crate) revoked_tokens: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl AppState {
    pub(crate) fn db(&self) -> Arc<DatabaseConnection> {
        self.static_state.db()
    }

    pub(crate) fn get_db(&self) -> RlnDatabase {
        RlnDatabase::new((*self.db()).clone())
    }

    pub(crate) fn get_changing_state(&self) -> MutexGuard<'_, bool> {
        self.changing_state.lock().unwrap()
    }

    pub(crate) fn get_ldk_background_services(
        &self,
    ) -> MutexGuard<'_, Option<LdkBackgroundServices>> {
        self.ldk_background_services.lock().unwrap()
    }

    pub(crate) async fn get_unlocked_app_state(
        &self,
    ) -> TokioMutexGuard<'_, Option<Arc<UnlockedAppState>>> {
        self.unlocked_app_state.lock().await
    }
}

// VSS-related fields below are always present on `StaticState` regardless of
// the `vss` feature flag — they ride the same SDK / NodeConfig surface as the
// non-VSS knobs. With `vss` off the implementation never reads them, so we
// silence the dead-code warning at the field level (the older
// `cfg_attr(dead_code)` annotations made the fields look optional; they
// aren't, only their consumers are gated).
pub(crate) struct StaticState {
    pub(crate) enable_virtual_channels_v0: bool,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) network: BitcoinNetwork,
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) ldk_data_dir: PathBuf,
    pub(crate) logger: Arc<FilesystemLogger>,
    pub(crate) max_media_upload_size_mb: u16,
    pub(crate) virtual_peer_pubkeys: Vec<PublicKey>,
    pub(crate) database: RwLock<Arc<DatabaseConnection>>,
    pub(crate) lsp_base_url: Option<String>,
    pub(crate) lsp_bearer_token: Option<String>,
    /// VSS server URL (None = VSS disabled). Populated regardless of the
    /// `vss` feature flag; only the consumer in `start_ldk` is feature-gated.
    #[cfg_attr(not(feature = "vss"), allow(dead_code))]
    pub(crate) vss_url: Option<String>,
    /// When true, a failed VSS restore on a fresh device logs a warning and
    /// continues with empty local state instead of aborting unlock.
    #[cfg_attr(not(feature = "vss"), allow(dead_code))]
    pub(crate) vss_allow_empty_restore: bool,
}

impl StaticState {
    pub(crate) fn db(&self) -> Arc<DatabaseConnection> {
        self.database.read().unwrap().clone()
    }
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
    pub(crate) async_order_handler: Arc<AsyncOrderMessageHandler>,
    pub(crate) async_payments_preimage_root: Arc<AsyncPaymentsPreimageRoot>,
    pub(crate) kv_store: Arc<SyncedKvStore>,
    pub(crate) bump_tx_event_handler: Arc<BumpTxEventHandler>,
    pub(crate) maker_swaps: Arc<Mutex<SwapMap>>,
    pub(crate) taker_swaps: Arc<Mutex<SwapMap>>,
    pub(crate) rgb_wallet_wrapper: Arc<RgbLibWalletWrapper>,
    pub(crate) router: Arc<Router>,
    pub(crate) output_sweeper: Arc<OutputSweeper>,
    pub(crate) rgb_send_lock: Arc<Mutex<bool>>,
    pub(crate) channel_ids_map: Arc<Mutex<ChannelIdsMap>>,
    pub(crate) proxy_endpoint: String,
    pub(crate) virtual_channel_draft_store: Arc<Mutex<VirtualChannelDraftStore>>,
    pub(crate) virtual_channel_session_store: Arc<Mutex<VirtualChannelSessionStore>>,
}

impl UnlockedAppState {
    pub(crate) fn get_inbound_payments(&self) -> MutexGuard<'_, InboundPaymentInfoStorage> {
        self.inbound_payments.lock().unwrap()
    }

    pub(crate) fn get_outbound_payments(&self) -> MutexGuard<'_, OutboundPaymentInfoStorage> {
        self.outbound_payments.lock().unwrap()
    }

    pub(crate) fn get_maker_swaps(&self) -> MutexGuard<'_, SwapMap> {
        self.maker_swaps.lock().unwrap()
    }

    pub(crate) fn get_taker_swaps(&self) -> MutexGuard<'_, SwapMap> {
        self.taker_swaps.lock().unwrap()
    }

    pub(crate) fn get_channel_ids_map(&self) -> MutexGuard<'_, ChannelIdsMap> {
        self.channel_ids_map.lock().unwrap()
    }

    pub(crate) fn get_virtual_channel_draft_store(
        &self,
    ) -> MutexGuard<'_, VirtualChannelDraftStore> {
        self.virtual_channel_draft_store.lock().unwrap()
    }

    pub(crate) fn get_virtual_channel_session_store(
        &self,
    ) -> MutexGuard<'_, VirtualChannelSessionStore> {
        self.virtual_channel_session_store.lock().unwrap()
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

pub(crate) fn check_already_initialized(database: &DatabaseConnection) -> Result<(), APIError> {
    let db = crate::database::RlnDatabase::new(database.clone());
    if db.mnemonic_exists()? {
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
    database: &DatabaseConnection,
) -> Result<Mnemonic, APIError> {
    let db = crate::database::RlnDatabase::new(database.clone());
    if let Some(mnemonic_record) = db.get_mnemonic()? {
        let mcrypt = new_magic_crypt!(password, 256);
        let mnemonic_str = mcrypt
            .decrypt_base64_to_string(mnemonic_record.encrypted_mnemonic)
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

/// Validate a VSS URL. By default only `https://` URLs and loopback HTTP
/// URLs (`http://localhost`, `http://127.0.0.1`, `http://[::1]`) are
/// accepted; pass `allow_http = true` to allow `http://` on any host (for
/// private networks with out-of-band trust).
pub(crate) fn validate_vss_url(url: &str, allow_http: bool) -> Result<(), AppError> {
    let trimmed = url.trim();
    if let Some(rest) = trimmed.strip_prefix("https://") {
        if rest.is_empty() {
            return Err(AppError::InvalidVssConfig(format!(
                "VSS URL `{url}` has no host"
            )));
        }
        return Ok(());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        // Strip any optional userinfo (`user:pass@`) and trailing path/query.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host_with_port = authority
            .rsplit_once('@')
            .map(|(_, after)| after)
            .unwrap_or(authority);
        let is_loopback_host = ["localhost", "127.0.0.1", "[::1]", "0.0.0.0"]
            .iter()
            .any(|h| host_with_port == *h || host_with_port.starts_with(&format!("{h}:")));
        if is_loopback_host || allow_http {
            return Ok(());
        }
        return Err(AppError::InvalidVssConfig(format!(
            "VSS URL `{url}` uses http:// on non-loopback host `{host_with_port}`. \
             Use https:// in production, or pass --vss-allow-http to allow http:// \
             on a private network you trust out-of-band."
        )));
    }
    Err(AppError::InvalidVssConfig(format!(
        "VSS URL `{url}` must start with http:// or https://"
    )))
}

pub(crate) fn get_db_path(storage_dir_path: &Path) -> PathBuf {
    storage_dir_path.join("rln_db")
}

pub(crate) fn encrypt_and_save_mnemonic(
    password: String,
    mnemonic: String,
    database: &DatabaseConnection,
) -> Result<(), APIError> {
    let mcrypt = new_magic_crypt!(password, 256);
    let encrypted_mnemonic = mcrypt.encrypt_str_to_base64(mnemonic);
    let db = crate::database::RlnDatabase::new(database.clone());
    db.save_mnemonic(encrypted_mnemonic)?;
    tracing::info!("Saved wallet mnemonic");
    Ok(())
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
        write!(&mut res, "{v:02x}").expect("Unable to write");
    }
    res
}

pub(crate) fn new_jsonrpc_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
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

pub(crate) async fn open_database_pool(
    storage_dir_path: &Path,
) -> Result<DatabaseConnection, AppError> {
    let db_path = get_db_path(storage_dir_path);
    let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
    let mut opt = ConnectOptions::new(connection_string);
    // Use single connection to avoid deadlocks
    opt.max_connections(1)
        .min_connections(0)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8));
    Database::connect(opt).await.map_err(|e| {
        AppError::IO(std::io::Error::other(format!(
            "Database connection failed: {e}"
        )))
    })
}

pub(crate) async fn start_daemon(args: &UserArgs) -> Result<Arc<AppState>, AppError> {
    // Initialize the Logger (creates ldk_data_dir and its logs directory)
    let ldk_data_dir = args.storage_dir_path.join(LDK_DIR);
    let logger = Arc::new(FilesystemLogger::new(ldk_data_dir.clone()));

    // Initialize the shared database connection
    let database = crate::runtime::block_on(open_database_pool(&args.storage_dir_path))?;
    let db_path = get_db_path(&args.storage_dir_path);

    crate::runtime::block_on(Migrator::up(&database, None))
        .map_err(|e| AppError::IO(std::io::Error::other(format!("Migration failed: {e}"))))?;

    tracing::info!(db_path = %db_path.display(), "Shared database initialized");

    let cancel_token = CancellationToken::new();

    if args.vss_url.is_some() {
        tracing::info!(vss_url = ?args.vss_url, "VSS cloud backup enabled");
    }

    let static_state = Arc::new(StaticState {
        enable_virtual_channels_v0: args.enable_virtual_channels_v0,
        ldk_peer_listening_port: args.ldk_peer_listening_port,
        network: args.network,
        storage_dir_path: args.storage_dir_path.clone(),
        ldk_data_dir,
        logger,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
        virtual_peer_pubkeys: args.virtual_peer_pubkeys.clone(),
        database: RwLock::new(Arc::new(database)),
        lsp_base_url: args.lsp_base_url.clone(),
        lsp_bearer_token: args.lsp_bearer_token.clone(),
        vss_url: args.vss_url.clone(),
        vss_allow_empty_restore: args.vss_allow_empty_restore,
    });

    let app_state = Arc::new(AppState {
        static_state,
        cancel_token,
        unlocked_app_state: Arc::new(TokioMutex::new(None)),
        ldk_background_services: Arc::new(Mutex::new(None)),
        changing_state: Mutex::new(false),
        root_public_key: args.root_public_key,
        revoked_tokens: Arc::new(Mutex::new(HashSet::new())),
    });

    // load revoked tokens from database if authentication is enabled
    if app_state.root_public_key.is_some() {
        let loaded_tokens = app_state.load_revoked_tokens()?;
        *app_state.revoked_tokens.lock().unwrap() = loaded_tokens;
    }

    Ok(app_state)
}

pub(crate) fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn get_max_local_rgb_amount<'r>(
    contract_id: ContractId,
    channels: impl Iterator<Item = &'r ChannelDetails>,
    kv_store: &dyn KVStoreSync,
) -> u64 {
    let mut max_balance = 0;
    for chan_info in channels {
        if let Some(rgb_info) =
            get_rgb_channel_info_optional(&chan_info.channel_id, false, kv_store)
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

pub(crate) fn validate_and_parse_payment_hash(
    payment_hash_str: &str,
) -> Result<PaymentHash, APIError> {
    let payment_hash_vec = hex_str_to_vec(payment_hash_str);
    if payment_hash_vec.is_none() || payment_hash_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidPaymentHash(payment_hash_str.to_string()));
    }
    Ok(PaymentHash(payment_hash_vec.unwrap().try_into().unwrap()))
}

pub(crate) fn validate_and_parse_description_hash(
    description_hash_str: &str,
) -> Result<lightning_invoice::Sha256, APIError> {
    Ok(lightning_invoice::Sha256(
        Sha256::from_str(description_hash_str)
            .map_err(|_| APIError::InvalidDescriptionHash(description_hash_str.to_string()))?,
    ))
}

pub(crate) fn validate_and_parse_payment_preimage(
    payment_preimage_str: &str,
    payment_hash: &PaymentHash,
) -> Result<PaymentPreimage, APIError> {
    let preimage_vec = hex_str_to_vec(payment_preimage_str);
    if preimage_vec.is_none() || preimage_vec.as_ref().unwrap().len() != 32 {
        return Err(APIError::InvalidPaymentPreimage);
    }
    let preimage = PaymentPreimage(preimage_vec.unwrap().try_into().unwrap());
    let computed_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());
    if computed_hash != *payment_hash {
        return Err(APIError::InvalidPaymentPreimage);
    }
    Ok(preimage)
}

#[cfg(test)]
mod utils_tests {
    use super::validate_vss_url;

    #[test]
    fn vss_url_https_accepted() {
        assert!(validate_vss_url("https://example.com/vss", false).is_ok());
        assert!(validate_vss_url("https://example.com/vss", true).is_ok());
    }

    #[test]
    fn vss_url_loopback_http_accepted_without_override() {
        assert!(validate_vss_url("http://localhost:8081/vss", false).is_ok());
        assert!(validate_vss_url("http://127.0.0.1:8081/vss", false).is_ok());
        assert!(validate_vss_url("http://[::1]:8081/vss", false).is_ok());
    }

    #[test]
    fn vss_url_non_loopback_http_rejected_without_override() {
        assert!(validate_vss_url("http://example.com/vss", false).is_err());
    }

    #[test]
    fn vss_url_non_loopback_http_accepted_with_override() {
        assert!(validate_vss_url("http://example.com/vss", true).is_ok());
    }

    #[test]
    fn vss_url_other_schemes_rejected() {
        assert!(validate_vss_url("ftp://example.com/vss", true).is_err());
        assert!(validate_vss_url("example.com/vss", true).is_err());
    }
}
