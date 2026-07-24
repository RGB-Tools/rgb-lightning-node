use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use tokio::sync::Mutex as TokioMutex;

use bitcoin::io;
use bitcoin::secp256k1::PublicKey;
use lightning::rgb_utils::{
    BITCOIN_NETWORK_FNAME, INDEXER_URL_FNAME, RGB_PAYMENT_INFO_INBOUND_NS,
    RGB_PAYMENT_INFO_OUTBOUND_NS, RGB_PRIMARY_NS, RGB_WALLET_CONFIG_NS,
    WALLET_ACCOUNT_XPUB_COLORED_FNAME, WALLET_ACCOUNT_XPUB_VANILLA_FNAME, WALLET_FINGERPRINT_FNAME,
    WALLET_MASTER_FINGERPRINT_FNAME,
};
use lightning::util::async_poll::AsyncResult;
use lightning::util::persist::{KVStore, KVStoreSync, KvOp};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    TransactionTrait,
};

use crate::database::entities::{
    channel_peer, config, kv_store,
    prelude::{ChannelPeer, Config, KvStore, RevokedToken},
    revoked_token,
};
use crate::error::APIError;

const CONFIG_IDX: i32 = 1;

/// Dedicated runtime for DB futures issued from sync code. `block_in_place` +
/// `Handle::block_on` on the caller's runtime is not enough: LDK sync code blocks on std
/// mutexes on worker threads without `block_in_place`, so a worker core can stay pinned by a
/// lock whose holder is a queued task that never gets polled, deadlocking the runtime under
/// load. A separate runtime with long-lived workers cannot be starved by its callers.
fn db_runtime() -> &'static tokio::runtime::Runtime {
    static DB_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    DB_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rln-db")
            .enable_all()
            .build()
            .expect("valid db runtime")
    })
}

/// Runs a DB future to completion from sync code. When called from a runtime worker,
/// `block_in_place` hands the core off so the wait cannot starve the caller's runtime.
fn block_on<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    db_runtime().spawn(async move {
        let _ = tx.send(fut.await);
    });
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| rx.recv().expect("db task completes"))
    } else {
        rx.recv().expect("db task completes")
    }
}

/// LDK reads wallet config through the `rgb/wallet_config` KVStore namespace; those reads are
/// served from the typed `config` table (the single source of truth) plus an in-memory
/// read-through cache, since the values are static for the lifetime of an unlock.
fn is_wallet_config(primary_namespace: &str, secondary_namespace: &str) -> bool {
    primary_namespace == RGB_PRIMARY_NS && secondary_namespace == RGB_WALLET_CONFIG_NS
}

fn wallet_config_value(model: &config::Model, key: &str) -> Option<String> {
    match key {
        INDEXER_URL_FNAME => model.indexer_url.clone(),
        BITCOIN_NETWORK_FNAME => model.bitcoin_network.clone(),
        WALLET_FINGERPRINT_FNAME => model.wallet_fingerprint.clone(),
        WALLET_ACCOUNT_XPUB_VANILLA_FNAME => model.wallet_account_xpub_vanilla.clone(),
        WALLET_ACCOUNT_XPUB_COLORED_FNAME => model.wallet_account_xpub_colored.clone(),
        WALLET_MASTER_FINGERPRINT_FNAME => model.wallet_master_fingerprint.clone(),
        _ => None,
    }
}

type KeyLocks = Mutex<HashMap<(String, String, String), Arc<TokioMutex<u64>>>>;

pub struct SeaOrmKvStore {
    connection: Arc<DatabaseConnection>,
    wallet_config_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Per-key lock holding the version of the last applied write; writes and removes carry a
    /// version assigned at call time and are skipped if a newer one already applied, so
    /// out-of-order execution cannot clobber newer data. Entries are never pruned: the stored
    /// version is the key's staleness watermark, dropping it would let a delayed older write
    /// reapply. One entry per key ever touched, negligible at our scale.
    key_locks: Arc<KeyLocks>,
    version_counter: Arc<AtomicU64>,
}

impl SeaOrmKvStore {
    /// Caller must ensure migrations have already been run.
    pub fn from_connection(connection: Arc<DatabaseConnection>) -> Self {
        Self {
            connection,
            wallet_config_cache: Arc::new(RwLock::new(HashMap::new())),
            key_locks: Arc::new(Mutex::new(HashMap::new())),
            version_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn next_version(&self) -> u64 {
        self.version_counter.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn key_lock(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Arc<TokioMutex<u64>> {
        self.key_locks
            .lock()
            .unwrap()
            .entry((
                primary_namespace.to_string(),
                secondary_namespace.to_string(),
                key.to_string(),
            ))
            .or_default()
            .clone()
    }

    /// Test-only: force a key's last-applied version watermark.
    #[cfg(test)]
    pub(crate) fn force_key_version(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        version: u64,
    ) {
        let lock = self.key_lock(primary_namespace, secondary_namespace, key);
        block_on(async move { *lock.lock().await = version });
    }

    pub fn add_revoked_tokens(&self, token_id_hexes: Vec<String>) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let conn = Arc::clone(&self.connection);
        block_on(async move {
            conn.transaction::<_, (), sea_orm::DbErr>(move |txn| {
                Box::pin(async move {
                    for hex in token_id_hexes {
                        let token = revoked_token::ActiveModel {
                            token_id: ActiveValue::Set(hex),
                            revoked_at: ActiveValue::Set(now),
                        };
                        RevokedToken::insert(token)
                            .on_conflict(
                                OnConflict::column(revoked_token::Column::TokenId)
                                    .do_nothing()
                                    .to_owned(),
                            )
                            .exec(txn)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await
        })
        .map_err(|e| match e {
            sea_orm::TransactionError::Connection(err)
            | sea_orm::TransactionError::Transaction(err) => APIError::from(err),
        })?;

        Ok(())
    }

    pub fn delete_channel_peer(&self, pubkey: &str) -> Result<(), APIError> {
        let conn = Arc::clone(&self.connection);
        let pubkey = pubkey.to_string();
        block_on(async move {
            ChannelPeer::delete_many()
                .filter(channel_peer::Column::Pubkey.eq(pubkey))
                .exec(conn.as_ref())
                .await
        })?;

        Ok(())
    }

    /// Returns `(key, value)` of the proxy payment-info entries (`{channel_id}{payment_hash}`)
    /// for the given payment hash in a single query, inbound namespace first. The bare
    /// `{payment_hash}` and `{payment_hash}_pending` keys do not match the suffix-anchored
    /// pattern.
    pub fn find_rgb_payment_proxies(
        &self,
        payment_hash_hex: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, APIError> {
        let conn = Arc::clone(&self.connection);
        let payment_hash_hex = payment_hash_hex.to_string();
        let results = block_on(async move {
            KvStore::find()
                .filter(kv_store::Column::PrimaryNamespace.eq(RGB_PRIMARY_NS))
                .filter(
                    kv_store::Column::SecondaryNamespace
                        .is_in([RGB_PAYMENT_INFO_INBOUND_NS, RGB_PAYMENT_INFO_OUTBOUND_NS]),
                )
                .filter(kv_store::Column::Key.like(format!("%{payment_hash_hex}")))
                .filter(kv_store::Column::Key.ne(&payment_hash_hex))
                .order_by_asc(kv_store::Column::SecondaryNamespace)
                .all(conn.as_ref())
                .await
        })?;

        Ok(results.into_iter().map(|r| (r.key, r.value)).collect())
    }

    pub fn get_config(&self) -> Result<Option<config::Model>, APIError> {
        let conn = Arc::clone(&self.connection);
        Ok(block_on(async move {
            Config::find_by_id(CONFIG_IDX).one(conn.as_ref()).await
        })?)
    }

    pub fn is_initialized(&self) -> Result<bool, APIError> {
        Ok(self.get_config()?.is_some())
    }

    pub fn load_revoked_tokens(&self) -> Result<HashSet<Vec<u8>>, APIError> {
        let conn = Arc::clone(&self.connection);
        let results = block_on(async move { RevokedToken::find().all(conn.as_ref()).await })?;

        let mut revoked = HashSet::new();
        for record in results {
            if let Some(token_bytes) = crate::utils::hex_str_to_vec(&record.token_id) {
                revoked.insert(token_bytes);
            }
        }

        Ok(revoked)
    }

    pub fn persist_channel_peer(
        &self,
        pubkey: &PublicKey,
        address: &SocketAddr,
    ) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let peer = channel_peer::ActiveModel {
            pubkey: ActiveValue::Set(pubkey.to_string()),
            address: ActiveValue::Set(address.to_string()),
            created_at: ActiveValue::Set(now),
        };

        let conn = Arc::clone(&self.connection);
        block_on(async move {
            ChannelPeer::insert(peer)
                .on_conflict(
                    OnConflict::column(channel_peer::Column::Pubkey)
                        .update_column(channel_peer::Column::Address)
                        .to_owned(),
                )
                .exec(conn.as_ref())
                .await
        })?;

        tracing::info!("persisted peer (pubkey: {pubkey}, addr: {address})");
        Ok(())
    }

    pub fn read_channel_peer_data(&self) -> Result<HashMap<PublicKey, SocketAddr>, APIError> {
        let conn = Arc::clone(&self.connection);
        let results = block_on(async move { ChannelPeer::find().all(conn.as_ref()).await })?;

        let mut peer_data = HashMap::new();
        for record in results {
            if let (Ok(pubkey), Ok(address)) = (
                PublicKey::from_str(&record.pubkey),
                SocketAddr::from_str(&record.address),
            ) {
                peer_data.insert(pubkey, address);
            }
        }

        Ok(peer_data)
    }

    pub fn save_mnemonic(&self, encrypted_mnemonic: String) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let row = config::ActiveModel {
            idx: ActiveValue::Set(CONFIG_IDX),
            encrypted_mnemonic: ActiveValue::Set(encrypted_mnemonic),
            indexer_url: ActiveValue::NotSet,
            bitcoin_network: ActiveValue::NotSet,
            wallet_fingerprint: ActiveValue::NotSet,
            wallet_account_xpub_vanilla: ActiveValue::NotSet,
            wallet_account_xpub_colored: ActiveValue::NotSet,
            wallet_master_fingerprint: ActiveValue::NotSet,
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
        };

        let conn = Arc::clone(&self.connection);
        block_on(async move {
            Config::insert(row)
                .on_conflict(
                    OnConflict::column(config::Column::Idx)
                        .update_columns([
                            config::Column::EncryptedMnemonic,
                            config::Column::UpdatedAt,
                        ])
                        .to_owned(),
                )
                .exec(conn.as_ref())
                .await
        })?;

        Ok(())
    }

    fn update_config_field(&self, column: config::Column, value: &str) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;
        let conn = Arc::clone(&self.connection);
        let value = value.to_string();
        block_on(async move {
            Config::update_many()
                .filter(config::Column::Idx.eq(CONFIG_IDX))
                .col_expr(column, value.into())
                .col_expr(config::Column::UpdatedAt, now.into())
                .exec(conn.as_ref())
                .await
        })?;
        let cache_key = match column {
            config::Column::IndexerUrl => Some(INDEXER_URL_FNAME),
            config::Column::BitcoinNetwork => Some(BITCOIN_NETWORK_FNAME),
            config::Column::WalletFingerprint => Some(WALLET_FINGERPRINT_FNAME),
            config::Column::WalletAccountXpubVanilla => Some(WALLET_ACCOUNT_XPUB_VANILLA_FNAME),
            config::Column::WalletAccountXpubColored => Some(WALLET_ACCOUNT_XPUB_COLORED_FNAME),
            config::Column::WalletMasterFingerprint => Some(WALLET_MASTER_FINGERPRINT_FNAME),
            _ => None,
        };
        if let Some(cache_key) = cache_key {
            self.wallet_config_cache.write().unwrap().remove(cache_key);
        }
        Ok(())
    }

    pub fn set_indexer_url(&self, value: &str) -> Result<(), APIError> {
        self.update_config_field(config::Column::IndexerUrl, value)
    }

    pub fn set_bitcoin_network(&self, value: &str) -> Result<(), APIError> {
        self.update_config_field(config::Column::BitcoinNetwork, value)
    }

    pub fn set_wallet_fingerprint(&self, value: &str) -> Result<(), APIError> {
        self.update_config_field(config::Column::WalletFingerprint, value)
    }

    pub fn set_wallet_account_xpub_vanilla(&self, value: &str) -> Result<(), APIError> {
        self.update_config_field(config::Column::WalletAccountXpubVanilla, value)
    }

    pub fn set_wallet_account_xpub_colored(&self, value: &str) -> Result<(), APIError> {
        self.update_config_field(config::Column::WalletAccountXpubColored, value)
    }

    pub fn set_wallet_master_fingerprint(&self, value: &str) -> Result<(), APIError> {
        self.update_config_field(config::Column::WalletMasterFingerprint, value)
    }
}

impl KVStore for SeaOrmKvStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> AsyncResult<'static, Vec<u8>, io::Error> {
        tracing::trace!(primary_namespace, secondary_namespace, key, "KVStore read");
        if is_wallet_config(primary_namespace, secondary_namespace) {
            if let Some(value) = self.wallet_config_cache.read().unwrap().get(key).cloned() {
                return Box::pin(async move { Ok(value) });
            }
            let conn = Arc::clone(&self.connection);
            let cache = Arc::clone(&self.wallet_config_cache);
            let key = key.to_string();
            return Box::pin(async move {
                let model = Config::find_by_id(CONFIG_IDX)
                    .one(conn.as_ref())
                    .await
                    .map_err(|e| {
                        tracing::error!(key, error = %e, "config read failed");
                        io::Error::new(io::ErrorKind::Other, format!("Database read failed: {e}"))
                    })?;
                match model.as_ref().and_then(|m| wallet_config_value(m, &key)) {
                    Some(value) => {
                        let value = value.into_bytes();
                        cache.write().unwrap().insert(key, value.clone());
                        Ok(value)
                    }
                    None => Err(io::Error::new(io::ErrorKind::NotFound, "Key not found")),
                }
            });
        }
        let conn = Arc::clone(&self.connection);
        let primary_namespace = primary_namespace.to_string();
        let secondary_namespace = secondary_namespace.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let result = KvStore::find()
                .filter(kv_store::Column::PrimaryNamespace.eq(&primary_namespace))
                .filter(kv_store::Column::SecondaryNamespace.eq(&secondary_namespace))
                .filter(kv_store::Column::Key.eq(&key))
                .one(conn.as_ref())
                .await
                .map_err(|e| {
                    tracing::error!(primary_namespace, secondary_namespace, key, error = %e, "KVStore read failed");
                    io::Error::new(io::ErrorKind::Other, format!("Database read failed: {e}"))
                })?;

            match result {
                Some(record) => Ok(record.value),
                None => {
                    tracing::trace!(
                        primary_namespace,
                        secondary_namespace,
                        key,
                        "KVStore key not found"
                    );
                    Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"))
                }
            }
        })
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> AsyncResult<'static, (), io::Error> {
        tracing::trace!(
            primary_namespace,
            secondary_namespace,
            key,
            value_len = buf.len(),
            "KVStore write"
        );
        let conn = Arc::clone(&self.connection);
        let version = self.next_version();
        let key_lock = self.key_lock(primary_namespace, secondary_namespace, key);
        let primary_namespace = primary_namespace.to_string();
        let secondary_namespace = secondary_namespace.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let mut last_applied = key_lock.lock().await;
            if *last_applied > version {
                return Ok(());
            }
            let model = kv_store::ActiveModel {
                primary_namespace: ActiveValue::Set(primary_namespace.clone()),
                secondary_namespace: ActiveValue::Set(secondary_namespace.clone()),
                key: ActiveValue::Set(key.clone()),
                value: ActiveValue::Set(buf),
            };

            KvStore::insert(model)
                .on_conflict(
                    OnConflict::columns([
                        kv_store::Column::PrimaryNamespace,
                        kv_store::Column::SecondaryNamespace,
                        kv_store::Column::Key,
                    ])
                    .update_column(kv_store::Column::Value)
                    .to_owned(),
                )
                .exec(conn.as_ref())
                .await
                .map_err(|e| {
                    tracing::error!(primary_namespace, secondary_namespace, key, error = %e, "KVStore write failed");
                    io::Error::new(io::ErrorKind::Other, format!("Database write failed: {e}"))
                })?;

            *last_applied = version;

            Ok(())
        })
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> AsyncResult<'static, (), io::Error> {
        tracing::trace!(
            primary_namespace,
            secondary_namespace,
            key,
            lazy,
            "KVStore remove"
        );
        let conn = Arc::clone(&self.connection);
        let version = self.next_version();
        let key_lock = self.key_lock(primary_namespace, secondary_namespace, key);
        let primary_namespace = primary_namespace.to_string();
        let secondary_namespace = secondary_namespace.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let mut last_applied = key_lock.lock().await;
            if *last_applied > version {
                return Ok(());
            }
            KvStore::delete_many()
                .filter(kv_store::Column::PrimaryNamespace.eq(&primary_namespace))
                .filter(kv_store::Column::SecondaryNamespace.eq(&secondary_namespace))
                .filter(kv_store::Column::Key.eq(&key))
                .exec(conn.as_ref())
                .await
                .map_err(|e| {
                    tracing::error!(primary_namespace, secondary_namespace, key, error = %e, "KVStore remove failed");
                    io::Error::new(io::ErrorKind::Other, format!("Database delete failed: {e}"))
                })?;

            *last_applied = version;

            Ok(())
        })
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> AsyncResult<'static, Vec<String>, io::Error> {
        tracing::trace!(primary_namespace, secondary_namespace, "KVStore list");
        let conn = Arc::clone(&self.connection);
        let primary_namespace = primary_namespace.to_string();
        let secondary_namespace = secondary_namespace.to_string();
        Box::pin(async move {
            let results = KvStore::find()
                .filter(kv_store::Column::PrimaryNamespace.eq(&primary_namespace))
                .filter(kv_store::Column::SecondaryNamespace.eq(&secondary_namespace))
                .all(conn.as_ref())
                .await
                .map_err(|e| {
                    tracing::error!(primary_namespace, secondary_namespace, error = %e, "KVStore list failed");
                    io::Error::new(io::ErrorKind::Other, format!("Database list failed: {e}"))
                })?;

            Ok(results.into_iter().map(|r| r.key).collect())
        })
    }
}

impl KVStoreSync for SeaOrmKvStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, io::Error> {
        if is_wallet_config(primary_namespace, secondary_namespace) {
            if let Some(value) = self.wallet_config_cache.read().unwrap().get(key).cloned() {
                return Ok(value);
            }
        }
        block_on(KVStore::read(
            self,
            primary_namespace,
            secondary_namespace,
            key,
        ))
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), io::Error> {
        block_on(KVStore::write(
            self,
            primary_namespace,
            secondary_namespace,
            key,
            buf,
        ))
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> Result<(), io::Error> {
        block_on(KVStore::remove(
            self,
            primary_namespace,
            secondary_namespace,
            key,
            lazy,
        ))
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, io::Error> {
        block_on(KVStore::list(self, primary_namespace, secondary_namespace))
    }

    fn execute_batch(&self, primary_namespace: &str, ops: Vec<KvOp>) -> Result<(), io::Error> {
        let version = self.next_version();
        let op_key = |op: &KvOp| match op {
            KvOp::Write {
                secondary_namespace,
                key,
                ..
            }
            | KvOp::Remove {
                secondary_namespace,
                key,
            } => (secondary_namespace.clone(), key.clone()),
        };
        // acquire all touched key locks upfront in sorted order so concurrent batches can't deadlock
        let mut keys: Vec<(String, String)> = ops.iter().map(&op_key).collect();
        keys.sort();
        keys.dedup();
        let locks: Vec<Arc<TokioMutex<u64>>> = keys
            .iter()
            .map(|(sns, key)| self.key_lock(primary_namespace, sns, key))
            .collect();
        let conn = Arc::clone(&self.connection);
        let primary_namespace = primary_namespace.to_string();
        block_on(async move {
            let mut guards = Vec::with_capacity(locks.len());
            for lock in &locks {
                guards.push(lock.lock().await);
            }
            // ops share one version and form one logical write: if any touched key already
            // applied a newer version, skip the whole batch instead of applying it partially
            if guards.iter().any(|guard| **guard > version) {
                tracing::debug!(primary_namespace, "KVStore batch is stale, skipping");
                return Ok(());
            }
            let txn = conn.begin().await.map_err(|e| {
                tracing::error!(primary_namespace, error = %e, "KVStore batch begin failed");
                io::Error::new(io::ErrorKind::Other, format!("Database begin failed: {e}"))
            })?;
            for op in ops {
                match op {
                    KvOp::Write {
                        secondary_namespace,
                        key,
                        value,
                    } => {
                        tracing::trace!(
                            primary_namespace,
                            secondary_namespace,
                            key,
                            value_len = value.len(),
                            "KVStore batch write"
                        );
                        let model = kv_store::ActiveModel {
                            primary_namespace: ActiveValue::Set(primary_namespace.clone()),
                            secondary_namespace: ActiveValue::Set(secondary_namespace),
                            key: ActiveValue::Set(key),
                            value: ActiveValue::Set(value),
                        };
                        KvStore::insert(model)
                            .on_conflict(
                                OnConflict::columns([
                                    kv_store::Column::PrimaryNamespace,
                                    kv_store::Column::SecondaryNamespace,
                                    kv_store::Column::Key,
                                ])
                                .update_column(kv_store::Column::Value)
                                .to_owned(),
                            )
                            .exec(&txn)
                            .await
                            .map_err(|e| {
                                tracing::error!(primary_namespace, error = %e, "KVStore batch write failed");
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("Database write failed: {e}"),
                                )
                            })?;
                    }
                    KvOp::Remove {
                        secondary_namespace,
                        key,
                    } => {
                        tracing::trace!(
                            primary_namespace,
                            secondary_namespace,
                            key,
                            "KVStore batch remove"
                        );
                        KvStore::delete_many()
                            .filter(kv_store::Column::PrimaryNamespace.eq(&primary_namespace))
                            .filter(kv_store::Column::SecondaryNamespace.eq(&secondary_namespace))
                            .filter(kv_store::Column::Key.eq(&key))
                            .exec(&txn)
                            .await
                            .map_err(|e| {
                                tracing::error!(primary_namespace, error = %e, "KVStore batch remove failed");
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("Database delete failed: {e}"),
                                )
                            })?;
                    }
                }
            }
            txn.commit().await.map_err(|e| {
                tracing::error!(primary_namespace, error = %e, "KVStore batch commit failed");
                io::Error::new(io::ErrorKind::Other, format!("Database commit failed: {e}"))
            })?;
            for guard in guards.iter_mut() {
                **guard = version;
            }
            Ok(())
        })
    }
}
