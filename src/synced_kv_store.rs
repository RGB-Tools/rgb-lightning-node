use std::sync::Arc;

use bitcoin::io;
use lightning::util::persist::KVStoreSync;

use crate::kv_store::SeaOrmKvStore;

/// Maximum number of writes the pending-retry queue is allowed to hold.
///
/// When this cap is reached we drop the oldest entry per key (newest write
/// wins for any given key — channel-monitor persistence is last-write-wins
/// anyway). Bounds memory under prolonged VSS outage while still preserving
/// the latest state for each touched key.
#[cfg(feature = "vss")]
const PENDING_QUEUE_CAP: usize = 1000;

/// How many pending entries to attempt to drain on each successful VSS write.
#[cfg(feature = "vss")]
const PENDING_DRAIN_BATCH: usize = 16;

/// KVStore wrapper that writes to the local SeaORM store and (optionally)
/// replicates to a remote VSS server. Reads always go to the local store for
/// latency. When `remote` is `None`, this behaves identically to a plain
/// `SeaOrmKvStore`.
pub struct SyncedKvStore {
    local: Arc<SeaOrmKvStore>,
    #[cfg(feature = "vss")]
    remote: Option<Arc<crate::vss_kv_store::VssKvStore>>,
    /// VSS-replication failures park here so a transient outage doesn't lose
    /// state from the remote backup. Each successful VSS write drains up to
    /// [`PENDING_DRAIN_BATCH`] entries; the map is capped at
    /// [`PENDING_QUEUE_CAP`].
    ///
    /// Key: encoded VSS key string (same format as `vss_key()`).
    /// Value: bytes that should be re-written to VSS. `None` represents a
    /// pending removal (so a later write to the same key supersedes the
    /// removal correctly).
    #[cfg(feature = "vss")]
    pending: Arc<std::sync::Mutex<std::collections::HashMap<String, Option<Vec<u8>>>>>,
}

impl SyncedKvStore {
    /// Creates a SyncedKvStore with local-only storage (no VSS replication).
    pub fn local_only(local: Arc<SeaOrmKvStore>) -> Self {
        Self {
            local,
            #[cfg(feature = "vss")]
            remote: None,
            #[cfg(feature = "vss")]
            pending: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Creates a SyncedKvStore with local storage and VSS replication.
    #[cfg(feature = "vss")]
    pub fn with_vss(
        local: Arc<SeaOrmKvStore>,
        remote: Arc<crate::vss_kv_store::VssKvStore>,
    ) -> Self {
        Self {
            local,
            remote: Some(remote),
            pending: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Restores all key-value pairs from VSS into the local store.
    ///
    /// `force = false` is the safe default and returns `Ok(0)` if the local
    /// store already has a channel-manager key (i.e. it's not a fresh
    /// device). `force = true` overwrites local state with whatever VSS holds
    /// and is intended only for explicit operator use.
    ///
    /// Returns the number of keys restored, or 0 if VSS is not configured or
    /// the local store is already populated.
    #[cfg(feature = "vss")]
    pub(crate) fn restore_from_vss(&self, force: bool) -> Result<usize, io::Error> {
        let Some(ref remote) = self.remote else {
            return Ok(0);
        };

        if !force {
            // Guard: refuse to clobber an already-populated local store.
            // The caller in `start_ldk` also performs this check, but a
            // belt-and-suspenders guard makes this API hard to misuse.
            use lightning::util::persist::{
                CHANNEL_MANAGER_PERSISTENCE_KEY, CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
                CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
            };
            if self
                .local
                .read(
                    CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
                    CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
                    CHANNEL_MANAGER_PERSISTENCE_KEY,
                )
                .is_ok()
            {
                tracing::info!(
                    "VSS restore skipped: local store already has channel manager data \
                     (pass force=true to override)"
                );
                return Ok(0);
            }
        }

        tracing::info!("Starting restore from VSS...");
        let items = remote.download_all()?;
        let total = items.len();
        let mut restored = 0usize;

        for (vss_key_str, value) in items {
            if let Some((primary_ns, secondary_ns, key)) =
                crate::vss_kv_store::parse_vss_key(&vss_key_str)
            {
                if let Err(e) = self.local.write(&primary_ns, &secondary_ns, &key, value) {
                    tracing::warn!(
                        vss_key = vss_key_str,
                        error = %e,
                        "Failed to restore key to local store"
                    );
                } else {
                    restored += 1;
                }
            } else {
                tracing::warn!(
                    vss_key = vss_key_str,
                    "Skipping unrecognized VSS key format"
                );
            }
        }

        tracing::info!(restored, total, "VSS restore complete");
        Ok(restored)
    }

    /// Returns the number of pending VSS-replication entries that failed and
    /// are awaiting retry. Surfaced via `/vssbackupinfo` so operators can
    /// alert on persistent backup-staleness.
    #[cfg(feature = "vss")]
    pub fn pending_remote_writes(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Enqueue a failed VSS replication for later retry.
    #[cfg(feature = "vss")]
    fn enqueue_pending(&self, vss_key: String, value: Option<Vec<u8>>) {
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= PENDING_QUEUE_CAP && !pending.contains_key(&vss_key) {
            // Drop one entry to make room. HashMap iteration order is
            // arbitrary; for "drop newest of the same key" we still want the
            // newer value for that key, so we just evict an arbitrary other
            // key. Logged as a metric so the operator can alert on it.
            if let Some(evict) = pending.keys().next().cloned() {
                pending.remove(&evict);
                tracing::warn!(
                    evicted_key = evict,
                    cap = PENDING_QUEUE_CAP,
                    "VSS pending-writes queue at cap; evicted an entry to make room"
                );
            }
        }
        pending.insert(vss_key, value);
    }

    /// Attempt to drain up to [`PENDING_DRAIN_BATCH`] entries from the
    /// pending queue. Called opportunistically after each successful VSS
    /// write. Entries that re-fail are re-queued.
    #[cfg(feature = "vss")]
    fn drain_pending(&self) {
        let Some(ref remote) = self.remote else {
            return;
        };
        let to_retry: Vec<(String, Option<Vec<u8>>)> = {
            let mut pending = self.pending.lock().unwrap();
            let take_n = pending.len().min(PENDING_DRAIN_BATCH);
            let keys: Vec<String> = pending.keys().take(take_n).cloned().collect();
            keys.into_iter()
                .filter_map(|k| pending.remove(&k).map(|v| (k, v)))
                .collect()
        };
        if to_retry.is_empty() {
            return;
        }
        let drained = to_retry.len();
        for (vss_key, value) in to_retry {
            let parsed = crate::vss_kv_store::parse_vss_key(&vss_key);
            let Some((primary, secondary, key)) = parsed else {
                tracing::warn!(vss_key, "Dropping unparseable key from pending queue");
                continue;
            };
            let result = match &value {
                Some(buf) => remote.write(&primary, &secondary, &key, buf.clone()),
                None => remote.remove(&primary, &secondary, &key, false),
            };
            if let Err(e) = result {
                tracing::debug!(
                    vss_key,
                    error = %e,
                    "Pending VSS replication still failing; re-queued"
                );
                self.enqueue_pending(vss_key, value);
            }
        }
        tracing::debug!(drained, "Drained pending VSS writes");
    }
}

impl KVStoreSync for SyncedKvStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, io::Error> {
        // Always read from local store
        self.local.read(primary_namespace, secondary_namespace, key)
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), io::Error> {
        // Write to local first (must succeed)
        self.local
            .write(primary_namespace, secondary_namespace, key, buf.clone())?;

        // Replicate to VSS (best-effort, queue for retry on failure).
        #[cfg(feature = "vss")]
        if let Some(ref remote) = self.remote {
            match remote.write(primary_namespace, secondary_namespace, key, buf.clone()) {
                Ok(()) => {
                    self.drain_pending();
                }
                Err(e) => {
                    tracing::warn!(
                        primary_namespace,
                        secondary_namespace,
                        key,
                        error = %e,
                        "VSS replication write failed; queued for retry"
                    );
                    let vss_key =
                        crate::vss_kv_store::vss_key(primary_namespace, secondary_namespace, key);
                    self.enqueue_pending(vss_key, Some(buf));
                }
            }
        }

        Ok(())
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> Result<(), io::Error> {
        // Remove from local first (must succeed)
        self.local
            .remove(primary_namespace, secondary_namespace, key, lazy)?;

        // Replicate removal to VSS (best-effort, queue for retry on failure).
        #[cfg(feature = "vss")]
        if let Some(ref remote) = self.remote {
            match remote.remove(primary_namespace, secondary_namespace, key, lazy) {
                Ok(()) => {
                    self.drain_pending();
                }
                Err(e) => {
                    tracing::warn!(
                        primary_namespace,
                        secondary_namespace,
                        key,
                        error = %e,
                        "VSS replication remove failed; queued for retry"
                    );
                    let vss_key =
                        crate::vss_kv_store::vss_key(primary_namespace, secondary_namespace, key);
                    self.enqueue_pending(vss_key, None);
                }
            }
        }

        Ok(())
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, io::Error> {
        // Always list from local store
        self.local.list(primary_namespace, secondary_namespace)
    }
}
