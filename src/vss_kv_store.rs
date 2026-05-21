use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::io;
use bitcoin::secp256k1::SecretKey;
use futures::stream::{FuturesUnordered, StreamExt};
use hex::DisplayHex;
use lightning::util::persist::KVStoreSync;
use rgb_lib::wallet::vss::{decrypt_data, encrypt_data, VssEncryptionMetadata};
use uuid::Uuid;
use vss_client::client::VssClient;
use vss_client::error::VssError;
use vss_client::headers::sigs_auth::SigsAuthProvider;
use vss_client::types::{GetObjectRequest, KeyValue, ListKeyVersionsRequest, PutObjectRequest};
use vss_client::util::retry::{
    ExponentialBackoffRetryPolicy, MaxAttemptsRetryPolicy, MaxTotalDelayRetryPolicy, RetryPolicy,
};

/// Type alias for the retry policy used by VssClient.
type VssRetryPolicy =
    MaxTotalDelayRetryPolicy<MaxAttemptsRetryPolicy<ExponentialBackoffRetryPolicy<VssError>>>;

/// Result of a single VSS get-object during a paged `download_all`. `Ok(None)`
/// means the key disappeared between list and get (race; benign).
type FetchResult = Result<Option<(String, Vec<u8>)>, VssError>;

/// HKDF info tag used to derive this KV stream's per-value encryption key.
/// Domain-separates it from rgb-lib's wallet-backup stream so the two derived
/// keys are distinct even when the signing key and salt happen to match.
const VSS_KV_HKDF_INFO: &[u8] = b"rgb-ln-vss-kv-encryption-v1";

/// Wire-format version for inline-encrypted values stored on VSS.
const VSS_KV_FORMAT_VERSION: u8 = 1;

/// Raw salt length (matches rgb-lib's `BACKUP_SALT_LENGTH`).
const SALT_LEN: usize = 32;

/// Raw nonce length (matches rgb-lib's `BACKUP_NONCE_LENGTH`).
const NONCE_LEN: usize = 19;

/// Total header length: [1-byte version][32-byte salt][19-byte nonce].
const HEADER_LEN: usize = 1 + SALT_LEN + NONCE_LEN;

/// VSS key that holds the single-writer fencing token. Anything that writes to
/// this store_id must hold this token; on takeover the new owner has to delete
/// this key explicitly.
const FENCE_KEY: &str = "__rln_instance__";

/// How many writes between periodic fence re-checks.
///
/// The startup fence acquire catches the common case (another instance is
/// already running); a periodic re-check catches the rare case where the fence
/// key was deleted out-of-band while we kept running.
const FENCE_CHECK_INTERVAL: u64 = 100;

/// KVStore implementation backed by a VSS (Versioned Storage Service) server.
///
/// Maps the `(primary_namespace, secondary_namespace, key)` triple used by
/// `lightning::util::persist::KVStoreSync` to a single VSS key string.
/// Values are always encrypted at rest with XChaCha20-Poly1305 (key derived
/// from `signing_key` via HKDF-SHA256).
pub struct VssKvStore {
    client: VssClient<VssRetryPolicy>,
    store_id: String,
    signing_key: SecretKey,
    /// Per-process identity used by [`Self::acquire_fence`] and the periodic
    /// fence re-check.
    instance_id: Uuid,
    /// Counter incremented on every write; modulo [`FENCE_CHECK_INTERVAL`] is
    /// used to schedule periodic fence re-checks.
    write_counter: std::sync::atomic::AtomicU64,
}

impl VssKvStore {
    /// Creates a new VssKvStore connected to the given VSS server.
    ///
    /// # Arguments
    /// * `server_url` - VSS server URL (e.g., "http://localhost:8081/vss")
    /// * `store_id` - Keyspace identifier (derived from node pubkey)
    /// * `signing_key` - Secret key used both for sigs-auth and for deriving
    ///   the per-value encryption key via HKDF-SHA256.
    pub fn new(
        server_url: String,
        store_id: String,
        signing_key: SecretKey,
    ) -> Result<Self, io::Error> {
        let auth_provider = SigsAuthProvider::new(signing_key, HashMap::new());

        let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100))
            .with_max_attempts(3)
            .with_max_total_delay(Duration::from_secs(5));

        let client = VssClient::new_with_headers(server_url, retry_policy, Arc::new(auth_provider));

        Ok(Self {
            client,
            store_id,
            signing_key,
            instance_id: Uuid::new_v4(),
            write_counter: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Runs an async future to completion using the ambient Tokio runtime
    /// (which must be multi-threaded — `#[tokio::main]` in `src/main.rs`
    /// satisfies this).
    fn block_on<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }

    /// Encrypt a value for storage on VSS using the inline wire format
    /// `[version|salt|nonce|ciphertext]`.
    fn encrypt_value(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        let salt_bytes: [u8; SALT_LEN] = rand::random();
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let metadata = VssEncryptionMetadata {
            salt: salt_bytes.as_hex().to_string(),
            nonce: nonce_bytes.as_hex().to_string(),
            version: VSS_KV_FORMAT_VERSION,
        };
        let ciphertext = encrypt_data(
            &plaintext,
            &self.signing_key,
            &metadata,
            Some(VSS_KV_HKDF_INFO),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("VSS encrypt failed: {e}")))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.push(VSS_KV_FORMAT_VERSION);
        out.extend_from_slice(&salt_bytes);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a value retrieved from VSS.
    fn decrypt_value(&self, stored: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        if stored.len() < HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VSS decrypt: stored value shorter than header",
            ));
        }
        let version = stored[0];
        if version != VSS_KV_FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("VSS decrypt: unknown wire format version {version}"),
            ));
        }
        let salt = &stored[1..1 + SALT_LEN];
        let nonce = &stored[1 + SALT_LEN..HEADER_LEN];
        let ciphertext = &stored[HEADER_LEN..];
        let metadata = VssEncryptionMetadata {
            salt: salt.as_hex().to_string(),
            nonce: nonce.as_hex().to_string(),
            version,
        };
        decrypt_data(
            ciphertext,
            &self.signing_key,
            &metadata,
            Some(VSS_KV_HKDF_INFO),
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("VSS decrypt failed: {e}"),
            )
        })
    }

    /// Acquires the single-writer fence for this `store_id`.
    ///
    /// Read the fence key first; if another instance owns it, refuse to
    /// proceed (the operator must clear the fence by hand). If no fence
    /// exists, try to claim it with a conditional create (`version = 0`); a
    /// `ConflictError` means a concurrent instance won the race.
    pub fn acquire_fence(&self) -> Result<(), io::Error> {
        let get_req = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: FENCE_KEY.to_string(),
        };
        match self.block_on(self.client.get_object(&get_req)) {
            Ok(resp) => {
                if let Some(kv) = resp.value {
                    let remote_id = String::from_utf8_lossy(&kv.value).to_string();
                    if remote_id == self.instance_id.to_string() {
                        return Ok(());
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "VSS store_id is owned by another rgb-lightning-node \
                             instance ({remote_id}). Refusing to start to avoid \
                             concurrent-writer corruption. If this previous owner \
                             is definitively gone and you want to take over, \
                             delete the `{FENCE_KEY}` key from VSS first."
                        ),
                    ));
                }
            }
            Err(VssError::NoSuchKeyError(_)) => {}
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("VSS fence read failed: {e}"),
                ));
            }
        }

        let put_req = PutObjectRequest {
            store_id: self.store_id.clone(),
            global_version: None,
            transaction_items: vec![KeyValue {
                key: FENCE_KEY.to_string(),
                version: 0,
                value: self.instance_id.to_string().into_bytes(),
            }],
            delete_items: vec![],
        };
        match self.block_on(self.client.put_object(&put_req)) {
            Ok(_) => {
                tracing::info!(
                    instance_id = %self.instance_id,
                    "VSS fence acquired"
                );
                Ok(())
            }
            Err(VssError::ConflictError(_)) => Err(io::Error::new(
                io::ErrorKind::Other,
                "VSS fence: another instance won the race to claim this store_id",
            )),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("VSS fence acquire failed: {e}"),
            )),
        }
    }

    /// Periodic re-check of the fence; panics if the fence has been taken over
    /// by another instance, since at that point our writes would corrupt the
    /// other instance's state.
    fn check_fence_periodic(&self) {
        let counter = self
            .write_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if counter == 0 || !counter.is_multiple_of(FENCE_CHECK_INTERVAL) {
            return;
        }
        let get_req = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: FENCE_KEY.to_string(),
        };
        match self.block_on(self.client.get_object(&get_req)) {
            Ok(resp) => {
                if let Some(kv) = resp.value {
                    let remote_id = String::from_utf8_lossy(&kv.value).to_string();
                    if remote_id != self.instance_id.to_string() {
                        panic!(
                            "VSS fence broken: another instance ({remote_id}) has \
                             taken over store_id; refusing to continue writing to \
                             avoid corrupting their state"
                        );
                    }
                } else {
                    tracing::warn!(
                        "VSS fence key disappeared mid-session; another operator \
                         may have cleared it"
                    );
                }
            }
            Err(VssError::NoSuchKeyError(_)) => {
                tracing::warn!(
                    "VSS fence key missing mid-session; another operator may have \
                     cleared it"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "VSS fence periodic check failed");
            }
        }
    }

    /// Downloads all key-value pairs from VSS for this store_id, decrypting
    /// each value. Used for restore operations.
    pub fn download_all(&self) -> Result<Vec<(String, Vec<u8>)>, io::Error> {
        let mut all_items = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let list_req = ListKeyVersionsRequest {
                store_id: self.store_id.clone(),
                key_prefix: None,
                page_size: None,
                page_token: page_token.clone(),
            };
            let response = self
                .block_on(self.client.list_key_versions(&list_req))
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("VSS list_key_versions failed: {e}"),
                    )
                })?;

            // Fetch values for the keys in this page concurrently. VSS
            // returns one page at a time and pages are typically small, so we
            // run them through `FuturesUnordered` to avoid the N+1 RTT of the
            // previous serial implementation. Note: the network library
            // (vss-client) does its own connection pooling, so we don't add
            // an extra concurrency cap beyond the page size.
            let keys: Vec<String> = response
                .key_versions
                .iter()
                .map(|kv| kv.key.clone())
                .filter(|k| k != FENCE_KEY)
                .collect();
            let store_id = self.store_id.clone();
            let client = &self.client;
            let fetched: Vec<FetchResult> = self.block_on(async move {
                let mut in_flight: FuturesUnordered<_> = keys
                    .into_iter()
                    .map(|key| {
                        let req = GetObjectRequest {
                            store_id: store_id.clone(),
                            key,
                        };
                        async move {
                            match client.get_object(&req).await {
                                Ok(resp) => Ok(resp.value.map(|kv| (kv.key, kv.value))),
                                Err(VssError::NoSuchKeyError(_)) => Ok(None),
                                Err(e) => Err(e),
                            }
                        }
                    })
                    .collect();
                let mut out = Vec::with_capacity(in_flight.len());
                while let Some(res) = in_flight.next().await {
                    out.push(res);
                }
                out
            });

            for item in fetched {
                match item {
                    Ok(Some((key, raw))) => {
                        let plaintext = self.decrypt_value(raw)?;
                        all_items.push((key, plaintext));
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("VSS get_object failed during download_all: {e}"),
                        ));
                    }
                }
            }

            let next_token: Option<String> = response.next_page_token;
            match next_token {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => break,
            }
        }

        Ok(all_items)
    }
}

/// Encode a `(primary_namespace, secondary_namespace, key)` triple as a
/// single VSS key string.
///
/// Format: `{primary_ns}/{secondary_ns}/{key}` where empty namespaces become `_`.
pub(crate) fn vss_key(primary_namespace: &str, secondary_namespace: &str, key: &str) -> String {
    let primary = if primary_namespace.is_empty() {
        "_"
    } else {
        primary_namespace
    };
    let secondary = if secondary_namespace.is_empty() {
        "_"
    } else {
        secondary_namespace
    };
    format!("{primary}/{secondary}/{key}")
}

/// Parses a VSS key back into (primary_namespace, secondary_namespace, key).
///
/// Returns `None` if the key doesn't match the expected format.
pub(crate) fn parse_vss_key(vss_key: &str) -> Option<(String, String, String)> {
    let mut parts = vss_key.splitn(3, '/');
    let primary = parts.next()?;
    let secondary = parts.next()?;
    let key = parts.next()?;
    if key.is_empty() {
        return None;
    }
    let primary = if primary == "_" {
        String::new()
    } else {
        primary.to_string()
    };
    let secondary = if secondary == "_" {
        String::new()
    } else {
        secondary.to_string()
    };
    Some((primary, secondary, key.to_string()))
}

/// Returns the VSS key prefix for listing all keys in a namespace.
fn vss_key_prefix(primary_namespace: &str, secondary_namespace: &str) -> String {
    let primary = if primary_namespace.is_empty() {
        "_"
    } else {
        primary_namespace
    };
    let secondary = if secondary_namespace.is_empty() {
        "_"
    } else {
        secondary_namespace
    };
    format!("{primary}/{secondary}/")
}

impl KVStoreSync for VssKvStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, io::Error> {
        let vss_key = vss_key(primary_namespace, secondary_namespace, key);
        tracing::trace!(vss_key, "VssKvStore read");

        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: vss_key.clone(),
        };

        let response = self.block_on(self.client.get_object(&request));

        match response {
            Ok(resp) => {
                if let Some(kv) = resp.value {
                    self.decrypt_value(kv.value)
                } else {
                    Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"))
                }
            }
            Err(VssError::NoSuchKeyError(_)) => {
                Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"))
            }
            Err(e) => {
                tracing::error!(vss_key, error = %e, "VssKvStore read failed");
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("VSS read failed: {e}"),
                ))
            }
        }
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), io::Error> {
        let vss_key = vss_key(primary_namespace, secondary_namespace, key);
        tracing::trace!(vss_key, value_len = buf.len(), "VssKvStore write");

        self.check_fence_periodic();

        let stored = self.encrypt_value(buf)?;

        // Use non-conditional writes (version = -1) so high-frequency monitor
        // updates don't fail on version conflicts. Concurrent writer safety
        // is provided by [`acquire_fence`] + periodic re-checks rather than
        // by VSS's optimistic locking.
        let request = PutObjectRequest {
            store_id: self.store_id.clone(),
            global_version: None,
            transaction_items: vec![KeyValue {
                key: vss_key.clone(),
                version: -1,
                value: stored,
            }],
            delete_items: vec![],
        };

        self.block_on(self.client.put_object(&request))
            .map_err(|e| {
                tracing::error!(vss_key, error = %e, "VssKvStore write failed");
                io::Error::new(io::ErrorKind::Other, format!("VSS write failed: {e}"))
            })?;
        Ok(())
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        _lazy: bool,
    ) -> Result<(), io::Error> {
        let vss_key = vss_key(primary_namespace, secondary_namespace, key);
        tracing::trace!(vss_key, "VssKvStore remove");

        self.check_fence_periodic();

        let request = PutObjectRequest {
            store_id: self.store_id.clone(),
            global_version: None,
            transaction_items: vec![],
            delete_items: vec![KeyValue {
                key: vss_key.clone(),
                version: -1,
                value: vec![],
            }],
        };

        self.block_on(self.client.put_object(&request))
            .map_err(|e| {
                tracing::error!(vss_key, error = %e, "VssKvStore remove failed");
                io::Error::new(io::ErrorKind::Other, format!("VSS remove failed: {e}"))
            })?;
        Ok(())
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, io::Error> {
        let prefix = vss_key_prefix(primary_namespace, secondary_namespace);
        tracing::trace!(prefix, "VssKvStore list");

        let mut keys = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let request = ListKeyVersionsRequest {
                store_id: self.store_id.clone(),
                key_prefix: Some(prefix.clone()),
                page_size: None,
                page_token: page_token.clone(),
            };

            let response = self
                .block_on(self.client.list_key_versions(&request))
                .map_err(|e| {
                    tracing::error!(prefix, error = %e, "VssKvStore list failed");
                    io::Error::new(io::ErrorKind::Other, format!("VSS list failed: {e}"))
                })?;

            for kv in &response.key_versions {
                let kv_key: &str = &kv.key;
                if kv_key == FENCE_KEY {
                    continue;
                }
                if let Some(key_name) = kv_key.strip_prefix(prefix.as_str()) {
                    keys.push(key_name.to_string());
                }
            }

            let next_token: Option<String> = response.next_page_token;
            match next_token {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => break,
            }
        }

        Ok(keys)
    }
}
