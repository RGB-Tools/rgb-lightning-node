//! VSS integration tests
//!
//! Requires a running VSS server: `docker compose --profile vss up -d`
//! Run with: `cargo test --features vss vss_ -- --nocapture`

#[cfg(feature = "vss")]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};
    use hex::DisplayHex;
    use lightning::util::persist::KVStoreSync;
    use sea_orm::{ConnectOptions, Database};

    use crate::kv_store::SeaOrmKvStore;
    use crate::synced_kv_store::SyncedKvStore;
    use crate::vss_kv_store::{parse_vss_key, vss_key, VssKvStore};

    const VSS_URL: &str = "http://localhost:8081/vss";

    fn generate_test_keys() -> (SecretKey, String) {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        let store_id = format!("rln_test_{}", public_key.serialize()[0..8].as_hex());
        (secret_key, store_id)
    }

    fn vss_server_available() -> bool {
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:8081".parse().unwrap(),
            Duration::from_secs(2),
        )
        .is_ok()
    }

    fn create_test_sqlite() -> Arc<sea_orm::DatabaseConnection> {
        use rln_migration::MigratorTrait;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.keep();
        let db_path = path.join("test_rln_db");
        let conn_str = format!("sqlite:{}?mode=rwc", db_path.display());
        let mut opt = ConnectOptions::new(conn_str);
        opt.max_connections(1)
            .connect_timeout(Duration::from_secs(5));
        let db = crate::runtime::block_on(Database::connect(opt)).expect("test db");
        crate::runtime::block_on(rln_migration::Migrator::up(&db, None)).expect("migration");
        Arc::new(db)
    }

    // --- Unit tests ---

    #[test]
    fn vss_key_roundtrip() {
        let cases = vec![
            ("channel_manager", "", "manager"),
            ("", "", "inbound_payments"),
            ("monitors", "funding_txo", "abc123"),
            ("rgb", "inbound", "hash_pending"),
        ];
        for (primary, secondary, key) in cases {
            let encoded = vss_key(primary, secondary, key);
            let (p, s, k) = parse_vss_key(&encoded).expect("parse should succeed");
            assert_eq!(p, primary, "primary mismatch for key={encoded}");
            assert_eq!(s, secondary, "secondary mismatch for key={encoded}");
            assert_eq!(k, key, "key mismatch for key={encoded}");
        }
    }

    #[test]
    fn parse_vss_key_rejects_invalid() {
        assert!(parse_vss_key("no_slashes").is_none());
        assert!(parse_vss_key("one/slash").is_none());
        assert!(parse_vss_key("a/b/").is_none()); // empty key
    }

    // --- Integration tests (require VSS server) ---

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vss_kv_store_crud() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        let (signing_key, store_id) = generate_test_keys();
        let store = VssKvStore::new(VSS_URL.to_string(), store_id, signing_key).expect("vss store");

        let ns = "test_ns";
        let sub_ns = "sub";
        let key = "mykey";
        let data = b"hello vss world".to_vec();

        // Write
        store
            .write(ns, sub_ns, key, data.clone())
            .expect("write should succeed");

        // Read back
        let read_data = store.read(ns, sub_ns, key).expect("read should succeed");
        assert_eq!(read_data, data);

        // List
        let keys = store.list(ns, sub_ns).expect("list should succeed");
        assert!(keys.contains(&key.to_string()), "list should contain key");

        // Overwrite
        let data2 = b"updated value".to_vec();
        store
            .write(ns, sub_ns, key, data2.clone())
            .expect("overwrite should succeed");
        let read_data2 = store.read(ns, sub_ns, key).expect("re-read");
        assert_eq!(read_data2, data2);

        // Remove
        store
            .remove(ns, sub_ns, key, false)
            .expect("remove should succeed");
        let err = store.read(ns, sub_ns, key).unwrap_err();
        assert_eq!(err.kind(), bitcoin::io::ErrorKind::NotFound);

        // List after remove should be empty
        let keys = store.list(ns, sub_ns).expect("list after remove");
        assert!(!keys.contains(&key.to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vss_kv_store_multiple_namespaces() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        let (signing_key, store_id) = generate_test_keys();
        let store = VssKvStore::new(VSS_URL.to_string(), store_id, signing_key).expect("vss store");

        // Write to different namespaces (simulating LDK's real usage)
        store
            .write("channel_manager", "", "manager", b"cm_data".to_vec())
            .expect("write cm");
        store
            .write(
                "channel_monitors",
                "funding_abc",
                "monitor",
                b"mon_data".to_vec(),
            )
            .expect("write monitor");
        store
            .write("", "", "inbound_payments", b"payments".to_vec())
            .expect("write payments");

        // Read each back
        assert_eq!(
            store.read("channel_manager", "", "manager").unwrap(),
            b"cm_data"
        );
        assert_eq!(
            store
                .read("channel_monitors", "funding_abc", "monitor")
                .unwrap(),
            b"mon_data"
        );
        assert_eq!(store.read("", "", "inbound_payments").unwrap(), b"payments");

        // List in specific namespace
        let cm_keys = store.list("channel_manager", "").unwrap();
        assert_eq!(cm_keys, vec!["manager"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vss_kv_store_download_all() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        let (signing_key, store_id) = generate_test_keys();
        let store = VssKvStore::new(VSS_URL.to_string(), store_id, signing_key).expect("vss store");

        // Write several entries
        let entries = vec![
            ("ns1", "sub1", "key1", b"value1".to_vec()),
            ("ns1", "sub2", "key2", b"value2".to_vec()),
            ("ns2", "", "key3", b"value3".to_vec()),
            ("", "", "key4", b"value4".to_vec()),
        ];
        for (ns, sub, key, val) in &entries {
            store.write(ns, sub, key, val.clone()).expect("write");
        }

        // Download all
        let all = store.download_all().expect("download_all");
        assert_eq!(all.len(), entries.len());

        // Verify all entries are present (order may differ)
        for (ns, sub, key, val) in &entries {
            let vss_k = vss_key(ns, sub, key);
            let found = all.iter().find(|(k, _)| k == &vss_k);
            assert!(found.is_some(), "missing key: {vss_k}");
            assert_eq!(&found.unwrap().1, val, "value mismatch for {vss_k}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn synced_kv_store_backup_restore_cycle() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        let (signing_key, store_id) = generate_test_keys();

        // --- Phase 1: Write data through SyncedKvStore (local + VSS) ---
        let db1 = create_test_sqlite();
        let local1 = Arc::new(SeaOrmKvStore::from_connection(db1));
        let vss1 = Arc::new(
            VssKvStore::new(VSS_URL.to_string(), store_id.clone(), signing_key).expect("vss store"),
        );
        let synced1 = SyncedKvStore::with_vss(local1.clone(), vss1);

        // Simulate real LDK data patterns
        let test_data = vec![
            ("channel_manager", "", "manager", vec![0xCA; 256]),
            (
                "channel_monitors",
                "funding_tx_001",
                "monitor",
                vec![0xBE; 512],
            ),
            ("", "", "inbound_payments", vec![0xEF; 128]),
            ("", "", "outbound_payments", vec![0xAB; 64]),
            ("scorer", "", "scorer_data", vec![0xCD; 32]),
        ];

        for (ns, sub, key, val) in &test_data {
            synced1
                .write(ns, sub, key, val.clone())
                .expect("synced write");
        }

        // Verify local reads work
        for (ns, sub, key, val) in &test_data {
            let read = synced1.read(ns, sub, key).expect("local read");
            assert_eq!(&read, val);
        }

        // --- Phase 2: Create a FRESH local store + same VSS = simulate new device ---
        let db2 = create_test_sqlite();
        let local2 = Arc::new(SeaOrmKvStore::from_connection(db2));
        let vss2 = Arc::new(
            VssKvStore::new(VSS_URL.to_string(), store_id, signing_key).expect("vss store 2"),
        );
        let synced2 = SyncedKvStore::with_vss(local2.clone(), vss2);

        // Fresh local store should have nothing
        let err = synced2.read("channel_manager", "", "manager").unwrap_err();
        assert_eq!(err.kind(), bitcoin::io::ErrorKind::NotFound);

        // --- Phase 3: Restore from VSS ---
        let restored_count = synced2.restore_from_vss(true).expect("restore");
        assert_eq!(restored_count, test_data.len());

        // --- Phase 4: Verify all data matches after restore ---
        for (ns, sub, key, val) in &test_data {
            let read = synced2.read(ns, sub, key).expect("post-restore read");
            assert_eq!(&read, val, "mismatch after restore: {ns}/{sub}/{key}");
        }

        // List should also work
        let cm_keys = synced2.list("channel_manager", "").expect("list");
        assert_eq!(cm_keys, vec!["manager"]);
    }

    /// Edge case: VSS server unreachable. Writes must still succeed locally
    /// (the local store is authoritative) and the failed replication must be
    /// queued for later retry. Does not require a running VSS server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn synced_kv_store_degrades_when_vss_unreachable() {
        let (signing_key, store_id) = generate_test_keys();
        let local = Arc::new(SeaOrmKvStore::from_connection(create_test_sqlite()));
        // Nothing is listening here, so every VSS request fails fast.
        let unreachable = Arc::new(
            VssKvStore::new("http://127.0.0.1:5/vss".to_string(), store_id, signing_key)
                .expect("vss store"),
        );
        let synced = SyncedKvStore::with_vss(local, unreachable);

        // Local write succeeds even though VSS is down.
        synced
            .write("channel_manager", "", "manager", b"cm_data".to_vec())
            .expect("local write should succeed while VSS is unreachable");

        // Data is immediately readable from the local store.
        assert_eq!(
            synced.read("channel_manager", "", "manager").unwrap(),
            b"cm_data"
        );

        // The failed replication was queued for retry.
        assert!(
            synced.pending_remote_writes() > 0,
            "failed VSS write should be queued for retry"
        );
    }

    /// Edge case: node shutdown and recovery on a fresh device using the
    /// production default (`force = false`). An empty local store is
    /// repopulated from VSS; a second restore is a no-op so existing state is
    /// never clobbered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn synced_kv_store_recovers_with_default_guard() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        // The restore guard keys off LDK's real channel-manager location, so
        // store the manager under exactly that namespace/key.
        use lightning::util::persist::{
            CHANNEL_MANAGER_PERSISTENCE_KEY, CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
            CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
        };

        let (signing_key, store_id) = generate_test_keys();

        // Original node: persist some state (local + VSS), then "shut down".
        let original = SyncedKvStore::with_vss(
            Arc::new(SeaOrmKvStore::from_connection(create_test_sqlite())),
            Arc::new(
                VssKvStore::new(VSS_URL.to_string(), store_id.clone(), signing_key)
                    .expect("vss store"),
            ),
        );
        let state = vec![
            (
                CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
                CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
                CHANNEL_MANAGER_PERSISTENCE_KEY,
                vec![0x11; 128],
            ),
            (
                "channel_monitors",
                "funding_xyz",
                "monitor",
                vec![0x22; 256],
            ),
        ];
        for (ns, sub, key, val) in &state {
            original.write(ns, sub, key, val.clone()).expect("write");
        }
        drop(original);

        // Recovery on a fresh device: empty local store, same VSS URL + key.
        let recovered = SyncedKvStore::with_vss(
            Arc::new(SeaOrmKvStore::from_connection(create_test_sqlite())),
            Arc::new(
                VssKvStore::new(VSS_URL.to_string(), store_id, signing_key).expect("vss store"),
            ),
        );

        // Production default (force = false) restores because local is empty.
        let restored = recovered.restore_from_vss(false).expect("restore");
        assert_eq!(restored, state.len());
        for (ns, sub, key, val) in &state {
            assert_eq!(
                &recovered.read(ns, sub, key).unwrap(),
                val,
                "{ns}/{sub}/{key}"
            );
        }

        // Second restore is a no-op: local now holds channel-manager state, so
        // force = false must refuse to clobber it.
        let again = recovered.restore_from_vss(false).expect("second restore");
        assert_eq!(again, 0, "force=false must not re-clobber populated state");
    }

    /// Helper to create a minimal wallet zip (required format for VssBackupClient)
    fn create_test_wallet_zip(fingerprint: &str, payload: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.add_directory(format!("{fingerprint}/"), opts).unwrap();
            zip.start_file(format!("{fingerprint}/test_data.bin"), opts)
                .unwrap();
            zip.write_all(payload).unwrap();
            zip.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn vss_backup_client_encrypted_roundtrip() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        let (signing_key, store_id) = generate_test_keys();
        let config =
            rgb_lib::wallet::vss::VssBackupConfig::new(VSS_URL.to_string(), store_id, signing_key)
                .with_encryption(true);

        let client = rgb_lib::wallet::vss::VssBackupClient::new(config).expect("encrypted client");
        assert!(client.encryption_enabled());

        let fingerprint = "a1b2c3d4";
        let original_payload = b"encrypted secret channel data for testing";
        let zip_data = create_test_wallet_zip(fingerprint, original_payload);

        let rt = client.handle().clone();

        // Upload encrypted
        let version = rt
            .block_on(client.upload_backup(zip_data.clone()))
            .expect("upload encrypted backup");
        assert!(version > 0);

        // Download and decrypt
        let downloaded = rt
            .block_on(client.download_backup())
            .expect("download encrypted backup");

        // Verify content matches original zip
        assert_eq!(downloaded, zip_data);

        // Cleanup
        rt.block_on(client.delete_backup()).expect("cleanup");
    }

    #[test]
    fn vss_backup_client_unencrypted_roundtrip() {
        if !vss_server_available() {
            eprintln!("SKIP: VSS server not available at {VSS_URL}");
            return;
        }

        let (signing_key, store_id) = generate_test_keys();
        let config =
            rgb_lib::wallet::vss::VssBackupConfig::new(VSS_URL.to_string(), store_id, signing_key)
                .with_encryption(false);

        let client =
            rgb_lib::wallet::vss::VssBackupClient::new(config).expect("unencrypted client");
        assert!(!client.encryption_enabled());

        let fingerprint = "e5f6a7b8";
        let original_payload = b"plaintext channel data for unencrypted backup test";
        let zip_data = create_test_wallet_zip(fingerprint, original_payload);

        let rt = client.handle().clone();

        // Upload unencrypted (sanitized — fingerprint stripped, bdk_db excluded)
        let version = rt
            .block_on(client.upload_backup(zip_data.clone()))
            .expect("upload unencrypted backup");
        assert!(version > 0);

        // Download — returns sanitized zip (fingerprint replaced with "wallet/")
        let downloaded = rt
            .block_on(client.download_backup())
            .expect("download unencrypted backup");

        // For unencrypted backups, the zip is sanitized:
        // - fingerprint dir replaced with "wallet/"
        // - bdk_db files excluded
        // So downloaded != original zip, but the test data file should be preserved
        let reader = std::io::Cursor::new(&downloaded);
        let mut archive = zip::ZipArchive::new(reader).expect("valid zip");

        let mut found_data = false;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let name = entry.name().to_string();
            // Fingerprint should be replaced with "wallet/"
            assert!(
                !name.contains(fingerprint),
                "sanitized zip should not contain original fingerprint, found: {name}"
            );
            if name.ends_with("test_data.bin") {
                found_data = true;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
                assert_eq!(buf, original_payload, "payload content mismatch");
            }
        }
        assert!(found_data, "test_data.bin should be in sanitized zip");

        // Cleanup
        rt.block_on(client.delete_backup()).expect("cleanup");
    }
}
