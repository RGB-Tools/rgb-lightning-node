use lightning::rgb_utils::{
    BITCOIN_NETWORK_FNAME, INDEXER_URL_FNAME, RGB_PAYMENT_INFO_INBOUND_NS,
    RGB_PAYMENT_INFO_OUTBOUND_NS, RGB_PRIMARY_NS, RGB_WALLET_CONFIG_NS,
};
use lightning::util::persist::{KVStore, KVStoreSync, KvOp};
use rln_migration::{Migrator, MigratorTrait};

use crate::kv_store::SeaOrmKvStore;

use super::*;

async fn test_store() -> SeaOrmKvStore {
    let conn = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&conn, None).await.unwrap();
    SeaOrmKvStore::from_connection(Arc::new(conn))
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_write_is_skipped() {
    let store = test_store().await;
    let f_old = KVStore::write(&store, "ns", "sub", "k", vec![1]);
    let f_new = KVStore::write(&store, "ns", "sub", "k", vec![2]);
    f_new.await.unwrap();
    f_old.await.unwrap();
    assert_eq!(
        KVStore::read(&store, "ns", "sub", "k").await.unwrap(),
        vec![2]
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_remove_is_skipped() {
    let store = test_store().await;
    KVStore::write(&store, "ns", "sub", "k", vec![1])
        .await
        .unwrap();
    let f_old = KVStore::remove(&store, "ns", "sub", "k", false);
    let f_new = KVStore::write(&store, "ns", "sub", "k", vec![2]);
    f_new.await.unwrap();
    f_old.await.unwrap();
    assert_eq!(
        KVStore::read(&store, "ns", "sub", "k").await.unwrap(),
        vec![2]
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_batch_is_skipped_entirely() {
    let store = test_store().await;
    KVStore::write(&store, "rgb", "sub", "a", vec![1])
        .await
        .unwrap();
    // simulate a newer write already applied to "b"
    store.force_key_version("rgb", "sub", "b", u64::MAX);
    KVStoreSync::execute_batch(
        &store,
        "rgb",
        vec![
            KvOp::Write {
                secondary_namespace: "sub".to_string(),
                key: "a".to_string(),
                value: vec![9],
            },
            KvOp::Write {
                secondary_namespace: "sub".to_string(),
                key: "b".to_string(),
                value: vec![9],
            },
        ],
    )
    .unwrap();
    // one stale key voids the whole batch
    assert_eq!(
        KVStore::read(&store, "rgb", "sub", "a").await.unwrap(),
        vec![1]
    );
    assert!(KVStore::read(&store, "rgb", "sub", "b").await.is_err());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_batch_applies_all_ops() {
    let store = test_store().await;
    KVStore::write(&store, "rgb", "sub", "stale", vec![0])
        .await
        .unwrap();
    KVStoreSync::execute_batch(
        &store,
        "rgb",
        vec![
            KvOp::Write {
                secondary_namespace: "sub".to_string(),
                key: "a".to_string(),
                value: vec![1],
            },
            KvOp::Write {
                secondary_namespace: "other".to_string(),
                key: "b".to_string(),
                value: vec![2],
            },
            KvOp::Remove {
                secondary_namespace: "sub".to_string(),
                key: "stale".to_string(),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        KVStore::read(&store, "rgb", "sub", "a").await.unwrap(),
        vec![1]
    );
    assert_eq!(
        KVStore::read(&store, "rgb", "other", "b").await.unwrap(),
        vec![2]
    );
    assert!(KVStore::read(&store, "rgb", "sub", "stale").await.is_err());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_converge() {
    let store = Arc::new(test_store().await);
    let mut handles = Vec::new();
    for i in 0..50u8 {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            KVStore::write(&*s, "ns", "sub", "k", vec![i])
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    KVStore::write(&*store, "ns", "sub", "k", vec![99])
        .await
        .unwrap();
    assert_eq!(
        KVStore::read(&*store, "ns", "sub", "k").await.unwrap(),
        vec![99]
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_rgb_payment_proxies_matches_only_proxy_keys() {
    let store = test_store().await;
    let hash = "aabbcc";
    let ns_in = RGB_PAYMENT_INFO_INBOUND_NS;
    let ns_out = RGB_PAYMENT_INFO_OUTBOUND_NS;
    KVStore::write(&store, RGB_PRIMARY_NS, ns_in, hash, vec![0])
        .await
        .unwrap();
    KVStore::write(
        &store,
        RGB_PRIMARY_NS,
        ns_in,
        &format!("{hash}_pending"),
        vec![1],
    )
    .await
    .unwrap();
    KVStore::write(
        &store,
        RGB_PRIMARY_NS,
        ns_in,
        &format!("chan1{hash}"),
        vec![2],
    )
    .await
    .unwrap();
    KVStore::write(
        &store,
        RGB_PRIMARY_NS,
        ns_out,
        &format!("chan2{hash}"),
        vec![3],
    )
    .await
    .unwrap();
    KVStore::write(&store, RGB_PRIMARY_NS, ns_out, "otherkey", vec![4])
        .await
        .unwrap();

    let proxies = store.find_rgb_payment_proxies(hash).unwrap();
    let keys: Vec<&str> = proxies.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec![format!("chan1{hash}"), format!("chan2{hash}")]);
    assert_eq!(proxies[0].1, vec![2]);
    assert_eq!(proxies[1].1, vec![3]);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_config_reads_come_from_config_table() {
    let store = test_store().await;
    store.save_mnemonic("enc".to_string()).unwrap();
    store.set_indexer_url("http://indexer").unwrap();

    let read = KVStore::read(
        &store,
        RGB_PRIMARY_NS,
        RGB_WALLET_CONFIG_NS,
        INDEXER_URL_FNAME,
    )
    .await
    .unwrap();
    assert_eq!(read, b"http://indexer".to_vec());

    // a raw kv write to the namespace is not visible: the config table is the source of truth
    KVStore::write(
        &store,
        RGB_PRIMARY_NS,
        RGB_WALLET_CONFIG_NS,
        BITCOIN_NETWORK_FNAME,
        b"junk".to_vec(),
    )
    .await
    .unwrap();
    assert!(KVStore::read(
        &store,
        RGB_PRIMARY_NS,
        RGB_WALLET_CONFIG_NS,
        BITCOIN_NETWORK_FNAME
    )
    .await
    .is_err());

    // a re-set is visible despite the cache
    store.set_indexer_url("http://other").unwrap();
    let read = KVStore::read(
        &store,
        RGB_PRIMARY_NS,
        RGB_WALLET_CONFIG_NS,
        INDEXER_URL_FNAME,
    )
    .await
    .unwrap();
    assert_eq!(read, b"http://other".to_vec());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_pragmas_are_applied() {
    use sea_orm::{ConnectionTrait, DbBackend, Statement};

    let dir = "tmp/kv_store_pragmas";
    std::fs::remove_dir_all(dir).ok();
    std::fs::create_dir_all(dir).unwrap();
    let conn = crate::utils::connect_db(std::path::Path::new(&format!("{dir}/rln_db")))
        .await
        .unwrap();

    let pragma = |sql: &str| Statement::from_string(DbBackend::Sqlite, sql.to_string());
    let journal_mode: String = conn
        .query_one(pragma("PRAGMA journal_mode;"))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();
    assert_eq!(journal_mode, "wal");
    let synchronous: i32 = conn
        .query_one(pragma("PRAGMA synchronous;"))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();
    assert_eq!(synchronous, 2);
    let busy_timeout: i32 = conn
        .query_one(pragma("PRAGMA busy_timeout;"))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap();
    assert_eq!(busy_timeout, 5000);
}
