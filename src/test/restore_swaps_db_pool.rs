use super::*;
use std::sync::Arc;

const TEST_DIR_BASE: &str = "tmp/restore_swaps_db_pool/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn restore_swaps_db_pool() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, node1_password) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    lock(node1_addr).await;
    let node1_backup_path = format!("{TEST_DIR_BASE}/node1_backup");
    if std::path::Path::new(&node1_backup_path).exists() {
        std::fs::remove_file(&node1_backup_path).unwrap();
    }
    backup(node1_addr, &node1_backup_path, &node1_password).await;
    shutdown(&[node1_addr]).await;

    let old_test_dir_node1 = format!("{test_dir_node1}_old");
    if std::path::Path::new(&old_test_dir_node1).exists() {
        std::fs::remove_dir_all(&old_test_dir_node1).unwrap();
    }
    std::fs::rename(test_dir_node1.clone(), old_test_dir_node1).unwrap();

    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None, true).await;

    let pre_db = {
        let state = test_get_app_state(node1_addr);
        let guard = state.static_state.database.read().unwrap();
        Arc::clone(&guard)
    };

    restore(node1_addr, &node1_backup_path, &node1_password).await;

    let post_db = {
        let state = test_get_app_state(node1_addr);
        let guard = state.static_state.database.read().unwrap();
        Arc::clone(&guard)
    };

    assert!(
        !Arc::ptr_eq(&pre_db, &post_db),
        "restore must replace StaticState.database with a fresh pool; \
         the same Arc was observed before and after restore_backup"
    );

    unlock(node1_addr, &node1_password).await;
    let _ = node_info(node1_addr).await;
}
