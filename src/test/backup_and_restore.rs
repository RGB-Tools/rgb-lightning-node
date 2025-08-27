use super::*;
use regex::RegexSet;

const TEST_DIR_BASE: &str = "tmp/backup_and_restore/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn backup_and_restore() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, node1_password) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    keysend(node1_addr, &node2_pubkey, None, Some(&asset_id), Some(100)).await;

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 900).await;
    wait_for_balance(node2_addr, &asset_id, 100).await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;

    lock(node1_addr).await;

    let node1_backup_path = format!("{TEST_DIR_BASE}/node1_backup");
    if Path::new(&node1_backup_path).exists() {
        std::fs::remove_file(&node1_backup_path).unwrap();
    }
    backup(node1_addr, &node1_backup_path, &node1_password).await;

    // check InvalidBackupPath error
    let payload = BackupRequest {
        backup_path: node1_backup_path.clone(),
        password: node1_password.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/backup"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid backup path",
        "InvalidBackupPath",
    )
    .await;

    shutdown(&[node1_addr, node2_addr]).await;

    let old_test_dir_node1 = format!("{test_dir_node1}_old");
    let old_test_dir_node1_path = Path::new(&old_test_dir_node1);
    if old_test_dir_node1_path.exists() {
        std::fs::remove_dir_all(&old_test_dir_node1).unwrap();
    }
    std::fs::rename(test_dir_node1.clone(), old_test_dir_node1.clone()).unwrap();

    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None).await;

    restore(node1_addr, &node1_backup_path, &node1_password).await;

    let ignores = RegexSet::new([r"log*"]).unwrap();
    let cmp = dircmp::Comparison::new(ignores);
    let diff = cmp
        .compare(old_test_dir_node1_path, Path::new(&test_dir_node1))
        .unwrap();
    assert!(diff.is_empty());

    unlock(node1_addr, &node1_password).await;

    let node1_info = node_info(node1_addr).await;
    assert_eq!(node1_pubkey, node1_info.pubkey);
}
