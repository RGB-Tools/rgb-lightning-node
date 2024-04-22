use super::*;
use regex::RegexSet;

const TEST_DIR_BASE: &str = "tmp/backup_and_restore/";
const NODE1_PEER_PORT: u16 = 9921;
const NODE2_PEER_PORT: u16 = 9922;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn backup_and_restore() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, node1_password) =
        start_node(test_dir_node1.clone(), NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let channel =
        open_colored_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 600, &asset_id).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    keysend(
        node1_addr,
        &node2_pubkey,
        Some(3000000),
        Some(asset_id.clone()),
        Some(100),
    )
    .await;

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 900).await;
    wait_for_balance(node2_addr, &asset_id, 100).await;

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;

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
        .post(format!("http://{}/backup", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let text = res.text().await.unwrap();
    let response: ErrorResponse = serde_json::from_str(&text).unwrap();
    assert_eq!(response.error, "Invalid backup path");
    assert_eq!(response.code, 400);

    shutdown(&[node1_addr, node2_addr]).await;

    let old_test_dir_node1 = format!("{test_dir_node1}_old");
    let old_test_dir_node1_path = Path::new(&old_test_dir_node1);
    if old_test_dir_node1_path.exists() {
        std::fs::remove_dir_all(&old_test_dir_node1).unwrap();
    }
    std::fs::rename(test_dir_node1.clone(), old_test_dir_node1.clone()).unwrap();

    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT).await;

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
