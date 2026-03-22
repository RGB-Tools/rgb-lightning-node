use super::*;

const TEST_DIR_BASE: &str = "tmp/inflate/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn success() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}success/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    let asset_id = issue_asset_ifa(node1_addr).await.asset_id;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);

    inflate(node1_addr, &asset_id, 500).await;
    mine(false);
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1500);
}
