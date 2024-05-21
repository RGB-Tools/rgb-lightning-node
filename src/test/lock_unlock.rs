use super::*;

const TEST_DIR_BASE: &str = "tmp/lock_unlock/";
const NODE1_PEER_PORT: u16 = 9941;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn lock_unlock() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");

    let (node1_addr, node1_password) =
        start_node(test_dir_node1.clone(), NODE1_PEER_PORT, false).await;

    println!("1 - lock+unlock");
    lock(node1_addr).await;
    unlock(node1_addr, &node1_password).await;

    fund_and_create_utxos(node1_addr).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);

    println!("2 - lock+unlock");
    lock(node1_addr).await;
    unlock(node1_addr, &node1_password).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);
}
