use super::*;

const TEST_DIR_BASE: &str = "tmp/send_receive/";
const NODE1_PEER_PORT: u16 = 9811;
const NODE2_PEER_PORT: u16 = 9812;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn send_receive() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let node1_addr = start_node(test_dir_node1, NODE1_PEER_PORT, false);
    let node2_addr = start_node(test_dir_node2, NODE2_PEER_PORT, false);

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let blinded_utxo = rgb_invoice(node2_addr).await;
    send_asset(node1_addr, &asset_id, 400, blinded_utxo).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 600);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 400);

    let blinded_utxo = rgb_invoice(node1_addr).await;
    send_asset(node2_addr, &asset_id, 300, blinded_utxo).await;
    mine(false);
    refresh_transfers(node1_addr).await;
    refresh_transfers(node1_addr).await;
    refresh_transfers(node2_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 900);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 100);

    let blinded_utxo = rgb_invoice(node2_addr).await;
    send_asset(node1_addr, &asset_id, 200, blinded_utxo).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 700);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 300);
}
