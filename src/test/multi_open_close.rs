use super::*;

const TEST_DIR_BASE: &str = "tmp/multi_open_close/";
const NODE1_PEER_PORT: u16 = 9891;
const NODE2_PEER_PORT: u16 = 9892;
const NODE3_PEER_PORT: u16 = 9893;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn multi_open_close() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let node1_addr = start_node(test_dir_node1, NODE1_PEER_PORT);
    let node2_addr = start_node(test_dir_node2, NODE2_PEER_PORT);
    let node3_addr = start_node(test_dir_node3, NODE3_PEER_PORT);

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let channel = open_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 600, &asset_id).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 400);

    keysend(node1_addr, &node2_pubkey, &asset_id, 100).await;

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;

    wait_for_balance(node1_addr, &asset_id, 900).await;
    wait_for_balance(node2_addr, &asset_id, 100).await;

    let channel = open_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 500, &asset_id).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 400);

    keysend(node1_addr, &node2_pubkey, &asset_id, 100).await;

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;

    wait_for_balance(node1_addr, &asset_id, 800).await;
    wait_for_balance(node2_addr, &asset_id, 200).await;

    let blinded_utxo = rgb_invoice(node3_addr).await;
    send_asset(node1_addr, &asset_id, 700, blinded_utxo).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let blinded_utxo = rgb_invoice(node3_addr).await;
    send_asset(node2_addr, &asset_id, 150, blinded_utxo).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance(node1_addr, &asset_id).await, 100);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 50);
    assert_eq!(asset_balance(node3_addr, &asset_id).await, 850);
}
