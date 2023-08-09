use super::*;

const TEST_DIR_BASE: &str = "tmp/multi_hop/";
const NODE1_PEER_PORT: u16 = 9901;
const NODE2_PEER_PORT: u16 = 9902;
const NODE3_PEER_PORT: u16 = 9903;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn multi_hop() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let node1_addr = start_node(test_dir_node1, NODE1_PEER_PORT, false);
    let node2_addr = start_node(test_dir_node2, NODE2_PEER_PORT, false);
    let node3_addr = start_node(test_dir_node3, NODE3_PEER_PORT, false);

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;
    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;
    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    let blinded_utxo = rgb_invoice(node2_addr).await;
    send_asset(node1_addr, &asset_id, 400, blinded_utxo).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 600);

    let channel_12 = open_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 500, &asset_id).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 100);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 400);

    let channel_23 = open_channel(node2_addr, &node3_pubkey, NODE3_PEER_PORT, 300, &asset_id).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 100);

    let LNInvoiceResponse { invoice } = ln_invoice(node3_addr, &asset_id, 50, 900).await;
    let _ = send_payment(node1_addr, invoice).await;

    close_channel(node2_addr, &channel_12.channel_id, &node1_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 550).await;
    wait_for_balance(node2_addr, &asset_id, 150).await;

    close_channel(node3_addr, &channel_23.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node2_addr, &asset_id, 400).await;
    wait_for_balance(node3_addr, &asset_id, 50).await;

    let blinded_utxo = rgb_invoice(node3_addr).await;
    send_asset(node1_addr, &asset_id, 200, blinded_utxo).await;
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

    let blinded_utxo = rgb_invoice(node2_addr).await;
    send_asset(node3_addr, &asset_id, 375, blinded_utxo).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node3_addr).await;

    assert_eq!(asset_balance(node1_addr, &asset_id).await, 350);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 625);
    assert_eq!(asset_balance(node3_addr, &asset_id).await, 25);
}
