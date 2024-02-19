use super::*;

const TEST_DIR_BASE: &str = "tmp/close_coop_zero_balance/";
const NODE1_PEER_PORT: u16 = 9851;
const NODE2_PEER_PORT: u16 = 9852;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn close_coop_zero_balance() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let channel =
        open_colored_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 1000, &asset_id).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 0);

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 1000).await;
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 0);

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 700, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;

    assert_eq!(asset_balance(node1_addr, &asset_id).await, 300);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 700);
}
