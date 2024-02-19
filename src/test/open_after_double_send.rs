use super::*;

const TEST_DIR_BASE: &str = "tmp/open_after_double_send/";
const NODE1_PEER_PORT: u16 = 9911;
const NODE2_PEER_PORT: u16 = 9912;
const NODE3_PEER_PORT: u16 = 9913;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn open_after_double_send() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;
    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 100, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 900);

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 200, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 700);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 300);

    let channel =
        open_colored_channel(node2_addr, &node1_pubkey, NODE1_PEER_PORT, 250, &asset_id).await;
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 50);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), Some(50), 900).await;
    let _ = send_payment(node2_addr, invoice).await;

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 750).await;
    wait_for_balance(node2_addr, &asset_id, 250).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 725, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node2_addr, &asset_id, 225, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance(node1_addr, &asset_id).await, 25);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 25);
    assert_eq!(asset_balance(node3_addr, &asset_id).await, 950);
}
