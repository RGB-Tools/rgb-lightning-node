use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_multihop_sell/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_roundtrip_multihop_sell() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 400, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        Some(200000),
        None,
        Some(500),
        Some(&asset_id),
    )
    .await;
    open_channel(
        node2_addr,
        &node3_pubkey,
        NODE3_PEER_PORT,
        Some(200000),
        None,
        Some(300),
        Some(&asset_id),
    )
    .await;

    open_channel(
        node2_addr,
        &node1_pubkey,
        NODE1_PEER_PORT,
        Some(5000000),
        Some(0),
        None,
        None,
    )
    .await;
    open_channel(
        node3_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        Some(5000000),
        Some(0),
        None,
        None,
    )
    .await;

    let maker_init_response = maker_init(node3_addr, 10, Some(&asset_id), 3600, None, 5000).await;
    taker(node1_addr, maker_init_response.swapstring.clone()).await;

    let node3_trades = list_trades(node3_addr).await;
    assert!(node3_trades.taker.is_empty());
    assert_eq!(node3_trades.maker.len(), 1);
    let node1_trades = list_trades(node1_addr).await;
    assert!(node1_trades.maker.is_empty());
    assert_eq!(node1_trades.taker.len(), 1);

    maker_execute(
        node3_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node1_pubkey,
    )
    .await;

    wait_for_ln_balance(node1_addr, &asset_id, 490).await;
}
