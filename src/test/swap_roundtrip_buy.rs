use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_buy/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_roundtrip_buy() {
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

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;

    open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    open_channel(
        node2_addr,
        &node1_pubkey,
        NODE2_PEER_PORT,
        Some(5000000),
        Some(546000),
        None,
        None,
    )
    .await;

    let maker_init_response = maker_init(node1_addr, 50000, None, 10, Some(&asset_id), 3600).await;
    taker(node2_addr, maker_init_response.swapstring.clone()).await;

    // Reconnect in case the bug happens when opening channels
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{}", NODE2_PEER_PORT),
    )
    .await;

    let node1_trades = list_trades(node1_addr).await;
    assert!(node1_trades.taker.is_empty());
    assert_eq!(node1_trades.maker.len(), 1);
    let node2_trades = list_trades(node2_addr).await;
    assert!(node2_trades.maker.is_empty());
    assert_eq!(node2_trades.taker.len(), 1);

    maker_execute(
        node1_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey,
    )
    .await;

    wait_for_ln_balance(node2_addr, &asset_id, 10).await;
}
