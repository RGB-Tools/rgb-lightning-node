use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_multihop_asset_asset/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn do_asset_asset_swap() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node1_addr).await;

    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node2_addr).await;

    fund_and_create_utxos(node3_addr).await;
    fund_and_create_utxos(node3_addr).await;
    fund_and_create_utxos(node3_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id_1 = issue_asset(node1_addr).await;
    let asset_id_2 = issue_asset(node3_addr).await;

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id_1, 400, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id_1).await, 600);

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node3_addr, &asset_id_2, 400, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;
    assert_eq!(asset_balance(node3_addr, &asset_id_2).await, 600);

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    open_colored_channel_custom_btc_amount(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        500,
        &asset_id_1,
        200000,
    )
    .await;
    open_colored_channel_custom_btc_amount(
        node2_addr,
        &node3_pubkey,
        NODE3_PEER_PORT,
        300,
        &asset_id_1,
        200000,
    )
    .await;

    open_colored_channel_custom_btc_amount(
        node3_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        500,
        &asset_id_2,
        200000,
    )
    .await;
    open_colored_channel_custom_btc_amount(
        node2_addr,
        &node1_pubkey,
        NODE1_PEER_PORT,
        300,
        &asset_id_2,
        200000,
    )
    .await;

    let maker_init_response = maker_init(
        node1_addr,
        20,
        Some(&asset_id_2),
        10,
        Some(&asset_id_1),
        500,
    )
    .await;
    taker(node3_addr, maker_init_response.swapstring.clone()).await;

    // Reconnect in case the bug happens when opening channels
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{}", NODE2_PEER_PORT),
    )
    .await;
    connect_peer(
        node2_addr,
        &node1_pubkey,
        &format!("127.0.0.1:{}", NODE1_PEER_PORT),
    )
    .await;
    connect_peer(
        node2_addr,
        &node3_pubkey,
        &format!("127.0.0.1:{}", NODE3_PEER_PORT),
    )
    .await;
    connect_peer(
        node3_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{}", NODE2_PEER_PORT),
    )
    .await;

    let node1_trades = list_trades(node1_addr).await;
    assert!(node1_trades.taker.is_empty());
    assert_eq!(node1_trades.maker.len(), 1);
    let node3_trades = list_trades(node3_addr).await;
    assert!(node3_trades.maker.is_empty());
    assert_eq!(node3_trades.taker.len(), 1);

    maker_execute(
        node1_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node3_pubkey,
    )
    .await;

    wait_for_ln_balance(node3_addr, &asset_id_1, 10).await;
    wait_for_ln_balance(node1_addr, &asset_id_2, 20).await;
}
