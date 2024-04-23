use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_whitelist/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_fail_whitelist() {
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

    let maker_init_response = maker_init(node1_addr, 36000, None, 10, Some(&asset_id), 5000).await;
    // We don't execute the taker command, so the swapstring is not going to be whitelisted, and the swap will fail.
    //let taker_response = taker(node2_addr, maker_init_response.swapstring.clone()).await;

    // Reconnect in case the bug happens when opening channels
    connect_peer(
        node2_addr,
        &node1_pubkey,
        &format!("127.0.0.1:{}", NODE1_PEER_PORT),
    )
    .await;
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{}", NODE2_PEER_PORT),
    )
    .await;

    maker_execute(
        node1_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey,
    )
    .await;

    for _ in 0..10 {
        let outbound_payment = list_payments(node1_addr)
            .await
            .into_iter()
            .find(|p| !p.inbound)
            .unwrap();
        if matches!(outbound_payment.status, HTLCStatus::Failed) {
            return;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    panic!("Payment didn't fail");
}
