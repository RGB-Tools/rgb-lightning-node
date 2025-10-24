use super::*;

const TEST_DIR_BASE: &str = "tmp/concurrent_openchannel/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn concurrent_openchannel() {
    initialize();

    const CHANNEL_CAPACITY_SAT: u64 = 100000;
    const PUSH_MSAT: u64 = 20000;
    const ASSET_AMOUNT: u64 = 100;

    let node1_peer_port = NODE1_PEER_PORT;
    let node2_peer_port = NODE2_PEER_PORT;
    let node3_peer_port = NODE3_PEER_PORT;
    let node4_peer_port = NODE4_PEER_PORT;
    let node5_peer_port = NODE5_PEER_PORT;
    let node6_peer_port = NODE6_PEER_PORT;

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let test_dir_node4 = format!("{TEST_DIR_BASE}node4");
    let test_dir_node5 = format!("{TEST_DIR_BASE}node5");
    let test_dir_node6 = format!("{TEST_DIR_BASE}node6");

    let (node1_addr, _) = start_node(&test_dir_node1, node1_peer_port, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, node2_peer_port, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, node3_peer_port, false).await;
    let (node4_addr, _) = start_node(&test_dir_node4, node4_peer_port, false).await;
    let (node5_addr, _) = start_node(&test_dir_node5, node5_peer_port, false).await;
    let (node6_addr, _) = start_node(&test_dir_node6, node6_peer_port, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    create_utxos(node1_addr, false, Some(5), Some(110000)).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;
    fund_and_create_utxos(node4_addr, None).await;
    fund_and_create_utxos(node5_addr, None).await;
    fund_and_create_utxos(node6_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let _node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let node3_pubkey = node_info(node3_addr).await.pubkey;
    let node4_pubkey = node_info(node4_addr).await.pubkey;
    let node5_pubkey = node_info(node5_addr).await.pubkey;
    let node6_pubkey = node_info(node6_addr).await.pubkey;

    let (_channel_mt_1, _channel_mt_2, _channel_mt_3, _channel_mt_4, _channel_mt_5) = tokio::join!(
        open_channel_with_retry(
            node1_addr,
            &node2_pubkey,
            Some(node2_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
            20,
        ),
        open_channel_with_retry(
            node1_addr,
            &node3_pubkey,
            Some(node3_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
            20,
        ),
        open_channel_with_retry(
            node1_addr,
            &node4_pubkey,
            Some(node4_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
            20,
        ),
        open_channel_with_retry(
            node1_addr,
            &node5_pubkey,
            Some(node5_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
            20,
        ),
        open_channel_with_retry(
            node1_addr,
            &node6_pubkey,
            Some(node6_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
            20,
        )
    );

    let node1_usable_channels = node_info(node1_addr).await.num_usable_channels;
    assert_eq!(node1_usable_channels, 5);
}
