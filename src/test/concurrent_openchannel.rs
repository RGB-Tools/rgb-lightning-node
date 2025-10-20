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

    let maker_peer_port = NODE1_PEER_PORT;
    let taker1_peer_port = NODE2_PEER_PORT;
    let taker2_peer_port = NODE3_PEER_PORT;
    let taker3_peer_port = NODE4_PEER_PORT;
    let taker4_peer_port = NODE5_PEER_PORT;
    let taker5_peer_port = NODE6_PEER_PORT;

    let test_dir_maker = format!("{TEST_DIR_BASE}maker");
    let test_dir_taker1 = format!("{TEST_DIR_BASE}taker1");
    let test_dir_taker2 = format!("{TEST_DIR_BASE}taker2");
    let test_dir_taker3 = format!("{TEST_DIR_BASE}taker3");
    let test_dir_taker4 = format!("{TEST_DIR_BASE}taker4");
    let test_dir_taker5 = format!("{TEST_DIR_BASE}taker5");

    let (maker_addr, _) = start_node(&test_dir_maker, maker_peer_port, false).await;
    let (taker1_addr, _) = start_node(&test_dir_taker1, taker1_peer_port, false).await;
    let (taker2_addr, _) = start_node(&test_dir_taker2, taker2_peer_port, false).await;
    let (taker3_addr, _) = start_node(&test_dir_taker3, taker3_peer_port, false).await;
    let (taker4_addr, _) = start_node(&test_dir_taker4, taker4_peer_port, false).await;
    let (taker5_addr, _) = start_node(&test_dir_taker5, taker5_peer_port, false).await;

    fund_and_create_utxos(maker_addr, None).await;
    create_utxos(maker_addr, false, Some(5), Some(110000)).await;
    fund_and_create_utxos(taker1_addr, None).await;
    fund_and_create_utxos(taker2_addr, None).await;
    fund_and_create_utxos(taker3_addr, None).await;
    fund_and_create_utxos(taker4_addr, None).await;
    fund_and_create_utxos(taker5_addr, None).await;

    let asset_id = issue_asset_nia(maker_addr).await.asset_id;

    let _maker_pubkey = node_info(maker_addr).await.pubkey;
    let taker1_pubkey = node_info(taker1_addr).await.pubkey;
    let taker2_pubkey = node_info(taker2_addr).await.pubkey;
    let taker3_pubkey = node_info(taker3_addr).await.pubkey;
    let taker4_pubkey = node_info(taker4_addr).await.pubkey;
    let taker5_pubkey = node_info(taker5_addr).await.pubkey;

    let (_channel_mt_1, _channel_mt_2, _channel_mt_3, _channel_mt_4, _channel_mt_5) = tokio::join!(
        open_channel(
            maker_addr,
            &taker1_pubkey,
            Some(taker1_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
        ),
        open_channel(
            maker_addr,
            &taker2_pubkey,
            Some(taker2_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
        ),
        open_channel(
            maker_addr,
            &taker3_pubkey,
            Some(taker3_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
        ),
        open_channel(
            maker_addr,
            &taker4_pubkey,
            Some(taker4_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
        ),
        open_channel(
            maker_addr,
            &taker5_pubkey,
            Some(taker5_peer_port),
            Some(CHANNEL_CAPACITY_SAT),
            Some(PUSH_MSAT),
            Some(ASSET_AMOUNT),
            Some(&asset_id),
        )
    );

    let maker_usable_channels = node_info(maker_addr).await.num_usable_channels;
    assert_eq!(maker_usable_channels, 5);
}
