use super::*;

const TEST_DIR_BASE: &str = "tmp/missing_acceptor/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn missing_acceptor() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    *IGNORE_INBOUND_CHANNELS_ON_NODE.lock().unwrap() =
        Some(PublicKey::from_str(&node2_pubkey).unwrap());

    // opening a channel where the acceptor is missing should not lock the funds
    let stuck_channel = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        true,
    )
    .await
    .unwrap();
    let stuck_temp_id = stuck_channel.temporary_channel_id;

    // the stuck channel should be visible on node1
    let channels_before = list_channels(node1_addr).await;
    assert!(channels_before
        .iter()
        .any(|c| c.channel_id == stuck_temp_id));

    // make sure a new channel can be opened
    open_channel_with_retry(
        node1_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        None,
        None,
        None,
        30,
    )
    .await;

    *IGNORE_INBOUND_CHANNELS_ON_NODE.lock().unwrap() = None;

    assert_eq!(list_channels(node1_addr).await.len(), 2);

    // the stuck channel can be force-closed via the /closechannel API,
    // this ensures the UTXOs can be unlocked in case of a missing acceptor
    close_channel(node1_addr, &stuck_temp_id, &node2_pubkey, true).await;

    // after closing, only the channel to node3 should remain on node1
    let channels_after = list_channels(node1_addr).await;
    assert!(!channels_after.iter().any(|c| c.channel_id == stuck_temp_id));
    assert_eq!(channels_after.len(), 1);
    assert_eq!(channels_after[0].peer_pubkey, node3_pubkey);
}
