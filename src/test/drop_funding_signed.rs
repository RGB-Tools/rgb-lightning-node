use super::*;

const TEST_DIR_BASE: &str = "tmp/drop_funding_signed/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn drop_funding_signed() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    // node1 only has enough funds for one vanilla channel; if the UTXOs stay locked, the second
    // channel open will fail
    fund_with_and_create_utxos(node1_addr, Some(1), 200_000).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let node3_pubkey = node_info(node3_addr).await.pubkey;

    // make node1 drop outgoing funding_signed and reply with an error
    *DROP_FUNDING_SIGNED_ON_NODE.lock().unwrap() =
        Some(PublicKey::from_str(&node2_pubkey).unwrap());

    open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(150_000),
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

    // wait for channel to disappear
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node1_addr).await;
        if channels.is_empty() {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("channel is not disappearing");
        }
    }

    // restore normal behavior before opening a new channel to a different peer
    *DROP_FUNDING_SIGNED_ON_NODE.lock().unwrap() = None;

    // opening a new channel to a different peer must succeed: the UTXOs locked for the discarded
    // funding TX must have been released
    open_channel_with_retry(
        node1_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        Some(100_000),
        None,
        None,
        None,
        None,
        30,
    )
    .await;

    // do the same but with a colored channel
    fund_with_and_create_utxos(node1_addr, Some(3), 500_000).await;
    let asset_cfa = issue_asset_cfa(node1_addr, None).await;
    *DROP_FUNDING_SIGNED_ON_NODE.lock().unwrap() =
        Some(PublicKey::from_str(&node2_pubkey).unwrap());
    open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100_000),
        None,
        Some(ISSUE_AMT),
        Some(&asset_cfa.asset_id),
        None,
        None,
        None,
        None,
        true,
    )
    .await
    .unwrap();
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node1_addr).await;
        if channels.len() == 1 {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("channel is not disappearing");
        }
    }
    *DROP_FUNDING_SIGNED_ON_NODE.lock().unwrap() = None;
    open_channel_with_retry(
        node1_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        Some(100_000),
        None,
        Some(ISSUE_AMT),
        Some(&asset_cfa.asset_id),
        None,
        30,
    )
    .await;
}
