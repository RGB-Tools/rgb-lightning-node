use super::*;

const TEST_DIR_BASE: &str = "tmp/openchannel_retry_after_failed_funding/";

/// A colored open whose funding the acceptor rejects leaves the initiator's files staged there.
/// Retrying from the same peer must succeed right away, not be refused until they are swept.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn openchannel_retry_after_failed_funding() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    // node2 rejects this funding: node1 puts more than the channel asset amount on the wire
    let force_guard = NodeOverrideGuard::set(&FORCE_PUSH_ASSET_AMOUNT_ON_NODE, &node1_pubkey);
    open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100_000),
        None,
        Some(100),
        Some(&asset_id),
        Some(0),
        None,
        None,
        None,
        true,
        true,
    )
    .await
    .unwrap();
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if list_channels(node1_addr).await.is_empty() {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("initiator channel was not discarded");
        }
    }
    drop(force_guard);

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100_000),
        None,
        Some(100),
        Some(&asset_id),
    )
    .await;
    assert_eq!(channel.asset_id, Some(asset_id));
}
