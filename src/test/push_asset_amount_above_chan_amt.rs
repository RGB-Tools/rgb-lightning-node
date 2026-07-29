use super::*;

const TEST_DIR_BASE: &str = "tmp/push_asset_amount_above_chan_amt/";

/// A counterparty sending a `push_asset_amount` greater than the channel asset amount used to
/// underflow `remote_rgb_amount` on the acceptor, panicking its event handler. The acceptor must
/// reject the funding and stay alive.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn push_asset_amount_above_chan_amt() {
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

    // node1 puts more than the channel asset amount on the wire, bypassing the REST clamp that the
    // push_asset_amount below satisfies
    let _force_guard = NodeOverrideGuard::set(&FORCE_PUSH_ASSET_AMOUNT_ON_NODE, &node1_pubkey);

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

    // node2 rejects the funding, so node1's pending channel is discarded
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

    // with the underflow node2 would have panicked in its event handler
    node_info(node2_addr).await;
    assert!(list_channels(node2_addr).await.is_empty());
}
