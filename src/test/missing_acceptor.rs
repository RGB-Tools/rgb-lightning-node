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
    open_channel_raw(
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
}
