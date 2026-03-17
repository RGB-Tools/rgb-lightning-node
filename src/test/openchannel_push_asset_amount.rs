use super::*;
const TEST_DIR_BASE: &str = "tmp/openchannel_push_asset_amount/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn openchannel_push_asset_amount() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}openchannel_push_asset_amount/node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}openchannel_push_asset_amount/node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}openchannel_push_asset_amount/node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;

    // Open channel with asset push: 600 total, push 250 to counterparty
    let partial_push_channel = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
        Some(250),
        None,
        None,
        None,
        true,
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);

    let node1_channels = list_channels(node1_addr).await;
    let node1_channel = node1_channels
        .iter()
        .find(|c| c.channel_id == partial_push_channel.channel_id)
        .unwrap();
    assert_eq!(node1_channel.asset_local_amount, Some(350));
    assert_eq!(node1_channel.asset_remote_amount, Some(250));

    let node2_channels = list_channels(node2_addr).await;
    let node2_channel = node2_channels
        .iter()
        .find(|c| c.channel_id == partial_push_channel.channel_id)
        .unwrap();
    assert_eq!(node2_channel.asset_local_amount, Some(250));
    assert_eq!(node2_channel.asset_remote_amount, Some(350));

    keysend_with_ln_balance(
        node1_addr,
        node2_addr,
        &node2_pubkey,
        None,
        Some(&asset_id),
        Some(100),
        Some(350),
        Some(250),
    )
    .await;
    keysend(node1_addr, &node2_pubkey, Some(10_000_000), None, None).await;
    keysend_with_ln_balance(
        node2_addr,
        node1_addr,
        &node1_pubkey,
        None,
        Some(&asset_id),
        Some(50),
        Some(350),
        Some(250),
    )
    .await;

    let node1_channel = list_channels(node1_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == partial_push_channel.channel_id)
        .unwrap();
    assert_eq!(node1_channel.asset_local_amount, Some(300));
    assert_eq!(node1_channel.asset_remote_amount, Some(300));

    let node2_channel = list_channels(node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == partial_push_channel.channel_id)
        .unwrap();
    assert_eq!(node2_channel.asset_local_amount, Some(300));
    assert_eq!(node2_channel.asset_remote_amount, Some(300));

    close_channel(
        node1_addr,
        &partial_push_channel.channel_id,
        &node2_pubkey,
        false,
    )
    .await;
    wait_for_balance(node1_addr, &asset_id, 700).await;
    wait_for_balance(node2_addr, &asset_id, 300).await;

    let full_push_channel = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
        Some(600),
        None,
        None,
        None,
        true,
    )
    .await;

    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    wait_for_usable_channels(node1_addr, 1).await;
    wait_for_usable_channels(node2_addr, 1).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 100);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 300);

    let node1_channel = list_channels(node1_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == full_push_channel.channel_id)
        .unwrap();
    assert_eq!(node1_channel.asset_local_amount, Some(0));
    assert_eq!(node1_channel.asset_remote_amount, Some(600));

    let node2_channel = list_channels(node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == full_push_channel.channel_id)
        .unwrap();
    assert_eq!(node2_channel.asset_local_amount, Some(600));
    assert_eq!(node2_channel.asset_remote_amount, Some(0));

    keysend(node1_addr, &node2_pubkey, Some(10_000_000), None, None).await;
    keysend_with_ln_balance(
        node2_addr,
        node1_addr,
        &node1_pubkey,
        None,
        Some(&asset_id),
        Some(100),
        Some(600),
        Some(0),
    )
    .await;

    let node1_channel = list_channels(node1_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == full_push_channel.channel_id)
        .unwrap();
    assert_eq!(node1_channel.asset_local_amount, Some(100));
    assert_eq!(node1_channel.asset_remote_amount, Some(500));

    let node2_channel = list_channels(node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == full_push_channel.channel_id)
        .unwrap();
    assert_eq!(node2_channel.asset_local_amount, Some(500));
    assert_eq!(node2_channel.asset_remote_amount, Some(100));

    close_channel(
        node1_addr,
        &full_push_channel.channel_id,
        &node2_pubkey,
        false,
    )
    .await;
    wait_for_balance(node1_addr, &asset_id, 200).await;
    wait_for_balance(node2_addr, &asset_id, 800).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node2_addr,
        &asset_id,
        Assignment::Fungible(100),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 200);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 700);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 100);
}
