use super::*;

const TEST_DIR_BASE: &str = "tmp/close_coop_standard/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn close_coop_standard() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    let unspents = list_unspents(node1_addr).await;
    assert_eq!(unspents.len(), 0);

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let unspents = list_unspents(node1_addr).await;
    assert_eq!(unspents.len(), 11);

    let assets = list_assets(node1_addr).await;
    assert_eq!(assets.nia.unwrap().len(), 0);
    assert_eq!(assets.uda.unwrap().len(), 0);
    assert_eq!(assets.cfa.unwrap().len(), 0);
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let assets = list_assets(node1_addr).await;
    assert_eq!(assets.nia.unwrap().len(), 1);
    assert_eq!(assets.uda.unwrap().len(), 0);
    assert_eq!(assets.cfa.unwrap().len(), 0);

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let peers = list_peers(node1_addr).await;
    assert!(!peers.iter().any(|p| p.pubkey == node2_pubkey));
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;
    let peers = list_peers(node1_addr).await;
    assert!(peers.iter().any(|p| p.pubkey == node2_pubkey));

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    keysend_with_ln_balance(
        node1_addr,
        node2_addr,
        &node2_pubkey,
        Some(6000000),
        Some(&asset_id),
        Some(150),
        Some(600),
        Some(0),
    )
    .await;
    keysend_with_ln_balance(
        node2_addr,
        node1_addr,
        &node1_pubkey,
        None,
        Some(&asset_id),
        Some(50),
        Some(150),
        Some(450),
    )
    .await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(10),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 390);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 10);

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 890).await;
    wait_for_balance(node2_addr, &asset_id, 100).await;

    let peers = list_peers(node1_addr).await;
    assert!(peers.iter().any(|p| p.pubkey == node2_pubkey));
    disconnect_peer(node1_addr, &node2_pubkey).await;
    let peers = list_peers(node1_addr).await;
    assert!(!peers.iter().any(|p| p.pubkey == node2_pubkey));

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(690),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node2_addr,
        &asset_id,
        Assignment::Fungible(50),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 200);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 50);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 750);
}
