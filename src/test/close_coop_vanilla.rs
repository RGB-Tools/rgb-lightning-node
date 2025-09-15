use super::*;

const TEST_DIR_BASE: &str = "tmp/close_coop_vanilla/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn with_anchors() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}with_anchors/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    let unspents = list_unspents(node1_addr).await;
    assert_eq!(unspents.len(), 0);

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let initial_balance = 99676210;

    assert_eq!(
        btc_balance(node1_addr).await.vanilla.spendable,
        initial_balance
    );
    assert_eq!(
        btc_balance(node2_addr).await.vanilla.spendable,
        initial_balance
    );
    assert_eq!(
        btc_balance(node3_addr).await.vanilla.spendable,
        initial_balance
    );

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
        Some(600_000),
        Some(300_000_000),
        None,
        None,
    )
    .await;
    keysend(node1_addr, &node2_pubkey, Some(10_000_000), None, None).await;
    keysend(node2_addr, &node1_pubkey, Some(10_000_000), None, None).await;
    assert_eq!(list_payments(node1_addr).await.len(), 2);
    assert_eq!(list_payments(node2_addr).await.len(), 2);

    let invoice = ln_invoice(node1_addr, Some(50000000), None, None, 900)
        .await
        .invoice;
    let _ = send_payment(node2_addr, invoice).await;
    assert_eq!(list_payments(node1_addr).await.len(), 3);
    assert_eq!(list_payments(node2_addr).await.len(), 3);

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn without_anchors() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}without_anchors/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    let unspents = list_unspents(node1_addr).await;
    assert_eq!(unspents.len(), 0);

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let initial_balance = 99676210;

    assert_eq!(
        btc_balance(node1_addr).await.vanilla.spendable,
        initial_balance
    );
    assert_eq!(
        btc_balance(node2_addr).await.vanilla.spendable,
        initial_balance
    );
    assert_eq!(
        btc_balance(node3_addr).await.vanilla.spendable,
        initial_balance
    );

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

    let channel = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(600_000),
        Some(300_000_000),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .await;
    keysend(node1_addr, &node2_pubkey, Some(10_000_000), None, None).await;
    keysend(node2_addr, &node1_pubkey, Some(10_000_000), None, None).await;
    assert_eq!(list_payments(node1_addr).await.len(), 2);
    assert_eq!(list_payments(node2_addr).await.len(), 2);

    let invoice = ln_invoice(node1_addr, Some(50000000), None, None, 900)
        .await
        .invoice;
    let _ = send_payment(node2_addr, invoice).await;
    assert_eq!(list_payments(node1_addr).await.len(), 3);
    assert_eq!(list_payments(node2_addr).await.len(), 3);

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
}
