use super::*;

const TEST_DIR_BASE: &str = "tmp/close_coop_vanilla/";
const NODE1_PEER_PORT: u16 = 9801;
const NODE2_PEER_PORT: u16 = 9802;
const NODE3_PEER_PORT: u16 = 9803;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn close_coop_vanilla() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    let unspents = list_unspents(node1_addr).await;
    assert_eq!(unspents.len(), 0);

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let initial_balance = 99870362;

    assert_eq!(btc_balance(node1_addr).await, initial_balance);
    assert_eq!(btc_balance(node2_addr).await, initial_balance);
    assert_eq!(btc_balance(node3_addr).await, initial_balance);

    let node1_info = node_info(node1_addr).await;
    let node2_info = node_info(node2_addr).await;
    let node1_pubkey = node1_info.pubkey;
    let node2_pubkey = node2_info.pubkey;

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
        NODE2_PEER_PORT,
        600_000,
        300_000_000,
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
