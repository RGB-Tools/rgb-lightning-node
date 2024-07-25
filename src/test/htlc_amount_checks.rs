use super::*;

const TEST_DIR_BASE: &str = "tmp/htlc_amount_checks/";
const NODE1_PEER_PORT: u16 = 9901;
const NODE2_PEER_PORT: u16 = 9902;
const NODE3_PEER_PORT: u16 = 9903;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn htlc_amount_checks_3nodes() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}3nodes/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node2_addr).await.asset_id;

    let node1_info = node_info(node1_addr).await;
    let node2_info = node_info(node2_addr).await;
    let node3_info = node_info(node3_addr).await;

    let node1_pubkey = node1_info.pubkey;
    let _node2_pubkey = node2_info.pubkey;
    let node3_pubkey = node3_info.pubkey;

    let _channel_21 = open_channel(
        node2_addr,
        &node1_pubkey,
        NODE1_PEER_PORT,
        None,
        None,
        Some(50),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 950);

    let _channel_23 = open_channel(
        node2_addr,
        &node3_pubkey,
        NODE3_PEER_PORT,
        None,
        None,
        Some(40),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 910);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), Some(45), 900).await;
    let _ = send_payment(node2_addr, invoice).await;

    let LNInvoiceResponse { invoice } =
        ln_invoice(node3_addr, None, Some(&asset_id), Some(30), 900).await;
    let _ = send_payment(node2_addr, invoice).await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    let channels_3 = list_channels(node3_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 2);
    assert_eq!(channels_3.len(), 1);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node3_addr, None, Some(&asset_id), Some(25), 900).await;
    let _ = send_payment_with_status(node1_addr, invoice, HTLCStatus::Failed).await; // RetriesExhausted

    println!("\nafter sending multi-hop payment");
    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    let channels_3 = list_channels(node3_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 2);
    assert_eq!(channels_3.len(), 1);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn htlc_amount_checks_2nodes() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}2nodes/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_info = node_info(node1_addr).await;
    let node2_info = node_info(node2_addr).await;

    let _node1_pubkey = node1_info.pubkey;
    let node2_pubkey = node2_info.pubkey;

    let _channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        None,
        None,
        Some(400),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);

    // check payment fails (due to RouteNotFound)
    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), Some(500), 900).await;
    let _ = send_payment_with_status(node1_addr, invoice, HTLCStatus::Failed).await;

    // check channel is still open after payment failed
    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
}
