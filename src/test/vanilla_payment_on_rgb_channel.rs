use super::*;

const TEST_DIR_BASE: &str = "tmp/vanilla_payment_on_rgb_channel/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn vanilla_payment_on_rgb_channel() {
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

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

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

    let channels_1_before = list_channels(node1_addr).await;
    let channels_2_before = list_channels(node2_addr).await;
    assert_eq!(channels_1_before.len(), 1);
    assert_eq!(channels_2_before.len(), 1);
    let chan_1_before = channels_1_before.first().unwrap();
    let chan_2_before = channels_2_before.first().unwrap();

    let amount = 5000000;
    let LNInvoiceResponse { invoice } = ln_invoice(node2_addr, Some(amount), None, None, 900).await;
    send_payment(node1_addr, invoice.clone()).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    let payments = list_payments(node1_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, None);
    assert_eq!(payment.asset_amount, None);
    let payments = list_payments(node2_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, None);
    assert_eq!(payment.asset_amount, None);

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
    let chan_1 = channels_1.first().unwrap();
    let chan_2 = channels_2.first().unwrap();
    assert_eq!(
        chan_1.local_balance_sat,
        chan_1_before.local_balance_sat - amount / 1000
    );
    assert_eq!(
        chan_2.local_balance_sat,
        chan_2_before.local_balance_sat + amount / 1000
    );

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 1000).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(900),
        recipient_id,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 100);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 0);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 900);
}
