use crate::routes::{BitcoinNetwork, TransactionType};

use super::*;

const TEST_DIR_BASE: &str = "tmp/payment/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn payment() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
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

    let asset_amount = Some(100);
    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), asset_amount, 900).await;
    send_payment_with_ln_balance(node1_addr, node2_addr, invoice.clone(), Some(600), Some(0)).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.expiry_sec, 900);
    assert_eq!(decoded.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded.asset_amount, asset_amount);
    assert_eq!(decoded.payee_pubkey, Some(node2_pubkey.clone()));
    assert!(matches!(decoded.network, BitcoinNetwork::Regtest));
    let status = invoice_status(node2_addr, &invoice).await;
    assert!(matches!(status, InvoiceStatus::Succeeded));

    let payments = list_payments(node1_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    let payments = list_payments(node2_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);

    let asset_amount = Some(50);
    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), asset_amount, 900).await;
    send_payment_with_ln_balance(
        node2_addr,
        node1_addr,
        invoice.clone(),
        Some(100),
        Some(500),
    )
    .await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    let payments = list_payments(node1_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    let payments = list_payments(node2_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), asset_amount, 900).await;
    let _ = send_payment(node1_addr, invoice.clone()).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    let payments = list_payments(node1_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    let payments = list_payments(node2_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), asset_amount, 900).await;
    let _ = send_payment(node2_addr, invoice.clone()).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    let payments = list_payments(node1_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    let payments = list_payments(node2_addr).await;
    let payment = payments
        .iter()
        .find(|p| p.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
    let chan_1 = channels_1.first().unwrap();
    let chan_2 = channels_2.first().unwrap();
    assert_eq!(chan_1.local_balance_msat, chan_1_before.local_balance_msat);
    assert_eq!(chan_2.local_balance_msat, chan_2_before.local_balance_msat);

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 950).await;
    wait_for_balance(node2_addr, &asset_id, 50).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 925, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node2_addr, &asset_id, 25, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 25);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 25);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 950);

    let transactions = list_transactions(node1_addr).await;
    let tx_user = transactions
        .iter()
        .find(|t| t.received == 100000000)
        .unwrap();
    let tx_utxos = transactions.iter().find(|t| t.sent == 100000000).unwrap();
    let tx_send = transactions.iter().find(|t| t.sent == 128000).unwrap();
    assert_eq!(tx_user.transaction_type, TransactionType::User);
    assert_eq!(tx_utxos.transaction_type, TransactionType::CreateUtxos);
    assert_eq!(tx_send.transaction_type, TransactionType::RgbSend);
    assert!(tx_utxos.fee.is_some());
    assert!(tx_utxos.confirmation_time.is_some());
}
