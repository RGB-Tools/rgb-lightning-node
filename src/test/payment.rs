use crate::routes::{BitcoinNetwork, TransactionType, TransferKind, TransferStatus};

use super::*;

const TEST_DIR_BASE: &str = "tmp/payment/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn success() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}success/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");
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
        Some(3500000),
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

    let payment = get_payment(node1_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );
    let payment = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );

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
    let payment = get_payment(node1_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );
    let payment = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );

    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), asset_amount, 900).await;
    let _ = send_payment(node1_addr, invoice.clone()).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    let payment = get_payment(node1_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );
    let payment = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );

    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), asset_amount, 900).await;
    let _ = send_payment(node2_addr, invoice.clone()).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    let payment = get_payment(node1_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );
    let payment = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, asset_amount);
    assert_eq!(payment.status, HTLCStatus::Succeeded);
    assert!(
        payment.preimage.is_some(),
        "Payment preimage should be present for successful payment"
    );

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
    let chan_1 = channels_1.first().unwrap();
    let chan_2 = channels_2.first().unwrap();
    assert_eq!(chan_1.local_balance_sat, chan_1_before.local_balance_sat);
    assert_eq!(chan_2.local_balance_sat, chan_2_before.local_balance_sat);

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 950).await;
    wait_for_balance(node2_addr, &asset_id, 50).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(925),
        recipient_id,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(
        node2_addr,
        &asset_id,
        Assignment::Fungible(25),
        recipient_id,
    )
    .await;
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
    assert!(tx_utxos.confirmation_time.is_some());

    let transfers = list_transfers(node1_addr, &asset_id).await;
    let xfer_1 = transfers.iter().find(|t| t.idx == 1).unwrap();
    assert_eq!(xfer_1.status, TransferStatus::Settled);
    assert_eq!(xfer_1.kind, TransferKind::Issuance);
    assert_eq!(xfer_1.assignments, vec![Assignment::Fungible(1000)]);
    assert!(xfer_1.txid.is_none());
    assert!(xfer_1.recipient_id.is_none());
    assert!(xfer_1.receive_utxo.is_none());
    assert!(xfer_1.change_utxo.is_none());
    assert!(xfer_1.expiration.is_none());
    assert!(xfer_1.transport_endpoints.is_empty());
    let xfer_2 = transfers.iter().find(|t| t.idx == 2).unwrap();
    assert_eq!(xfer_2.status, TransferStatus::Settled);
    assert_eq!(xfer_2.kind, TransferKind::Send);
    assert_eq!(xfer_2.requested_assignment, Some(Assignment::Fungible(600)));
    assert_eq!(xfer_2.assignments, vec![Assignment::Fungible(400)]);
    assert!(xfer_2.txid.is_some());
    assert!(xfer_2.recipient_id.is_some());
    assert!(xfer_2.receive_utxo.is_none());
    assert!(xfer_2.change_utxo.is_some());
    assert!(xfer_2.expiration.is_some());
    assert!(!xfer_2.transport_endpoints.is_empty());
    let xfer_3 = transfers.iter().find(|t| t.idx == 3).unwrap();
    assert_eq!(xfer_3.status, TransferStatus::Settled);
    assert_eq!(xfer_3.kind, TransferKind::ReceiveWitness);
    assert_eq!(xfer_3.assignments, vec![Assignment::Fungible(550)]);
    assert!(xfer_3.txid.is_some());
    assert!(xfer_3.recipient_id.is_some());
    assert!(xfer_3.receive_utxo.is_some());
    assert!(xfer_3.change_utxo.is_none());
    assert!(xfer_3.expiration.is_some());
    assert!(!xfer_3.transport_endpoints.is_empty());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn same_invoice_twice() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}same_invoice_twice/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let _channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        Some(3500000),
        Some(600),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    let channels_1_before = list_channels(node1_addr).await;
    let channels_2_before = list_channels(node2_addr).await;
    assert_eq!(channels_1_before.len(), 1);
    assert_eq!(channels_2_before.len(), 1);

    let asset_amount = Some(100);
    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), asset_amount, 900).await;

    send_payment_raw(node1_addr, invoice.clone()).await;

    // try to re-pay the same invoice
    println!("sending LN payment for invoice {invoice} from node {node1_addr}");
    let payload = SendPaymentRequest {
        invoice: invoice.clone(),
        amt_msat: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Another payment for this invoice is already in status",
        "DuplicatePayment",
    )
    .await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
}
