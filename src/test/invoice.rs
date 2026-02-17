use super::*;

const TEST_DIR_BASE: &str = "tmp/invoice/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn invoice() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    // an invoice with RGB data and no amt_msat should fail
    let payload = LNInvoiceRequest {
        amt_msat: None,
        expiry_sec: 900,
        asset_id: Some(asset_id.clone()),
        asset_amount: Some(1),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // an invoice with RGB data and amt_msat below INVOICE_MIN_MSAT should fail
    let payload = LNInvoiceRequest {
        amt_msat: Some(2999999),
        expiry_sec: 900,
        asset_id: Some(asset_id.clone()),
        asset_amount: Some(1),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // an invoice with no RGB data and no amt_msat should succeed
    let payload = LNInvoiceRequest {
        amt_msat: None,
        expiry_sec: 900,
        asset_id: None,
        asset_amount: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<LNInvoiceResponse>()
        .await;
    assert!(res.is_ok());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn zero_amount_invoice() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}zero_amount/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // Open a channel between node1 and node2
    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        None,
        None,
    )
    .await;

    // Create a zero-amount invoice on node2
    println!("Creating zero-amount invoice on node {node2_addr}");
    let payload = LNInvoiceRequest {
        amt_msat: None,
        expiry_sec: 900,
        asset_id: None,
        asset_amount: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<LNInvoiceResponse>()
        .await
        .unwrap();
    let invoice = res.invoice;

    // Decode the invoice to verify it's zero-amount
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.amt_msat, None, "Invoice should have no amount");

    // Pay the zero-amount invoice with a specific amount (5000 msat)
    let payment_amount = 5000u64;
    println!("Paying zero-amount invoice from node {node1_addr} with amount {payment_amount}");
    let payload = SendPaymentRequest {
        invoice: invoice.clone(),
        amt_msat: Some(payment_amount),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    // Check that the payment succeeded
    let status_code = res.status();
    let response_text = res.text().await.unwrap();
    assert_eq!(
        status_code,
        reqwest::StatusCode::OK,
        "Payment should succeed. Response: {response_text}"
    );

    // Wait for payment to complete
    wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;

    // Verify that both sender and receiver payments record the actual amount
    let payment_sender = get_payment(node1_addr, &decoded.payment_hash).await;
    assert_eq!(
        payment_sender.amt_msat,
        Some(payment_amount),
        "Sender payment should have the amount that was sent"
    );
    assert_eq!(payment_sender.status, HTLCStatus::Succeeded);

    let payment_receiver = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(
        payment_receiver.amt_msat,
        Some(payment_amount),
        "Receiver payment should have the amount that was received, not zero"
    );
    assert_eq!(payment_receiver.status, HTLCStatus::Succeeded);
}
