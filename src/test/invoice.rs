use super::*;
use bitcoin::hashes::sha256::Hash as Sha256;
use std::str::FromStr;

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
        payment_hash: None,
        description_hash: None,
        min_final_cltv_expiry_delta: None,
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
        payment_hash: None,
        description_hash: None,
        min_final_cltv_expiry_delta: None,
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
        payment_hash: None,
        description_hash: None,
        min_final_cltv_expiry_delta: None,
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
async fn description_hash_invoice() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}description_hash/node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    let description_hash = lightning_invoice::Sha256(Sha256::hash(b"out-of-band description"));
    let inbound_min_final_cltv = 144;
    let payload = LNInvoiceRequest {
        amt_msat: None,
        expiry_sec: 900,
        asset_id: None,
        asset_amount: None,
        payment_hash: None,
        description_hash: Some(description_hash.0.to_string()),
        min_final_cltv_expiry_delta: Some(inbound_min_final_cltv),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<LNInvoiceResponse>()
        .await
        .unwrap();

    let invoice = Bolt11Invoice::from_str(&res.invoice).unwrap();
    assert!(matches!(
        invoice.description(),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(hash) if *hash == description_hash
    ));
    assert_eq!(
        invoice.min_final_cltv_expiry_delta(),
        u64::from(inbound_min_final_cltv) + 3
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn invalid_description_hash_invoice() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}invalid_description_hash/node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    let payload = LNInvoiceRequest {
        amt_msat: None,
        expiry_sec: 900,
        asset_id: None,
        asset_amount: None,
        payment_hash: None,
        description_hash: Some("not-a-valid-description-hash".to_string()),
        min_final_cltv_expiry_delta: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid description hash: not-a-valid-description-hash",
        "InvalidDescriptionHash",
    )
    .await;
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
        payment_hash: None,
        description_hash: None,
        min_final_cltv_expiry_delta: None,
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
        asset_id: None,
        asset_amount: None,
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
    let payment_sender =
        get_payment(node1_addr, &decoded.payment_hash, PaymentType::Outbound).await;
    assert_eq!(
        payment_sender.amt_msat,
        Some(payment_amount),
        "Sender payment should have the amount that was sent"
    );
    assert_eq!(payment_sender.status, HTLCStatus::Succeeded);

    let payment_receiver = get_payment(
        node2_addr,
        &decoded.payment_hash,
        PaymentType::InboundAutoClaim,
    )
    .await;
    assert_eq!(
        payment_receiver.amt_msat,
        Some(payment_amount),
        "Receiver payment should have the amount that was received, not zero"
    );
    assert_eq!(payment_receiver.status, HTLCStatus::Succeeded);

    // Also cover RGB invoice payment where RGB amount is provided at send time.
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        Some(3_500_000),
        Some(600),
        Some(&asset_id),
    )
    .await;

    let payload = LNInvoiceRequest {
        amt_msat: Some(3_000_000),
        expiry_sec: 900,
        asset_id: Some(asset_id.clone()),
        asset_amount: None,
        payment_hash: None,
        description_hash: None,
        min_final_cltv_expiry_delta: None,
    };
    let invoice_without_amount = reqwest::Client::new()
        .post(format!("http://{node2_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<LNInvoiceResponse>()
        .await
        .unwrap()
        .invoice;

    let decoded_without_amount = decode_ln_invoice(node1_addr, &invoice_without_amount).await;
    assert_eq!(decoded_without_amount.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded_without_amount.asset_amount, None);

    // If the RGB invoice already includes asset_id and asset_amount, sendpayment can omit both.
    let payload = LNInvoiceRequest {
        amt_msat: Some(3_000_000),
        expiry_sec: 900,
        asset_id: Some(asset_id.clone()),
        asset_amount: Some(50),
        payment_hash: None,
        description_hash: None,
        min_final_cltv_expiry_delta: None,
    };
    let invoice_with_amount = reqwest::Client::new()
        .post(format!("http://{node2_addr}/lninvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<LNInvoiceResponse>()
        .await
        .unwrap()
        .invoice;

    let decoded_with_amount = decode_ln_invoice(node1_addr, &invoice_with_amount).await;
    assert_eq!(decoded_with_amount.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded_with_amount.asset_amount, Some(50));

    let payload = SendPaymentRequest {
        invoice: invoice_with_amount,
        amt_msat: Some(3_000_000),
        asset_id: None,
        asset_amount: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap()
        .json::<SendPaymentResponse>()
        .await
        .unwrap();
    wait_for_ln_payment(
        node2_addr,
        &res.payment_hash.unwrap(),
        HTLCStatus::Succeeded,
    )
    .await;
    let payment = get_payment(
        node2_addr,
        &decoded_with_amount.payment_hash,
        PaymentType::InboundAutoClaim,
    )
    .await;
    assert_eq!(payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payment.asset_amount, Some(50));

    // Attempting to pay without both RGB fields should fail.
    let payload = SendPaymentRequest {
        invoice: invoice_without_amount.clone(),
        amt_msat: Some(3_000_000),
        asset_id: None,
        asset_amount: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "both the asset ID and amount are necessary",
        "IncompleteRGBInfo",
    )
    .await;

    // Providing an invalid RGB asset_id format should fail.
    let payload = SendPaymentRequest {
        invoice: invoice_without_amount.clone(),
        amt_msat: Some(3_000_000),
        asset_id: Some(s!("not-a-valid-contract-id")),
        asset_amount: Some(100),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid asset ID",
        "InvalidAssetID",
    )
    .await;

    // Providing a different but valid RGB asset_id should fail with contract mismatch.
    let other_asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let payload = SendPaymentRequest {
        invoice: invoice_without_amount.clone(),
        amt_msat: Some(3_000_000),
        asset_id: Some(other_asset_id),
        asset_amount: Some(100),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "contract ID doesn't match the requested one",
        "InvalidInvoice",
    )
    .await;

    // Providing the RGB fields in sendpayment should succeed.
    let payload = SendPaymentRequest {
        invoice: invoice_without_amount,
        amt_msat: Some(3_000_000),
        asset_id: Some(asset_id),
        asset_amount: Some(100),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "paying RGB invoice by providing asset_amount in sendpayment should succeed"
    );
    let res = res.json::<SendPaymentResponse>().await.unwrap();
    wait_for_ln_payment(
        node2_addr,
        &res.payment_hash.unwrap(),
        HTLCStatus::Succeeded,
    )
    .await;
    let payment = get_payment(
        node2_addr,
        &decoded_without_amount.payment_hash,
        PaymentType::InboundAutoClaim,
    )
    .await;
    assert_eq!(payment.asset_amount, Some(100));
}
