use super::*;

const TEST_DIR_BASE: &str = "tmp/hodl_invoice/";
const ASSET_PAYMENT_AMOUNT: u64 = 10;

#[derive(Clone, Copy)]
enum ExpiryTrigger {
    Time,
    Blocks,
}

async fn invoice_cancel_expect_error(
    node_address: SocketAddr,
    payment_hash: String,
    expected_status: StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    println!("cancelling HODL invoice {payment_hash} on node {node_address}");
    let payload = CancelHodlInvoiceRequest { payment_hash };

    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/cancelhodlinvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(res, expected_status, expected_message, expected_name).await
}

async fn invoice_claim_expect_error(
    node_address: SocketAddr,
    payment_hash: String,
    payment_preimage: String,
    expected_status: StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    println!("claiming HODL invoice {payment_hash} on node {node_address}");
    let payload = ClaimHodlInvoiceRequest {
        payment_hash,
        payment_preimage,
    };

    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/claimhodlinvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(res, expected_status, expected_message, expected_name).await
}

async fn run_expire_hodl_invoice_case(
    node1_addr: SocketAddr,
    node2_addr: SocketAddr,
    test_dir_node2: &str,
    trigger: ExpiryTrigger,
) {
    let (preimage_hex, payment_hash_hex) = random_preimage_and_hash();
    let expiry_sec = match trigger {
        ExpiryTrigger::Time => 20,
        ExpiryTrigger::Blocks => 900,
    };
    let LNInvoiceResponse { invoice } = ln_invoice_hodl(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        None,
        None,
        expiry_sec,
        payment_hash_hex.clone(),
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    wait_for_inbound_payment_status(test_dir_node2, &payment_hash_hex, HTLCStatus::Claimable)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to appear: {err}"));
    let _ = wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Claimable).await;

    match trigger {
        ExpiryTrigger::Time => {
            let expiry_wait =
                std::time::Duration::from_secs(u64::from(expiry_sec).saturating_add(60));
            let _ = wait_for_ln_payment_with_timeout(
                node2_addr,
                &decoded.payment_hash,
                HTLCStatus::Failed,
                expiry_wait,
            )
            .await
            .unwrap_or_else(|err| {
                panic!("wait for payee payment to fail after time expiry: {err}")
            });
            let _ = wait_for_ln_payment_with_timeout(
                node1_addr,
                &decoded.payment_hash,
                HTLCStatus::Failed,
                expiry_wait,
            )
            .await
            .unwrap_or_else(|err| {
                panic!("wait for payer payment to fail after time expiry: {err}")
            });
        }
        ExpiryTrigger::Blocks => {
            let inbound_payments_path = Path::new(test_dir_node2)
                .join(LDK_DIR)
                .join(INBOUND_PAYMENTS_FNAME);
            let storage = read_inbound_payment_info(&inbound_payments_path);
            let hash = validate_and_parse_payment_hash(&payment_hash_hex).unwrap();
            let deadline_height = storage
                .payments
                .get(&hash)
                .and_then(|p| p.claim_deadline_height)
                .unwrap_or(0);

            let current_height = super::get_block_count();
            let blocks_to_mine = deadline_height.saturating_sub(current_height) + 2;
            super::mine_n_blocks(false, blocks_to_mine as u16);

            let _ = wait_for_ln_payment_with_timeout(
                node2_addr,
                &decoded.payment_hash,
                HTLCStatus::Failed,
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap_or_else(|err| {
                panic!("wait for payee payment to fail after block-based expiry: {err}")
            });
            let _ = wait_for_ln_payment_with_timeout(
                node1_addr,
                &decoded.payment_hash,
                HTLCStatus::Failed,
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap_or_else(|err| {
                panic!("wait for payer payment to fail after block-based expiry: {err}")
            });
        }
    }

    wait_for_inbound_payment_status(test_dir_node2, &payment_hash_hex, HTLCStatus::Failed)
        .await
        .unwrap_or_else(|err| panic!("wait for failed entry to persist: {err}"));
    let payee_payment =
        get_payment(node2_addr, &decoded.payment_hash, PaymentType::InboundHodl).await;
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Failed
    ));
    assert_eq!(payee_payment.payment_type, PaymentType::InboundHodl);
    assert_eq!(payee_payment.status, HTLCStatus::Failed);
    let payee_payment_from_list = list_payments(node2_addr)
        .await
        .into_iter()
        .find(|payment| payment.payment_hash == decoded.payment_hash)
        .unwrap();
    assert_eq!(
        payee_payment_from_list.payment_type,
        PaymentType::InboundHodl
    );
    let payee_payment_again =
        get_payment(node2_addr, &decoded.payment_hash, PaymentType::InboundHodl).await;
    assert_eq!(payee_payment_again.payment_type, PaymentType::InboundHodl);
    assert_eq!(payee_payment_again.status, HTLCStatus::Failed);
    invoice_claim_expect_error(
        node2_addr,
        payment_hash_hex.clone(),
        preimage_hex,
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;
    invoice_cancel_expect_error(
        node2_addr,
        payment_hash_hex,
        StatusCode::FORBIDDEN,
        "Invoice cannot be cancelled",
        "InvoiceNotCancellable",
    )
    .await;
}

fn set_inbound_rgb_payment_amount(test_dir: &str, payment_hash: &str, amount: u64) {
    let payment_hash = validate_and_parse_payment_hash(payment_hash).unwrap();
    let ldk_data_dir = Path::new(test_dir).join(LDK_DIR);
    let payment_info_path = get_rgb_payment_info_path(&payment_hash, &ldk_data_dir, true);
    assert!(
        payment_info_path.exists(),
        "inbound RGB payment metadata must exist before it is modified"
    );

    let mut payment_info = parse_rgb_payment_info(&payment_info_path);
    payment_info.amount = amount;
    fs::write(
        payment_info_path,
        serde_json::to_string(&payment_info).unwrap(),
    )
    .unwrap();
}

async fn setup_two_nodes_with_asset_channel(
    test_dir_suffix: &str,
    port_offset: u16,
) -> (SocketAddr, SocketAddr, String, String, String) {
    let test_dir_base = format!("{TEST_DIR_BASE}{test_dir_suffix}/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let node1_port = NODE1_PEER_PORT + port_offset;
    let node2_port = NODE2_PEER_PORT + port_offset;
    let (node1_addr, _) = start_node(&test_dir_node1, node1_port, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, node2_port, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    fund_and_create_utxos(node1_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let _channel = open_channel_with_retry(
        node1_addr,
        &node2_pubkey,
        Some(node2_port),
        Some(500000),
        Some(0),
        Some(100),
        Some(&asset_id),
        None,
        5,
    )
    .await;

    (
        node1_addr,
        node2_addr,
        test_dir_node1,
        test_dir_node2,
        asset_id,
    )
}

async fn wait_for_ln_payment_with_timeout(
    node_address: SocketAddr,
    payment_hash: &str,
    expected_status: HTLCStatus,
    timeout: std::time::Duration,
) -> Result<Payment, APIError> {
    let t_0 = std::time::Instant::now();
    loop {
        if let Some(payment) =
            check_payment_status(node_address, payment_hash, expected_status).await
        {
            return Ok(payment);
        }
        if t_0.elapsed() > timeout {
            return Err(APIError::Unexpected(format!(
                "payment {payment_hash} on {node_address} did not reach status \
                {expected_status:?} in {timeout:?}"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn wait_for_no_rgb_payment_pending_artifacts(
    test_dir: &str,
    payment_hash: &str,
) -> Result<(), APIError> {
    let ldk_data_dir = Path::new(test_dir).join(LDK_DIR);
    let pending_extension = ".outbound_pending";
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let pending_exists = std::fs::read_dir(&ldk_data_dir)
            .map_err(|err| {
                APIError::Unexpected(format!("cannot inspect RGB payment files: {err}"))
            })?
            .flatten()
            .any(|entry| {
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                file_name.contains(payment_hash) && file_name.ends_with(pending_extension)
            });

        if !pending_exists {
            return Ok(());
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
            return Err(APIError::Unexpected(format!(
                "RGB pending artifacts for {payment_hash} did not clear"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cancel_hodl_invoice_btc_rgb() {
    initialize();

    let (node1_addr, node2_addr, test_dir_node1, test_dir_node2, asset_id) =
        setup_two_nodes_with_asset_channel("cancel-hodl-btc-rgb", 10).await;
    let initial_ln_rgb_balance_node1 = asset_balance_offchain_outbound(node1_addr, &asset_id).await;
    let initial_ln_rgb_balance_node2 = asset_balance_offchain_outbound(node2_addr, &asset_id).await;

    let (preimage, payment_hash) = random_preimage_and_hash();

    // create a HODL invoice
    let LNInvoiceResponse {
        invoice: hodl_invoice,
    } = ln_invoice_hodl(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(ASSET_PAYMENT_AMOUNT),
        120,
        payment_hash.clone(),
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &hodl_invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash);
    assert_eq!(decoded.amt_msat, Some(HTLC_MIN_MSAT));
    assert_eq!(decoded.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded.asset_amount, Some(ASSET_PAYMENT_AMOUNT));

    // attempt to cancel before the payment is claimable
    invoice_cancel_expect_error(
        node2_addr,
        payment_hash.clone(),
        StatusCode::FORBIDDEN,
        "Invoice cannot be cancelled",
        "InvoiceNotCancellable",
    )
    .await;
    assert!(matches!(
        invoice_status(node2_addr, &hodl_invoice).await,
        InvoiceStatus::Pending
    ));

    // send the payment
    let _ = send_payment_with_status(node1_addr, hodl_invoice.clone(), HTLCStatus::Pending).await;

    // wait for the payee's payment to become claimable
    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Claimable)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to appear: {err}"));
    let payee_claimable =
        wait_for_ln_payment(node2_addr, &payment_hash, HTLCStatus::Claimable).await;
    assert_eq!(payee_claimable.asset_id, Some(asset_id.clone()));
    assert_eq!(payee_claimable.asset_amount, Some(ASSET_PAYMENT_AMOUNT));
    assert!(matches!(
        invoice_status(node2_addr, &hodl_invoice).await,
        InvoiceStatus::Claimable
    ));

    // cancel the HODL invoice
    cancel_hodl_invoice(node2_addr, payment_hash.clone()).await;

    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Cancelled)
        .await
        .unwrap_or_else(|err| panic!("wait for cancelled payment to persist: {err}"));
    wait_for_no_rgb_payment_pending_artifacts(&test_dir_node1, &payment_hash)
        .await
        .unwrap_or_else(|err| panic!("wait for sender RGB pending artifacts to clear: {err}"));

    // assert that the payer's payment failed
    let payer_failed = wait_for_ln_payment(node1_addr, &payment_hash, HTLCStatus::Failed).await;
    assert_eq!(payer_failed.asset_id, Some(asset_id.clone()));
    assert_eq!(payer_failed.asset_amount, Some(ASSET_PAYMENT_AMOUNT));

    // assert that the payee's invoice was cancelled
    assert!(matches!(
        invoice_status(node2_addr, &hodl_invoice).await,
        InvoiceStatus::Cancelled
    ));

    // attempt to cancel the invoice again; cancellation is not idempotent
    invoice_cancel_expect_error(
        node2_addr,
        payment_hash.clone(),
        StatusCode::FORBIDDEN,
        "Invoice cannot be cancelled",
        "InvoiceNotCancellable",
    )
    .await;

    // attempt to claim a non-claimable HODL invoice
    invoice_claim_expect_error(
        node2_addr,
        payment_hash.clone(),
        preimage,
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;

    // assert that the payee's payment remains cancelled
    let payee_payment = wait_for_ln_payment(node2_addr, &payment_hash, HTLCStatus::Cancelled).await;
    assert_eq!(payee_payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payee_payment.asset_amount, Some(ASSET_PAYMENT_AMOUNT));

    // verify that RGB balances are unchanged
    wait_for_ln_balance(node1_addr, &asset_id, initial_ln_rgb_balance_node1).await;
    wait_for_ln_balance(node2_addr, &asset_id, initial_ln_rgb_balance_node2).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn claim_hodl_invoice_btc_rgb() {
    initialize();

    let (node1_addr, mut node2_addr, _test_dir_node1, test_dir_node2, asset_id) =
        setup_two_nodes_with_asset_channel("claim-hodl-btc-rgb", 20).await;

    let initial_ln_balance_node1 = asset_balance_offchain_outbound(node1_addr, &asset_id).await;
    let initial_ln_balance_node2 = asset_balance_offchain_outbound(node2_addr, &asset_id).await;

    let (preimage, payment_hash) = random_preimage_and_hash();

    // create a HODL invoice
    let LNInvoiceResponse { invoice } = ln_invoice_hodl(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(ASSET_PAYMENT_AMOUNT),
        120,
        payment_hash.clone(),
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;

    // reject a second HODL invoice with the same payment hash
    let duplicate_hash_payload = LNInvoiceRequest {
        amt_msat: Some(10_000),
        expiry_sec: 60,
        asset_id: None,
        asset_amount: None,
        payment_hash: Some(payment_hash.clone()),
    };
    let duplicate_hash_res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/lninvoice"))
        .json(&duplicate_hash_payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        duplicate_hash_res,
        StatusCode::BAD_REQUEST,
        "Payment hash already used",
        "PaymentHashAlreadyUsed",
    )
    .await;

    // send the payment
    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Claimable)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to appear: {err}"));
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Claimable).await;
    assert_eq!(payee_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payee_payment.asset_amount, Some(ASSET_PAYMENT_AMOUNT));
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Claimable
    ));

    // restart the payee while the HODL invoice is still claimable and verify that the
    // persisted inbound payment state is restored before claiming it
    shutdown(&[node2_addr]).await;
    let (restarted_node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT + 20, true).await;
    node2_addr = restarted_node2_addr;

    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Claimable)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry after restart: {err}"));

    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Claimable).await;
    assert_eq!(payee_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payee_payment.asset_amount, Some(ASSET_PAYMENT_AMOUNT));

    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Claimable
    ));

    // reject an incorrect preimage
    let (wrong_preimage, _) = random_preimage_and_hash();
    invoice_claim_expect_error(
        node2_addr,
        payment_hash.clone(),
        wrong_preimage,
        StatusCode::BAD_REQUEST,
        "Invalid payment preimage",
        "InvalidPaymentPreimage",
    )
    .await;

    // claim the HODL invoice
    claim_hodl_invoice(node2_addr, payment_hash.clone(), preimage.clone()).await;

    // reject cancellation after claiming has started
    let cancel_while_claiming_payload = CancelHodlInvoiceRequest {
        payment_hash: payment_hash.clone(),
    };
    let cancel_while_claiming_res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/cancelhodlinvoice"))
        .json(&cancel_while_claiming_payload)
        .send()
        .await
        .unwrap();
    if cancel_while_claiming_res.status() == StatusCode::FORBIDDEN {
        check_response_is_nok(
            cancel_while_claiming_res,
            StatusCode::FORBIDDEN,
            "Invoice settlement is in progress",
            "InvoiceSettlingInProgress",
        )
        .await;
    } else if cancel_while_claiming_res.status() == StatusCode::CONFLICT {
        check_response_is_nok(
            cancel_while_claiming_res,
            StatusCode::CONFLICT,
            "Invoice is already claimed",
            "InvoiceAlreadyClaimed",
        )
        .await;
    } else {
        let status = cancel_while_claiming_res.status();
        let body = cancel_while_claiming_res.text().await.unwrap_or_default();
        panic!("expected 403 settling-in-progress or 409 already claimed, got {status}: {body}");
    }

    // a second claim must be rejected while settlement is in progress or after settlement
    let claim_while_claiming_payload = ClaimHodlInvoiceRequest {
        payment_hash: payment_hash.clone(),
        payment_preimage: preimage.clone(),
    };
    let claim_while_claiming_res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/claimhodlinvoice"))
        .json(&claim_while_claiming_payload)
        .send()
        .await
        .unwrap();
    if claim_while_claiming_res.status() == StatusCode::FORBIDDEN {
        check_response_is_nok(
            claim_while_claiming_res,
            StatusCode::FORBIDDEN,
            "Invoice settlement is in progress",
            "InvoiceSettlingInProgress",
        )
        .await;
    } else if claim_while_claiming_res.status() == StatusCode::CONFLICT {
        check_response_is_nok(
            claim_while_claiming_res,
            StatusCode::CONFLICT,
            "Invoice is already claimed",
            "InvoiceAlreadyClaimed",
        )
        .await;
    } else {
        let status = claim_while_claiming_res.status();
        let body = claim_while_claiming_res.text().await.unwrap_or_default();
        panic!("expected 403 settling-in-progress or 409 already claimed, got {status}: {body}");
    }

    // wait until the invoice's encoded expiry time has passed
    let invoice_expiry_ts = decoded
        .timestamp
        .saturating_add(decoded.expiry_sec)
        .saturating_add(1);
    let wait_timeout = std::time::Duration::from_secs(decoded.expiry_sec.saturating_add(30));
    assert!(
        wait_timeout > std::time::Duration::ZERO,
        "invoice expiry wait timeout must be > 0"
    );
    let target_ts = i128::from(invoice_expiry_ts);
    let t_0 = std::time::Instant::now();
    loop {
        let now_ts = i128::from(OffsetDateTime::now_utc().unix_timestamp());
        if now_ts >= target_ts {
            break;
        }
        if t_0.elapsed() > wait_timeout {
            panic!("invoice expiry did not pass in time (target: {target_ts}, current: {now_ts})");
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // claiming an already settled HODL invoice is not idempotent
    invoice_claim_expect_error(
        node2_addr,
        payment_hash.clone(),
        preimage.clone(),
        StatusCode::CONFLICT,
        "Invoice is already claimed",
        "InvoiceAlreadyClaimed",
    )
    .await;

    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Succeeded
    ));
    assert_eq!(payee_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payee_payment.asset_amount, Some(ASSET_PAYMENT_AMOUNT));

    // /getpayment must expose the preimage after the HODL invoice is claimed
    let payee_payment_from_get =
        get_payment(node2_addr, &decoded.payment_hash, PaymentType::InboundHodl).await;
    assert_eq!(
        payee_payment_from_get.payment_type,
        PaymentType::InboundHodl
    );
    assert_eq!(payee_payment_from_get.preimage, Some(preimage.clone()));

    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payer_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payer_payment.asset_amount, Some(ASSET_PAYMENT_AMOUNT));
    assert_eq!(payer_payment.preimage, Some(preimage));

    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Succeeded)
        .await
        .unwrap_or_else(|err| panic!("wait for claimed payment to persist as succeeded: {err}"));

    // verify RGB balances after successful payment
    wait_for_ln_balance(
        node1_addr,
        &asset_id,
        initial_ln_balance_node1 - ASSET_PAYMENT_AMOUNT,
    )
    .await;
    wait_for_ln_balance(
        node2_addr,
        &asset_id,
        initial_ln_balance_node2 + ASSET_PAYMENT_AMOUNT,
    )
    .await;

    // reject cancellation when the HODL invoice is already claimed
    invoice_cancel_expect_error(
        node2_addr,
        payment_hash.clone(),
        StatusCode::CONFLICT,
        "Invoice is already claimed",
        "InvoiceAlreadyClaimed",
    )
    .await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn claim_hodl_invoice_handles_htlc_handling_failed() {
    initialize();

    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, _asset_id) =
        setup_two_nodes_with_asset_channel("claim-hodl-htlc-failed", 30).await;
    let (preimage, payment_hash) = random_preimage_and_hash();

    let invoice = ln_invoice_hodl(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        None,
        None,
        120,
        payment_hash.clone(),
    )
    .await
    .invoice;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;

    send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Claimable)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to appear: {err}"));
    let payee_pubkey = node_info(node2_addr).await.pubkey;
    let fail_claim_guard = NodeOverrideGuard::set(&FAIL_HODL_CLAIM_ON_NODE, &payee_pubkey);
    let preimage_for_retry = preimage.clone();
    claim_hodl_invoice(node2_addr, payment_hash.clone(), preimage).await;
    drop(fail_claim_guard);

    let failed_payee =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(failed_payee.status, HTLCStatus::Failed);
    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Failed)
        .await
        .unwrap_or_else(|err| panic!("wait for failed inbound entry: {err}"));

    let failed_payer = wait_for_ln_payment(node1_addr, &payment_hash, HTLCStatus::Failed).await;
    assert_eq!(failed_payer.status, HTLCStatus::Failed);
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Failed
    ));

    shutdown(&[node2_addr]).await;
    let (restarted_node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT + 30, true).await;

    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Failed)
        .await
        .unwrap_or_else(|err| panic!("wait for failed entry after restart: {err}"));
    invoice_claim_expect_error(
        restarted_node2_addr,
        payment_hash,
        preimage_for_retry,
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn expire_hodl_invoice_time_and_blocks() {
    initialize();

    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, _asset_id) =
        setup_two_nodes_with_asset_channel("expire-hodl-time-blocks", 40).await;

    // verify expiry triggered by wall-clock time
    run_expire_hodl_invoice_case(node1_addr, node2_addr, &test_dir_node2, ExpiryTrigger::Time)
        .await;
    // verify expiry triggered by block height
    run_expire_hodl_invoice_case(
        node1_addr,
        node2_addr,
        &test_dir_node2,
        ExpiryTrigger::Blocks,
    )
    .await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_invoice_rejects_insufficient_asset_amount() {
    initialize();

    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, asset_id) =
        setup_two_nodes_with_asset_channel("rgb-amount-validation", 50).await;
    let initial_node1_balance = asset_balance_offchain_outbound(node1_addr, &asset_id).await;
    let initial_node2_balance = asset_balance_offchain_outbound(node2_addr, &asset_id).await;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // an RGB HODL invoice must fail instead of becoming Claimable when its
    // persisted inbound RGB amount is below the invoice requirement
    let (preimage, hodl_payment_hash) = random_preimage_and_hash();
    let LNInvoiceResponse {
        invoice: hodl_invoice,
    } = ln_invoice_hodl(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(ASSET_PAYMENT_AMOUNT),
        120,
        hodl_payment_hash.clone(),
    )
    .await;

    let defer_guard = defer_payment_claimable(&node2_pubkey);
    send_payment_raw(node1_addr, hodl_invoice.clone()).await;
    wait_for_deferred_payment().await;
    set_inbound_rgb_payment_amount(
        &test_dir_node2,
        &hodl_payment_hash,
        ASSET_PAYMENT_AMOUNT - 1,
    );
    drop(defer_guard);

    let hodl_payee_failed =
        wait_for_ln_payment(node2_addr, &hodl_payment_hash, HTLCStatus::Failed).await;
    assert_eq!(hodl_payee_failed.status, HTLCStatus::Failed);
    assert_eq!(
        hodl_payee_failed.asset_amount,
        Some(ASSET_PAYMENT_AMOUNT - 1)
    );
    assert!(matches!(
        invoice_status(node2_addr, &hodl_invoice).await,
        InvoiceStatus::Failed
    ));
    let hodl_payer_failed =
        wait_for_ln_payment(node1_addr, &hodl_payment_hash, HTLCStatus::Failed).await;
    assert_eq!(hodl_payer_failed.status, HTLCStatus::Failed);
    invoice_claim_expect_error(
        node2_addr,
        hodl_payment_hash,
        preimage,
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;

    // the same validation runs before auto-claiming a regular RGB invoice
    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(ASSET_PAYMENT_AMOUNT),
        120,
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;

    let defer_guard = defer_payment_claimable(&node2_pubkey);
    send_payment_raw(node1_addr, invoice.clone()).await;
    wait_for_deferred_payment().await;
    set_inbound_rgb_payment_amount(
        &test_dir_node2,
        &decoded.payment_hash,
        ASSET_PAYMENT_AMOUNT - 1,
    );
    drop(defer_guard);

    let auto_claim_payee_failed =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(auto_claim_payee_failed.status, HTLCStatus::Failed);
    assert_eq!(
        auto_claim_payee_failed.asset_amount,
        Some(ASSET_PAYMENT_AMOUNT - 1)
    );
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Failed
    ));
    let auto_claim_payer_failed =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Failed).await;
    assert_eq!(auto_claim_payer_failed.status, HTLCStatus::Failed);

    wait_for_ln_balance(node1_addr, &asset_id, initial_node1_balance).await;
    wait_for_ln_balance(node2_addr, &asset_id, initial_node2_balance).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn use_same_hodl_invoice_hash_for_inbound_rgb_and_outbound_btc() {
    initialize();

    let test_dir_suffix = "swap-hodl-same-hash";
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, asset_id) =
        setup_two_nodes_with_asset_channel(test_dir_suffix, 60).await;
    let test_dir_node3 = format!("{TEST_DIR_BASE}{test_dir_suffix}/node3");
    let node3_port = NODE3_PEER_PORT + 60;
    let (node3_addr, _) = start_node(&test_dir_node3, node3_port, false).await;
    fund_and_create_utxos(node3_addr, None).await;

    let node3_pubkey = node_info(node3_addr).await.pubkey;
    open_channel_with_retry(
        node2_addr,
        &node3_pubkey,
        Some(node3_port),
        Some(500_000),
        Some(0),
        None,
        None,
        None,
        5,
    )
    .await;

    let (_inbound_preimage, payment_hash) = random_preimage_and_hash();

    // create a HODL invoice for node2 to receive RGB assets
    let inbound_invoice = ln_invoice_hodl(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(ASSET_PAYMENT_AMOUNT),
        120,
        payment_hash.clone(),
    )
    .await
    .invoice;

    // send the payment from node1 to node2
    send_payment_with_status(node1_addr, inbound_invoice, HTLCStatus::Pending).await;
    wait_for_inbound_payment_status(&test_dir_node2, &payment_hash, HTLCStatus::Claimable)
        .await
        .unwrap_or_else(|err| panic!("wait for inbound RGB payment to become claimable: {err}"));

    let inbound_rgb_path = Path::new(&test_dir_node2)
        .join(LDK_DIR)
        .join(format!("{payment_hash}.inbound"));
    assert!(
        inbound_rgb_path.exists(),
        "expected inbound RGB metadata at {}",
        inbound_rgb_path.display()
    );

    // create a HODL invoice for node3 to receive BTC
    let outbound_invoice = ln_invoice_hodl(
        node3_addr,
        Some(HTLC_MIN_MSAT),
        None,
        None,
        120,
        payment_hash,
    )
    .await
    .invoice;

    // attempt to send the BTC payment from node2 to node3
    let response = reqwest::Client::new()
        .post(format!("http://{node2_addr}/sendpayment"))
        .json(&SendPaymentRequest {
            invoice: outbound_invoice,
            amt_msat: None,
            asset_id: None,
            asset_amount: None,
        })
        .send()
        .await
        .expect("sendpayment request should reach the node");

    assert!(response.status().is_success());
}
