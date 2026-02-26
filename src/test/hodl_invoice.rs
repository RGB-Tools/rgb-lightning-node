use super::*;

const TEST_DIR_BASE: &str = "tmp/hodl_invoice/";

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

async fn invoice_settle_expect_error(
    node_address: SocketAddr,
    payment_hash: String,
    payment_preimage: String,
    expected_status: StatusCode,
    expected_message: &str,
    expected_name: &str,
) {
    println!("settling HODL invoice {payment_hash} on node {node_address}");
    let payload = SettleHodlInvoiceRequest {
        payment_hash,
        payment_preimage,
    };

    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/settlehodlinvoice"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(res, expected_status, expected_message, expected_name).await
}

async fn run_auto_claim_invoice_regression_case(node1_addr: SocketAddr, node2_addr: SocketAddr) {
    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, Some(HTLC_MIN_MSAT), None, None, 120, None).await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Succeeded).await;
    let _payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    let _payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Succeeded
    ));
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
    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        None,
        None,
        expiry_sec,
        Some(payment_hash_hex.clone()),
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash_hex);

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    wait_for_claimable_state(test_dir_node2, &payment_hash_hex, true)
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
            let claimable_path = Path::new(test_dir_node2)
                .join(LDK_DIR)
                .join(CLAIMABLE_HTLCS_FNAME);
            let storage = read_claimable_htlcs(&claimable_path);
            let hash = validate_and_parse_payment_hash(&payment_hash_hex).unwrap();
            let deadline_height = storage
                .payments
                .get(&hash)
                .and_then(|c| c.claim_deadline_height)
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

    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Failed
    ));
    wait_for_claimable_state(test_dir_node2, &payment_hash_hex, false)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to be removed: {err}"));
    let payee_payment = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(payee_payment.status, HTLCStatus::Failed);
    let payee_payment_again = get_payment(node2_addr, &decoded.payment_hash).await;
    assert_eq!(payee_payment_again.status, HTLCStatus::Failed);
    wait_for_claimable_state(test_dir_node2, &payment_hash_hex, false)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to stay removed: {err}"));

    invoice_settle_expect_error(
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
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;
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

async fn wait_for_claimable_state(
    node_test_dir: &str,
    payment_hash: &str,
    expected: bool,
) -> Result<(), APIError> {
    let claimable_exists = || -> Result<bool, APIError> {
        let claimable_path = Path::new(node_test_dir)
            .join(LDK_DIR)
            .join(CLAIMABLE_HTLCS_FNAME);
        let storage = read_claimable_htlcs(&claimable_path);
        let hash = validate_and_parse_payment_hash(payment_hash)?;
        Ok(storage.payments.contains_key(&hash))
    };

    let t_0 = OffsetDateTime::now_utc();
    loop {
        if claimable_exists()? == expected {
            return Ok(());
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
            return Err(APIError::Unexpected(format!(
                "claimable entry for {payment_hash} did not reach state {expected}"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
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

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn autoclaim_and_expire_hodl_invoice_time_and_blocks() {
    initialize();

    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, _asset_id) =
        setup_two_nodes_with_asset_channel("autoclaim-expiry", 10).await;

    run_auto_claim_invoice_regression_case(node1_addr, node2_addr).await;
    run_expire_hodl_invoice_case(node1_addr, node2_addr, &test_dir_node2, ExpiryTrigger::Time)
        .await;
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
async fn cancel_hodl_invoice_btc_rgb() {
    initialize();

    let asset_payment_amount = 10;
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, asset_id) =
        setup_two_nodes_with_asset_channel("cancel-btc-rgb-rgb", 20).await;
    let initial_ln_rgb_balance_node1 = asset_balance_offchain_outbound(node1_addr, &asset_id).await;
    let initial_ln_rgb_balance_node2 = asset_balance_offchain_outbound(node2_addr, &asset_id).await;

    let (preimage, payment_hash) = random_preimage_and_hash();
    let LNInvoiceResponse {
        invoice: hodl_invoice,
    } = ln_invoice(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(asset_payment_amount),
        120,
        Some(payment_hash.clone()),
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &hodl_invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash);
    assert_eq!(decoded.amt_msat, Some(HTLC_MIN_MSAT));
    assert_eq!(decoded.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded.asset_amount, Some(asset_payment_amount));

    invoice_cancel_expect_error(
        node2_addr,
        payment_hash.clone(),
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;
    assert!(matches!(
        invoice_status(node2_addr, &hodl_invoice).await,
        InvoiceStatus::Pending
    ));

    let _ = send_payment_with_status(node1_addr, hodl_invoice.clone(), HTLCStatus::Pending).await;
    wait_for_claimable_state(&test_dir_node2, &payment_hash, true)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to appear: {err}"));

    let payee_claimable =
        wait_for_ln_payment(node2_addr, &payment_hash, HTLCStatus::Claimable).await;
    assert_eq!(payee_claimable.asset_id, Some(asset_id.clone()));
    assert_eq!(payee_claimable.asset_amount, Some(asset_payment_amount));

    cancel_hodl_invoice(node2_addr, payment_hash.clone()).await;

    let payer_failed = wait_for_ln_payment(node1_addr, &payment_hash, HTLCStatus::Failed).await;
    assert_eq!(payer_failed.asset_id, Some(asset_id.clone()));
    assert_eq!(payer_failed.asset_amount, Some(asset_payment_amount));

    assert!(matches!(
        invoice_status(node2_addr, &hodl_invoice).await,
        InvoiceStatus::Cancelled
    ));

    wait_for_claimable_state(&test_dir_node2, &payment_hash, false)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to be removed: {err}"));

    invoice_cancel_expect_error(
        node2_addr,
        payment_hash.clone(),
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;

    invoice_settle_expect_error(
        node2_addr,
        payment_hash.clone(),
        preimage,
        StatusCode::NOT_FOUND,
        "No claimable HTLC found for this invoice",
        "InvoiceNotClaimable",
    )
    .await;

    let payee_payment = wait_for_ln_payment(node2_addr, &payment_hash, HTLCStatus::Cancelled).await;
    assert_eq!(payee_payment.asset_id, Some(asset_id.clone()));
    assert_eq!(payee_payment.asset_amount, Some(asset_payment_amount));

    wait_for_ln_balance(node1_addr, &asset_id, initial_ln_rgb_balance_node1).await;
    wait_for_ln_balance(node2_addr, &asset_id, initial_ln_rgb_balance_node2).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn settle_hodl_invoice_btc_rgb() {
    initialize();

    let asset_payment_amount = 10;
    let (node1_addr, node2_addr, _test_dir_node1, test_dir_node2, asset_id) =
        setup_two_nodes_with_asset_channel("settle-btc-rgb", 30).await;

    let initial_ln_balance_node1 = asset_balance_offchain_outbound(node1_addr, &asset_id).await;
    let initial_ln_balance_node2 = asset_balance_offchain_outbound(node2_addr, &asset_id).await;

    let (preimage, payment_hash) = random_preimage_and_hash();
    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(asset_payment_amount),
        120,
        Some(payment_hash.clone()),
    )
    .await;
    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.payment_hash, payment_hash);
    assert_eq!(decoded.amt_msat, Some(HTLC_MIN_MSAT));
    assert_eq!(decoded.asset_id, Some(asset_id.to_string()));
    assert_eq!(decoded.asset_amount, Some(asset_payment_amount));

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

    let _ = send_payment_with_status(node1_addr, invoice.clone(), HTLCStatus::Pending).await;
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Pending
    ));
    wait_for_claimable_state(&test_dir_node2, &payment_hash, true)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to appear: {err}"));
    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Claimable).await;
    assert_eq!(payee_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payee_payment.asset_amount, Some(asset_payment_amount));

    let (wrong_preimage, _) = random_preimage_and_hash();
    invoice_settle_expect_error(
        node2_addr,
        payment_hash.clone(),
        wrong_preimage,
        StatusCode::BAD_REQUEST,
        "Invalid payment preimage",
        "InvalidPaymentPreimage",
    )
    .await;

    let first_settle =
        settle_hodl_invoice(node2_addr, payment_hash.clone(), preimage.clone()).await;
    assert!(first_settle.changed);

    let cancel_while_settling_payload = CancelHodlInvoiceRequest {
        payment_hash: payment_hash.clone(),
    };
    let cancel_while_settling_res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/cancelhodlinvoice"))
        .json(&cancel_while_settling_payload)
        .send()
        .await
        .unwrap();
    if cancel_while_settling_res.status() == StatusCode::FORBIDDEN {
        check_response_is_nok(
            cancel_while_settling_res,
            StatusCode::FORBIDDEN,
            "Invoice settlement is in progress",
            "InvoiceSettlingInProgress",
        )
        .await;
    } else if cancel_while_settling_res.status() == StatusCode::CONFLICT {
        check_response_is_nok(
            cancel_while_settling_res,
            StatusCode::CONFLICT,
            "Invoice is already settled",
            "InvoiceAlreadySettled",
        )
        .await;
    } else {
        let status = cancel_while_settling_res.status();
        let body = cancel_while_settling_res.text().await.unwrap_or_default();
        panic!("expected 403 settling-in-progress or 409 already settled, got {status}: {body}");
    }

    let settle_while_settling_payload = SettleHodlInvoiceRequest {
        payment_hash: payment_hash.clone(),
        payment_preimage: preimage.clone(),
    };
    let settle_while_settling_res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/settlehodlinvoice"))
        .json(&settle_while_settling_payload)
        .send()
        .await
        .unwrap();
    if settle_while_settling_res.status() == StatusCode::FORBIDDEN {
        check_response_is_nok(
            settle_while_settling_res,
            StatusCode::FORBIDDEN,
            "Invoice settlement is in progress",
            "InvoiceSettlingInProgress",
        )
        .await;
    } else if settle_while_settling_res.status() == StatusCode::OK {
        let _ = _check_response_is_ok(settle_while_settling_res).await;
    } else {
        let status = settle_while_settling_res.status();
        let body = settle_while_settling_res.text().await.unwrap_or_default();
        panic!("expected 403 settling-in-progress or 200 already settled, got {status}: {body}");
    }

    let _ = wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;

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

    let second_settle =
        settle_hodl_invoice(node2_addr, payment_hash.clone(), preimage.clone()).await;
    assert!(!second_settle.changed);

    let payee_payment =
        wait_for_ln_payment(node2_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert!(matches!(
        invoice_status(node2_addr, &invoice).await,
        InvoiceStatus::Succeeded
    ));
    assert_eq!(payee_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payee_payment.asset_amount, Some(asset_payment_amount));

    let payer_payment =
        wait_for_ln_payment(node1_addr, &decoded.payment_hash, HTLCStatus::Succeeded).await;
    assert_eq!(payer_payment.asset_id, Some(asset_id.to_string()));
    assert_eq!(payer_payment.asset_amount, Some(asset_payment_amount));

    wait_for_claimable_state(&test_dir_node2, &payment_hash, false)
        .await
        .unwrap_or_else(|err| panic!("wait for claimable entry to be removed: {err}"));

    let wait_for_payment_preimage = async || -> Result<GetPaymentPreimageResponse, APIError> {
        let t_0 = OffsetDateTime::now_utc();
        loop {
            let resp = get_payment_preimage(node1_addr, &payment_hash).await;
            if matches!(resp.status, HTLCStatus::Succeeded) && resp.preimage.is_some() {
                return Ok(resp);
            }
            if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
                return Err(APIError::Unexpected(format!(
                    "preimage for {payment_hash} was not available in time"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    };

    let preimage_resp = wait_for_payment_preimage()
        .await
        .unwrap_or_else(|err| panic!("wait for payment preimage to be available: {err}"));

    assert_eq!(preimage_resp.status, HTLCStatus::Succeeded);
    assert_eq!(preimage_resp.preimage, Some(preimage));

    wait_for_ln_balance(
        node1_addr,
        &asset_id,
        initial_ln_balance_node1 - asset_payment_amount,
    )
    .await;
    wait_for_ln_balance(
        node2_addr,
        &asset_id,
        initial_ln_balance_node2 + asset_payment_amount,
    )
    .await;

    invoice_cancel_expect_error(
        node2_addr,
        payment_hash.clone(),
        StatusCode::CONFLICT,
        "Invoice is already settled",
        "InvoiceAlreadySettled",
    )
    .await;
}
