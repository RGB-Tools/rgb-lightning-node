use super::*;

const TEST_DIR_BASE: &str = "tmp/concurrent_btc_payments/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn concurrent_btc_payments() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let test_dir_node4 = format!("{TEST_DIR_BASE}node4");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;
    let (node4_addr, _) = start_node(&test_dir_node4, NODE4_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;
    fund_and_create_utxos(node4_addr, None).await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let capacity_sat = 100000;
    let push_msat = 0;
    open_channel(
        node2_addr,
        &node1_pubkey,
        Some(NODE1_PEER_PORT),
        Some(capacity_sat),
        Some(push_msat),
        None,
        None,
    )
    .await;
    open_channel(
        node3_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(capacity_sat),
        Some(push_msat),
        None,
        None,
    )
    .await;
    open_channel(
        node4_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(capacity_sat),
        Some(push_msat),
        None,
        None,
    )
    .await;
    let channels = list_channels(node1_addr).await;
    assert_eq!(channels.len(), 1);
    let channel = channels.first().unwrap();
    assert_eq!(channel.local_balance_sat, 0);

    let amt_msat_1 = 4000000;
    let amt_msat_2 = 5000000;
    let LNInvoiceResponse { invoice: invoice_1 } =
        ln_invoice(node1_addr, Some(amt_msat_1), None, None, 900).await;
    let LNInvoiceResponse { invoice: invoice_2 } =
        ln_invoice(node1_addr, Some(amt_msat_2), None, None, 900).await;

    // send payments
    let payload_1 = SendPaymentRequest {
        invoice: invoice_1.clone(),
        amt_msat: None,
    };
    let res_1 = reqwest::Client::new()
        .post(format!("http://{node3_addr}/sendpayment"))
        .json(&payload_1)
        .send()
        .await
        .unwrap()
        .json::<SendPaymentResponse>()
        .await
        .unwrap();
    let payload_2 = SendPaymentRequest {
        invoice: invoice_2.clone(),
        amt_msat: None,
    };
    let res_2 = reqwest::Client::new()
        .post(format!("http://{node4_addr}/sendpayment"))
        .json(&payload_2)
        .send()
        .await
        .unwrap()
        .json::<SendPaymentResponse>()
        .await
        .unwrap();

    // check there are 2 concurrent pending payments
    let payments_1 = list_payments(node1_addr).await;
    assert_eq!(payments_1.len(), 2);
    assert!(payments_1.iter().all(|p| p.status == HTLCStatus::Pending));

    // wait for payments to have succeeded
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if check_payment_status(
            node3_addr,
            &res_1.payment_hash.clone().unwrap(),
            HTLCStatus::Succeeded,
        )
        .await
        .is_some()
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("cannot find successful payment")
        }
    }
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if check_payment_status(
            node4_addr,
            &res_2.payment_hash.clone().unwrap(),
            HTLCStatus::Succeeded,
        )
        .await
        .is_some()
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("cannot find successful payment")
        }
    }

    let status_1 = invoice_status(node1_addr, &invoice_1).await;
    let status_2 = invoice_status(node1_addr, &invoice_2).await;
    assert!(matches!(status_1, InvoiceStatus::Succeeded));
    assert!(matches!(status_2, InvoiceStatus::Succeeded));

    let decoded_1 = decode_ln_invoice(node1_addr, &invoice_1).await;
    let decoded_2 = decode_ln_invoice(node1_addr, &invoice_2).await;
    let payments = list_payments(node1_addr).await;
    let payment_1 = payments
        .iter()
        .find(|p| p.payment_hash == decoded_1.payment_hash)
        .unwrap();
    let payment_2 = payments
        .iter()
        .find(|p| p.payment_hash == decoded_2.payment_hash)
        .unwrap();
    assert_eq!(payment_1.amt_msat, Some(amt_msat_1));
    assert_eq!(payment_2.amt_msat, Some(amt_msat_2));

    let channels = list_channels(node1_addr).await;
    assert_eq!(channels.len(), 1);
    let channel = channels.first().unwrap();
    assert_eq!(channel.local_balance_sat * 1000, amt_msat_1 + amt_msat_2);
}
