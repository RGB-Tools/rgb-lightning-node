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
