use super::*;

const TEST_DIR_BASE: &str = "tmp/out_of_band/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn out_of_band() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    // receiver creates a blind invoice with no transport endpoints (out-of-band exchange)
    let recipient_id = rgb_invoice_oob(node2_addr, None, Some(Assignment::Fungible(400)), false)
        .await
        .recipient_id;

    // sender pays the invoice out-of-band (empty transport endpoints); donation is false so the
    // batch waits for the counterparty ACK before being broadcast
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: recipient_id.clone(),
            witness_data: None,
            assignment: Assignment::Fungible(400),
            transport_endpoints: vec![],
        }],
    )]);
    let txid = send_assets(node1_addr, recipient_map, false).await;
    assert!(!txid.is_empty());

    // sender fetches the consignment it wrote, to hand it to the receiver out-of-band
    let consignment_hex = get_consignment(node1_addr, &asset_id, &txid).await;
    let consignment_bytes = hex_str_to_vec(&consignment_hex).unwrap();
    assert!(!consignment_bytes.is_empty());

    // receiver processes the out-of-band consignment: the transfer moves to WaitingBroadcast,
    // leaving the ACK to be communicated out-of-band
    let refreshed = provide_out_of_band_consignment(node2_addr, consignment_bytes, vec![]).await;
    assert_eq!(refreshed.transfers.len(), 1);
    assert!(refreshed.transfers.values().all(|t| {
        matches!(t.updated_status, Some(TransferStatus::WaitingBroadcast)) && t.failure.is_none()
    }));

    // the sender's outgoing transfer waits for the counterparty ACK
    let sender_send_transfer = list_transfers(node1_addr, &asset_id)
        .await
        .into_iter()
        .find(|t| t.recipient_id.as_deref() == Some(recipient_id.as_str()))
        .expect("sender should have a send transfer for the recipient");
    assert_eq!(
        sender_send_transfer.status,
        TransferStatus::WaitingCounterparty
    );

    // sender records the ACK: being the only recipient, this completes the batch and broadcasts it
    let ack = provide_out_of_band_ack(node1_addr, &recipient_id).await;
    let operation = ack
        .operation
        .expect("recording the last recipient's ACK should complete and broadcast the batch");
    assert_eq!(operation.txid, txid);

    // mine and refresh both sides to settle
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 400);

    // ACKing a transfer that is no longer WaitingCounterparty is a client error
    let res = provide_out_of_band_ack_res(node1_addr, &recipient_id).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Cannot provide out-of-band ACK",
        "CannotProvideOutOfBandAck",
    )
    .await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn out_of_band_media() {
    initialize();

    let file_path = "README.md";

    let test_dir_node1 = format!("{TEST_DIR_BASE}media/node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}media/node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // issue a CFA asset with media on the sender
    let asset = issue_asset_cfa(node1_addr, Some(file_path)).await;
    let asset_id = asset.asset_id;
    let media_digest = asset.media.unwrap().digest;

    // receiver creates a blind invoice with no transport endpoints (out-of-band exchange)
    let recipient_id = rgb_invoice_oob(node2_addr, None, Some(Assignment::Fungible(400)), false)
        .await
        .recipient_id;

    // sender pays the invoice out-of-band (empty transport endpoints)
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: recipient_id.clone(),
            witness_data: None,
            assignment: Assignment::Fungible(400),
            transport_endpoints: vec![],
        }],
    )]);
    let txid = send_assets(node1_addr, recipient_map, false).await;
    assert!(!txid.is_empty());

    // sender fetches the consignment and the media bytes to hand to the receiver out-of-band
    let consignment_hex = get_consignment(node1_addr, &asset_id, &txid).await;
    let consignment_bytes = hex_str_to_vec(&consignment_hex).unwrap();
    let media_hex = get_asset_media(node1_addr, &media_digest).await;
    let media_bytes = hex_str_to_vec(&media_hex).unwrap();
    assert!(!media_bytes.is_empty());

    // receiver processes the out-of-band consignment together with the media file
    let refreshed =
        provide_out_of_band_consignment(node2_addr, consignment_bytes, vec![media_bytes.clone()])
            .await;
    assert_eq!(refreshed.transfers.len(), 1);
    assert!(refreshed.transfers.values().all(|t| {
        matches!(t.updated_status, Some(TransferStatus::WaitingBroadcast)) && t.failure.is_none()
    }));

    // the receiver has resolved the media from the provided file (same digest and bytes)
    let received_media_hex = get_asset_media(node2_addr, &media_digest).await;
    assert_eq!(hex_str_to_vec(&received_media_hex).unwrap(), media_bytes);

    // sender records the ACK to complete and broadcast the batch
    let ack = provide_out_of_band_ack(node1_addr, &recipient_id).await;
    let operation = ack
        .operation
        .expect("recording the last recipient's ACK should complete and broadcast the batch");
    assert_eq!(operation.txid, txid);

    // mine and refresh both sides to settle
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1600);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 400);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn out_of_band_fail() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}fail/node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let post_form = |form: reqwest::multipart::Form| async move {
        reqwest::Client::new()
            .post(format!("http://{node1_addr}/provideoutofbandconsignment"))
            .multipart(form)
            .send()
            .await
            .unwrap()
    };

    let post_raw = |content_type: &'static str, body: &'static str| async move {
        reqwest::Client::new()
            .post(format!("http://{node1_addr}/provideoutofbandconsignment"))
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .await
            .unwrap()
    };

    // body is not multipart at all: the Multipart extractor rejects it before the handler runs
    let res = post_raw("application/json", "{}").await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid request",
        "InvalidRequest",
    )
    .await;

    // content-type declares a multipart boundary the body doesn't honor: parsing the (corrupt)
    // stream fails while reading fields, which is reported as a missing consignment
    let res = post_raw(
        "multipart/form-data; boundary=boundary",
        "not a valid multipart body",
    )
    .await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Consignment file has not been provided",
        "ConsignmentFileNotProvided",
    )
    .await;

    // no multipart field at all: the consignment is missing
    let res = post_form(reqwest::multipart::Form::new()).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Consignment file has not been provided",
        "ConsignmentFileNotProvided",
    )
    .await;

    // only media fields, no consignment field
    let form = reqwest::multipart::Form::new()
        .part("media", reqwest::multipart::Part::bytes(vec![1, 2, 3]));
    let res = post_form(form).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Consignment file has not been provided",
        "ConsignmentFileNotProvided",
    )
    .await;

    // empty consignment field
    let form = reqwest::multipart::Form::new()
        .part("file", reqwest::multipart::Part::bytes(Vec::<u8>::new()));
    let res = post_form(form).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Consignment file is empty",
        "ConsignmentFileEmpty",
    )
    .await;

    // non-empty consignment but an empty media file
    let form = reqwest::multipart::Form::new()
        .part("file", reqwest::multipart::Part::bytes(vec![1, 2, 3]))
        .part("media", reqwest::multipart::Part::bytes(Vec::<u8>::new()));
    let res = post_form(form).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Media file is empty",
        "MediaFileEmpty",
    )
    .await;

    // non-empty consignment that rgb-lib cannot parse: reported as an invalid consignment
    let form = reqwest::multipart::Form::new()
        .part("file", reqwest::multipart::Part::bytes(vec![1, 2, 3]));
    let res = post_form(form).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid consignment",
        "InvalidConsignment",
    )
    .await;
}
