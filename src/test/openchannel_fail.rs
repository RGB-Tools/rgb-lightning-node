use super::*;

const TEST_DIR_BASE: &str = "tmp/open_fail/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn open_fail() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, Some(1)).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_info = node_info(node2_addr).await;

    let node2_pubkey = node2_info.pubkey;

    // open with bad asset amount
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(0),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel RGB amount must be equal or higher than 1",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with bad asset ID
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(s!("bad asset ID")),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid asset ID: bad asset ID",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid BTC amount (too low)
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 1_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel amount must be equal or higher than 5506",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid BTC amount (too high)
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 20000000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel amount must be equal or less than 16777215",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid push amount (for an RGB channel)
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Push amount must be equal or higher than the dust limit (546000)",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open an RGB channel with anchors disabled
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: false,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Anchor outputs are required for RGB channels",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with insufficient assets
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(2000),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(res, reqwest::StatusCode::FORBIDDEN, "Not enough assets").await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with insufficient allocation slots
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Cannot open channel: InsufficientAllocationSlots",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    fund_and_create_utxos(node1_addr, Some(9)).await;
    // open a 1st channel (success)
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(res.status() == reqwest::StatusCode::OK);
    // open a 2nd channel while the previous open is still in progess (fail)
    let payload = OpenChannelRequest {
        peer_pubkey_and_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Cannot perform this operation while an open channel operation is in progress",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
}
