use super::*;

const TEST_DIR_BASE: &str = "tmp/openchannel_fail/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn openchannel_fail() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_with_and_create_utxos(node1_addr, Some(1), 300_000).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    // insufficient BTC funds
    let res = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(300_000),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await;
    check_response_is_nok(
        res.unwrap_err(),
        reqwest::StatusCode::FORBIDDEN,
        "Not enough funds",
        "InsufficientFunds",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // insufficient colored bitcoin funds
    fund_wallet(address(node2_addr).await, 1000000);
    let res = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(200),
        Some(&asset_id),
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await;
    check_response_is_nok(
        res.unwrap_err(),
        reqwest::StatusCode::FORBIDDEN,
        "Not enough funds",
        "InsufficientFunds",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // insufficient RGB assets
    fund_and_create_utxos(node1_addr, Some(9)).await;
    let res = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(ISSUE_AMT + 1),
        Some(&asset_id),
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await;
    check_response_is_nok(
        res.unwrap_err(),
        reqwest::StatusCode::FORBIDDEN,
        "Not enough assets",
        "InsufficientAssets",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with unknown asset
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(s!("rgb:EIkAVQvq-WbAb5JG-CYxbUER-oqDNwne-ZNxBDID-p0cpf9U")),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Unknown RGB contract ID",
        "UnknownContractId",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with bad asset amount
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(0),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel RGB amount must be equal to or higher than 1",
        "InvalidAmount",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with bad asset ID
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(s!("bad asset ID")),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid asset ID: bad asset ID",
        "InvalidAssetID",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with push_asset_amount but without RGB info
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: None,
        asset_id: None,
        push_asset_amount: Some(100),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: push_asset_amount can only be used with RGB channels (asset_id must be specified)",
        "InvalidAmount",
    )
    .await;

    // open with push_asset_amount higher than asset_amount
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(500),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: Some(600),
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: push_asset_amount cannot be higher than asset_amount",
        "InvalidAmount",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid BTC amount (too low)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 1_000,
        push_msat: 3_500_000,
        asset_amount: None,
        asset_id: None,
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel amount must be equal to or higher than 5506 sats",
        "InvalidAmount",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid BTC amount (too high)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 20000000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel amount must be equal to or less than 16777215 sats",
        "InvalidAmount",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid push BTC amount (too high)
    println!("setting MOCK_FEE");
    *MOCK_FEE.lock().unwrap() = Some(1000);
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 100_000_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Insufficient capacity to cover the commitment transaction fees",
        "InsufficientCapacity",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with invalid push BTC amount (higher than capacity)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 100_000_001,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: Channel push amount cannot be higher than the capacity",
        "InvalidAmount",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open an RGB channel with anchors disabled
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: false,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Anchor outputs are required for RGB channels",
        "AnchorsRequired",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with insufficient capacity
    println!("setting MOCK_FEE");
    *MOCK_FEE.lock().unwrap() = Some(5000);
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 5506,
        push_msat: 0,
        asset_amount: None,
        asset_id: None,
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Insufficient capacity to cover the commitment transaction fees (9920 sat)",
        "InsufficientCapacity",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with insufficient assets
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(2000),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Not enough assets",
        "InsufficientAssets",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open with an invalid temporary channel id
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: Some(s!("ttoooosshhoorrtt")),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid channel ID",
        "InvalidChannelID",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);
}
