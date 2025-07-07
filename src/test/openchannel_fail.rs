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

    // open with insufficient allocation slots
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
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
        "No uncolored UTXOs are available (hint: call createutxos)",
        "NoAvailableUtxos",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    fund_and_create_utxos(node1_addr, Some(9)).await;

    // open with unknown asset
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(s!("rgb:EIkAVQvq-WbAb5JG-CYxbUER-oqDNwne-ZNxBDID-p0cpf9U")),
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

    // open with bad asset amount
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(0),
        asset_id: Some(asset_id.clone()),
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

    // open with invalid BTC amount (too low)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 1_000,
        push_msat: 3_500_000,
        asset_amount: None,
        asset_id: None,
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

    // open a 1st channel (success)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id.clone()),
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
    assert!(res.status() == reqwest::StatusCode::OK);
    // open a 2nd channel while the previous open is still in progess (fail)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{node2_pubkey}@127.0.0.1:{NODE2_PEER_PORT}"),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(100),
        asset_id: Some(asset_id),
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
        "Cannot perform this operation while an open channel operation is in progress",
        "OpenChannelInProgress",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
}
