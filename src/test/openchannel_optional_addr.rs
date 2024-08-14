use super::*;

const TEST_DIR_BASE: &str = "tmp/openchannel_optional_addr/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn openchannel_optional_addr() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    // open channel without addr and without having connected to the peer > fails
    println!("\nopening channel with no addr (peer not connected)");
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: node2_pubkey.to_string(),
        capacity_sat: 100_000,
        push_msat: 3_500_000,
        asset_amount: Some(600),
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
        "Invalid peer info: cannot find the address for the provided pubkey",
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 0);
    assert_eq!(channels_2.len(), 0);

    // open without addr after having connected to the peer > works
    println!("\nconnecting peer");
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;

    println!("\nopening channel with no addr (peer connected)");
    let _channel = open_channel(
        node1_addr,
        &node2_pubkey,
        None,
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
}
