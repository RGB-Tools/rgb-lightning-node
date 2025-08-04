use super::*;
const TEST_DIR_BASE: &str = "tmp/push_rgb_assets/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn test_push_rgb_assets() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}test_push_rgb_assets/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    connect_peer(node1_addr, &node2_pubkey, &format!("127.0.0.1:{NODE2_PEER_PORT}"),).await;
    
    // Open channel with asset push: 600 total, push 250 to counterparty
    let channel = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600), 
        Some(&asset_id),
        Some(250), 
        None,
        None,
        None,
        true,
    )
    .await;

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);

    // Check balances after channel opening with push
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);
    
    let node1_channels = list_channels(node1_addr).await;
    let node1_channel = node1_channels.iter().find(|c| c.channel_id == channel.channel_id).unwrap();
    assert_eq!(node1_channel.asset_local_amount, Some(350)); 
    assert_eq!(node1_channel.asset_remote_amount, Some(250)); 

    let node2_channels = list_channels(node2_addr).await;
    let node2_channel = node2_channels.iter().find(|c| c.channel_id == channel.channel_id).unwrap();
    assert_eq!(node2_channel.asset_local_amount, Some(250)); 
    assert_eq!(node2_channel.asset_remote_amount, Some(350)); 

}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn test_push_rgb_assets_validation() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}test_push_rgb_assets_validation/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // Fund node1 with on-chain funds  
    fund_and_create_utxos(node1_addr, None).await;

    // Issue an RGB asset on node1
    let asset = issue_asset_nia(node1_addr).await;
    let asset_id = asset.asset_id;

    // Connect peers
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;
    
    // Test 1: Try to use push_asset_amount without RGB channel (should fail)
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: None,
        asset_id: None,
        push_asset_amount: Some(100), // This should fail
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };

    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    
    assert_eq!(res.status(), 400); // Should fail with bad request
    

    // Test 2: Try to push more than asset_amount (should fail)  
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(500),
        asset_id: Some(asset_id.clone()),
        push_asset_amount: Some(600), // More than asset_amount, should fail
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };

    let res = reqwest::Client::new()
        .post(format!("http://{}/openchannel", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    
    assert_eq!(res.status(), 400); // Should fail with bad request

    println!("✓ RGB asset push validation working correctly!");
}