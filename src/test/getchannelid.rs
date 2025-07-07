use super::*;

const TEST_DIR_BASE: &str = "tmp/getchannelid/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn getchannelid_success() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}success/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    // open channel with custom temporary channel ID
    println!("\nopening channel with custom temporary channel ID");
    let temporary_channel_id =
        s!("0011223344556677889900112233445566778899001122334455667788990011");

    let channel = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
        None,
        None,
        Some(&temporary_channel_id),
        true,
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);

    // get channel ID from temporary channel ID
    println!("\ngetting final channel ID from temporary one");
    let chan_id = get_channel_id(node1_addr, &temporary_channel_id).await;
    assert_eq!(chan_id, channel.channel_id);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn getchannelid_fail() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}fail/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    // get channel ID from invalid (odd char) temporary channel ID
    println!("\ngetting channel ID for an odd temporary one");
    let temporary_channel_id = s!("odd");
    let payload = GetChannelIdRequest {
        temporary_channel_id,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getchannelid"))
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

    // get channel ID from invalid (short) temporary channel ID
    println!("\ngetting channel ID for a short temporary one");
    let temporary_channel_id = s!("0123456789abcdef");
    let payload = GetChannelIdRequest {
        temporary_channel_id,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getchannelid"))
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

    // get channel ID from unknown temporary channel ID
    println!("\ngetting channel ID for an unknown temporary one");
    let temporary_channel_id =
        s!("0011223344556677889900112233445566778899001122334455667788990011");
    let payload = GetChannelIdRequest {
        temporary_channel_id,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getchannelid"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Unknown temporary channel ID",
        "UnknownTemporaryChannelId",
    )
    .await;
}
