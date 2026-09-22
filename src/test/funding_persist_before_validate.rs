use super::*;

const TEST_DIR_BASE: &str = "tmp/funding_persist_before_validate/";

/// A counterparty that puts more `push_asset_amount` on the wire than the channel asset amount
/// makes the acceptor reject the funding. The acceptor must not have persisted the peer's media
/// before that rejection: validation has to happen before anything is written to the wallet dirs.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn funding_persist_before_validate() {
    initialize();

    let file_path = "README.md";
    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let asset = issue_asset_cfa(node1_addr, Some(file_path)).await;
    let digest = asset.media.unwrap().digest;

    // baseline: node2 must not have the media before the channel attempt
    let pre = reqwest::Client::new()
        .post(format!("http://{node2_addr}/getassetmedia"))
        .json(&GetAssetMediaRequest {
            digest: digest.clone(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        pre.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "node2 unexpectedly already had the media before the channel attempt"
    );

    let _force_guard = NodeOverrideGuard::set(&FORCE_PUSH_ASSET_AMOUNT_ON_NODE, &node1_pubkey);

    open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100_000),
        None,
        Some(100),
        Some(&asset.asset_id),
        Some(0),
        None,
        None,
        None,
        true,
        true,
    )
    .await
    .unwrap();

    // node2 rejects the funding, which discards node1's pending channel
    wait_for_no_channels(node1_addr).await;
    assert!(list_channels(node2_addr).await.is_empty());

    let payload = GetAssetMediaRequest {
        digest: digest.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/getassetmedia"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "acceptor persisted peer media before validating the funding (persist-before-validate)"
    );
}
