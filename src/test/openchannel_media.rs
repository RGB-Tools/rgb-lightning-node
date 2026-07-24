use super::*;

use crate::kv_store::SeaOrmKvStore;
use lightning::rgb_utils::RgbKvStoreExt;

const TEST_DIR_BASE: &str = "tmp/openchannel_media/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn openchannel_media() {
    initialize();

    let file_path = "README.md";

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // node1 issues a CFA asset with a media file attached
    let asset = issue_asset_cfa(node1_addr, Some(file_path)).await;
    let digest = asset.media.unwrap().digest;

    // sanity: node2 does not know the media yet
    let payload = GetAssetMediaRequest {
        digest: digest.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node2_addr}/getassetmedia"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);

    // open a colored channel node1 -> node2 (this sends the consignment + media over p2p)
    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset.asset_id),
    )
    .await;

    // node2 didn't know the asset, so it asked for the media (accept_channel known_asset = false)
    assert!(!counterparty_knows_asset(&test_dir_node1, &channel.channel_id).await);

    // the acceptor now has the media
    let media_hex = get_asset_media(node2_addr, &digest).await;
    let media_bytes = hex_str_to_vec(&media_hex).unwrap();
    let mut buf_reader = tokio::io::BufReader::new(tokio::fs::File::open(file_path).await.unwrap());
    let mut file_bytes = Vec::new();
    buf_reader.read_to_end(&mut file_bytes).await.unwrap();
    assert_eq!(media_bytes, file_bytes);

    // node2 now knows the asset, so on a second channel for the same asset it reports known_asset
    // in accept_channel and node1 skips sending the media again
    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset.asset_id),
    )
    .await;
    assert!(counterparty_knows_asset(&test_dir_node1, &channel.channel_id).await);

    // and the media is still there and intact
    let media_hex = get_asset_media(node2_addr, &digest).await;
    assert_eq!(hex_str_to_vec(&media_hex).unwrap(), file_bytes);
}

// read the counterparty_knows_asset flag the node recorded in the channel's RgbInfo when it
// received accept_channel
async fn counterparty_knows_asset(test_dir_node: &str, channel_id: &str) -> bool {
    let conn = crate::utils::connect_db(&crate::utils::get_db_path(Path::new(test_dir_node)))
        .await
        .unwrap();
    let kv_store = SeaOrmKvStore::from_connection(Arc::new(conn));
    kv_store
        .read_rgb_channel_info(channel_id, false)
        .unwrap()
        .counterparty_knows_asset
}
