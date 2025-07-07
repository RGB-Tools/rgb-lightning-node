use super::*;

const TEST_DIR_BASE: &str = "tmp/issue/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn issue() {
    initialize();

    let amt = 5000;
    let file_path = "README.md";

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    // check /createutxos size parameter
    let unspents_1 = list_unspents(node1_addr).await;
    create_utxos(node1_addr, false, Some(1), Some(amt)).await;
    let unspents_2 = list_unspents(node1_addr).await;
    assert_eq!(unspents_1.len(), unspents_2.len() - 1);
    assert!(!unspents_1.iter().any(|u| u.utxo.btc_amount == amt as u64));
    assert!(unspents_2.iter().any(|u| u.utxo.btc_amount == amt as u64));

    // issue assets
    let asset_cfa = issue_asset_cfa(node1_addr, Some(file_path)).await;
    let asset_nia = issue_asset_nia(node1_addr).await;
    let asset_uda = issue_asset_uda(node1_addr, Some(file_path)).await;

    // check /listassets
    let assets = list_assets(node1_addr).await;
    let assets_cfa = assets.cfa.unwrap();
    let assets_nia = assets.nia.unwrap();
    let assets_uda = assets.uda.unwrap();
    assert_eq!(assets_cfa.len(), 1);
    assert_eq!(assets_nia.len(), 1);
    assert_eq!(assets_uda.len(), 1);
    let cfa_asset = assets_cfa.first().unwrap();
    let nia_asset = assets_nia.first().unwrap();
    let uda_asset = assets_uda.first().unwrap();
    assert_eq!(cfa_asset.asset_id, asset_cfa.asset_id);
    assert_eq!(nia_asset.asset_id, asset_nia.asset_id);
    assert_eq!(uda_asset.asset_id, asset_uda.asset_id);

    // check /getassetmedia
    let mut buf_reader = tokio::io::BufReader::new(tokio::fs::File::open(file_path).await.unwrap());
    let mut file_bytes = Vec::new();
    buf_reader.read_to_end(&mut file_bytes).await.unwrap();

    let cfa_digest = &cfa_asset.media.as_ref().unwrap().digest;
    let cfa_media_hex = get_asset_media(node1_addr, cfa_digest).await;
    let cfa_media_bytes = hex_str_to_vec(&cfa_media_hex).unwrap();
    assert_eq!(cfa_media_bytes, file_bytes);

    let uda_digest = &uda_asset
        .token
        .as_ref()
        .unwrap()
        .media
        .as_ref()
        .unwrap()
        .digest;
    let uda_media_hex = get_asset_media(node1_addr, uda_digest).await;
    let uda_media_bytes = hex_str_to_vec(&uda_media_hex).unwrap();
    assert_eq!(uda_media_bytes, file_bytes);

    // check /getassetmedia invalid digest errors
    let payload = GetAssetMediaRequest { digest: s!("a") };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getassetmedia"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid media digest",
        "InvalidMediaDigest",
    )
    .await;

    let payload = GetAssetMediaRequest { digest: s!("") };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getassetmedia"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "IO error: Is a directory (os error 21)",
        "IO",
    )
    .await;
}
