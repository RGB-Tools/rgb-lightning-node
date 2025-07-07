use super::*;

const TEST_DIR_BASE: &str = "tmp/upload_asset_media/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn success() {
    initialize();

    let file_path = "README.md";

    let test_dir_base = format!("{TEST_DIR_BASE}success/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    // upload asset media
    let digest = post_asset_media(node1_addr, file_path).await;

    // issue asset
    let asset = issue_asset_cfa(node1_addr, Some(file_path)).await;
    assert_eq!(digest, asset.media.unwrap().digest);

    // check uploaded media and asset media are the same
    let assets = list_assets(node1_addr).await;
    let cfa_assets = assets.cfa.unwrap();
    assert_eq!(cfa_assets.len(), 1);
    let cfa_asset = cfa_assets.first().unwrap();
    let cfa_digest = &cfa_asset.media.as_ref().unwrap().digest;
    let cfa_media_hex = get_asset_media(node1_addr, cfa_digest).await;
    let cfa_media_bytes = hex_str_to_vec(&cfa_media_hex).unwrap();
    let mut buf_reader = tokio::io::BufReader::new(tokio::fs::File::open(file_path).await.unwrap());
    let mut file_bytes = Vec::new();
    buf_reader.read_to_end(&mut file_bytes).await.unwrap();
    assert_eq!(cfa_media_bytes, file_bytes);

    // upload asset media smaller than the size limit but bigger than the default body limit
    let file_bytes = vec![4; 2 * 1024 * 1024];
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(file_bytes).headers([].into_iter().collect()),
    );
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/postassetmedia"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn fail() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}fail/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    // upload asset media with no multipart field
    let form = reqwest::multipart::Form::new();
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/postassetmedia"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Media file has not been provided",
        "MediaFileNotProvided",
    )
    .await;

    // upload asset media with empty bytes
    let file_bytes = vec![];
    let form =
        reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(file_bytes));
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/postassetmedia"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Media file is empty",
        "MediaFileEmpty",
    )
    .await;

    // upload asset media bigger than the size limit
    let file_bytes = vec![4; 3 * 1024 * 1024];
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(file_bytes).headers([].into_iter().collect()),
    );
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/postassetmedia"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let api_error_response = res.text().await.unwrap();
    assert_eq!(api_error_response, "length limit exceeded");
}
