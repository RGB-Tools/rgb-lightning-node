use super::*;

const TEST_DIR_BASE: &str = "tmp/getassetmedia_path_traversal/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn getassetmedia_path_traversal() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None, false).await;
    init(node1_addr, "password1", None).await;
    unlock(node1_addr, "password1").await;

    let leak_dir = std::env::temp_dir().join("rgb_getassetmedia_path_traversal");
    std::fs::create_dir_all(&leak_dir).unwrap();
    let secret: &[u8] = b"SECRET-OUTSIDE-THE-MEDIA-DIR";
    let secret_file = leak_dir.join("secret");
    std::fs::write(&secret_file, secret).unwrap();

    let digest = secret_file.to_str().unwrap();
    assert_eq!(
        digest,
        digest.to_lowercase(),
        "test setup: planted path must be lowercase to survive the handler's to_lowercase()"
    );
    let payload = GetAssetMediaRequest {
        digest: digest.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getassetmedia"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    let status = res.status();
    let body = res.text().await.unwrap();
    assert!(
        !body.contains(&hex_str(secret)),
        "/getassetmedia leaked a file outside the media dir via path traversal (status {status})"
    );
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "a non-hex media digest must be rejected, got {status}: {body}"
    );
}
