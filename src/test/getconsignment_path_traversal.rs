use super::*;

const TEST_DIR_BASE: &str = "tmp/getconsignment_path_traversal/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn getconsignment_path_traversal() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None, false).await;
    init(node1_addr, "password1", None).await;
    unlock(node1_addr, "password1").await;

    let sentinel = tempfile::tempdir().unwrap();
    let leak_dir = sentinel.path().join("leak");
    std::fs::create_dir_all(&leak_dir).unwrap();
    let secret: &[u8] = b"SECRET-OUTSIDE-THE-CONSIGNMENT-DIR";
    std::fs::write(leak_dir.join("consignment_out"), secret).unwrap();

    let abs_txid = sentinel.path().to_str().unwrap();
    let payload = GetConsignmentRequest {
        asset_id: s!("leak"),
        txid: abs_txid.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/getconsignment"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    let status = res.status();
    let body = res.text().await.unwrap();
    assert!(
        !body.contains(&hex_str(secret)),
        "/getconsignment leaked a file outside its directory via path traversal (status {status})"
    );
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "path-traversal identifiers must be rejected, got {status}: {body}"
    );
}
