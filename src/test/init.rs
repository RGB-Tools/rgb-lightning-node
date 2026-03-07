use super::*;

const TEST_DIR_BASE: &str = "tmp/init/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn init_with_existing_mnemonic() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let _ = std::fs::remove_dir_all(&test_dir_node1);
    let _ = std::fs::remove_dir_all(&test_dir_node2);
    let _ = std::fs::remove_dir_all(&test_dir_node3);

    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None).await;
    let node2_addr = start_daemon(&test_dir_node2, NODE2_PEER_PORT, None).await;

    let mnemonic = s!(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );

    let payload = InitRequest {
        password: s!("password123"),
        mnemonic: Some(mnemonic.clone()),
    };
    let init_1 = reqwest::Client::new()
        .post(format!("http://{node1_addr}/init"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let init_1 = _check_response_is_ok(init_1).await;
    let init_1 = init_1.json::<InitResponse>().await.unwrap();
    assert_eq!(init_1.mnemonic, mnemonic);

    let payload = InitRequest {
        password: s!("password456"),
        mnemonic: Some(mnemonic.clone()),
    };
    let init_2 = reqwest::Client::new()
        .post(format!("http://{node2_addr}/init"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let init_2 = _check_response_is_ok(init_2).await;
    let init_2 = init_2.json::<InitResponse>().await.unwrap();
    assert_eq!(init_2.mnemonic, mnemonic);

    unlock(node1_addr, "password123").await;
    unlock(node2_addr, "password456").await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    assert_eq!(node1_pubkey, node2_pubkey);

    let node3_addr = start_daemon(&test_dir_node3, NODE3_PEER_PORT, None).await;
    let payload = InitRequest {
        password: s!("password789"),
        mnemonic: Some(s!("this is not a valid mnemonic")),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node3_addr}/init"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid mnemonic",
        "InvalidMnemonic",
    )
    .await;
}
