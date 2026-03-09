use super::*;

const TEST_DIR_BASE: &str = "tmp/init/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn init_with_existing_mnemonic() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None, false).await;
    let node2_addr = start_daemon(&test_dir_node2, NODE2_PEER_PORT, None, false).await;

    let mnemonic = s!(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );

    // fail: invalid mnemonic
    let res = init_res(
        node1_addr,
        "password789",
        Some(s!("this is not a valid mnemonic")),
    )
    .await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid mnemonic",
        "InvalidMnemonic",
    )
    .await;

    // success
    let init_1 = init(node1_addr, "password123", Some(mnemonic.clone())).await;
    assert_eq!(init_1.mnemonic, mnemonic);
    let init_2 = init(node2_addr, "password456", Some(mnemonic.clone())).await;
    assert_eq!(init_2.mnemonic, mnemonic);

    unlock(node1_addr, "password123").await;
    unlock(node2_addr, "password456").await;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    assert_eq!(node1_pubkey, node2_pubkey);
}
