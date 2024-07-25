use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_invalid_asset_to/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
#[should_panic(expected = "Invalid asset ID")]
async fn swap_fail_invalid_asset_to() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    maker_init(
        node1_addr,
        3600000,
        None,
        1000,
        Some("rgb:inexistent"),
        5000,
    )
    .await;
}
