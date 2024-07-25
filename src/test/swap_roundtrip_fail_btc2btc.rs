use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_btc2btc/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
#[should_panic(expected = "cannot swap BTC for BTC")]
async fn swap_roundtrip_fail_btc2btc() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    maker_init(node1_addr, 50000, None, 50000, None, 3600).await;
}
