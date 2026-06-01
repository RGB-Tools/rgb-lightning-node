use super::*;

const TEST_DIR_BASE: &str = "tmp/gossip_p2p/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn p2p_mode_reports_no_rgs_timestamp() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node_addr, _password) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    // The default unlock uses P2P gossip; no RGS snapshot is ever fetched.
    let info = node_info(node_addr).await;
    assert!(info.latest_rgs_snapshot_timestamp.is_none());
}
