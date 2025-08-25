use super::*;

const TEST_DIR_BASE: &str = "tmp/fail_transfers/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn success() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}success/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    let batch_transfer_idx = rgb_invoice(node1_addr, None, false)
        .await
        .batch_transfer_idx;

    let transfers_changed = fail_transfers(node1_addr, Some(batch_transfer_idx)).await;
    assert!(transfers_changed);
}
