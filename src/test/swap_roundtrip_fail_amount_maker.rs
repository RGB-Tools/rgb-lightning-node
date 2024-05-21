use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_amount_maker/";
const NODE1_PEER_PORT: u16 = 9821;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
#[should_panic(expected = "Not enough assets")]
async fn swap_fail_amount_maker() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    maker_init(node1_addr, 3600000, None, 1000, Some(&asset_id), 5000).await;
}
