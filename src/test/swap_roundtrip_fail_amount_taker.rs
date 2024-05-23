use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_amount_taker/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
#[should_panic(expected = "Not enough assets")]
async fn swap_fail_amount_taker() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;

    let asset_id = issue_asset_nia(node2_addr).await.asset_id;

    let maker_init_response =
        maker_init(node1_addr, 1000, Some(&asset_id), 360000, None, 5000).await;
    taker(node2_addr, maker_init_response.swapstring.clone()).await;
}
