use super::*;

const TEST_DIR_BASE: &str = "tmp/issue/";
const NODE1_PEER_PORT: u16 = 9821;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn issue() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;

    let asset_cfa = issue_asset_cfa(node1_addr).await;
    let asset_nia = issue_asset_nia(node1_addr).await;
    let asset_uda = issue_asset_uda(node1_addr).await;

    let assets = list_assets(node1_addr).await;
    let assets_cfa = assets.cfa.unwrap();
    let assets_nia = assets.nia.unwrap();
    let assets_uda = assets.uda.unwrap();
    assert_eq!(assets_cfa.len(), 1);
    assert_eq!(assets_nia.len(), 1);
    assert_eq!(assets_uda.len(), 1);
    let cfa_asset = assets_cfa.first().unwrap();
    let nia_asset = assets_nia.first().unwrap();
    let uda_asset = assets_uda.first().unwrap();
    assert_eq!(cfa_asset.asset_id, asset_cfa.asset_id);
    assert_eq!(nia_asset.asset_id, asset_nia.asset_id);
    assert_eq!(uda_asset.asset_id, asset_uda.asset_id);
}
