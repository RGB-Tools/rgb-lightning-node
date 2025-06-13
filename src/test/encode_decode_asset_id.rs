use super::*;

const TEST_DIR_BASE: &str = "tmp/asset_id/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn asset_id() {
    initialize();

    let amt = 5000;
    let file_path = "README.md";

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    // check /createutxos size parameter
    let unspents_1 = list_unspents(node1_addr).await;
    create_utxos(node1_addr, false, Some(1), Some(amt)).await;
    let unspents_2 = list_unspents(node1_addr).await;
    assert_eq!(unspents_1.len(), unspents_2.len() - 1);
    assert!(!unspents_1.iter().any(|u| u.utxo.btc_amount == amt as u64));
    assert!(unspents_2.iter().any(|u| u.utxo.btc_amount == amt as u64));

    // issue assets
    let asset_cfa = issue_asset_cfa(node1_addr, Some(file_path)).await;
    let asset_nia = issue_asset_nia(node1_addr).await;
    let asset_uda = issue_asset_uda(node1_addr, Some(file_path)).await;

    // check
    let cfa_decoded_result = decode_asset_id(node1_addr, asset_cfa.asset_id.clone()).await;
    let nia_decoded_result = decode_asset_id(node1_addr, asset_nia.asset_id.clone()).await;
    let uda_decoded_result = decode_asset_id(node1_addr, asset_uda.asset_id.clone()).await;

    let cfa_encoded_result = encode_asset_id(node1_addr, cfa_decoded_result.hex_format.clone()).await;
    let nia_encoded_result = encode_asset_id(node1_addr, nia_decoded_result.hex_format.clone()).await;
    let uda_encoded_result = encode_asset_id(node1_addr, uda_decoded_result.hex_format.clone()).await;

    assert_eq!(cfa_encoded_result.asset_id, asset_cfa.asset_id);
    assert_eq!(nia_encoded_result.asset_id, asset_nia.asset_id);
    assert_eq!(uda_encoded_result.asset_id, asset_uda.asset_id);
}
