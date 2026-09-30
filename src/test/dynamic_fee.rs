use super::*;

const TEST_DIR_BASE: &str = "tmp/dynamic_fee/";

// A funding tx priced at or below 7 sat/vB can only come from the reintroduced hardcode.
const REMOVED_FEE_RATE_SAT_VB: f64 = 7.0;

// Effective feerate of a confirmed tx in sats per vsize, derived from its inputs' prevouts.
fn tx_feerate(txid: &str) -> f64 {
    let raw = bitcoind(&["getrawtransaction", txid, "2"]);
    let tx: serde_json::Value = serde_json::from_str(&raw).expect("valid tx JSON");

    let inputs_sat: u64 = tx["vin"]
        .as_array()
        .expect("vin array")
        .iter()
        .map(|vin| {
            let prev = bitcoind(&["getrawtransaction", vin["txid"].as_str().unwrap(), "2"]);
            let prev_tx: serde_json::Value = serde_json::from_str(&prev).expect("valid prev tx");
            let out = &prev_tx["vout"][vin["vout"].as_u64().unwrap() as usize];
            (out["value"].as_f64().expect("prevout value") * 1e8).round() as u64
        })
        .sum();

    let outputs_sat: u64 = tx_output_sats(txid).into_iter().sum();
    let vsize = tx["vsize"].as_f64().expect("tx vsize");

    (inputs_sat.saturating_sub(outputs_sat)) as f64 / vsize
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn dynamic_fee() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;

    // FundingGenerationReady previously hardcoded FEE_RATE; it now reads the FeeEstimator.
    // The tx confirms within a few blocks, so its prevouts stay reachable via txindex.
    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        None,
        Some(100_000),
        None,
        None,
        None,
    )
    .await;
    let funding_txid = channel
        .funding_txid
        .expect("funded channel has a funding txid");
    let measured = tx_feerate(&funding_txid);
    println!("funding feerate: {measured} sat/vB");

    // The measured rate clears the priced fee_rate by the model's headroom, so a value at or
    // below 7 sat/vB means the constant is pricing the funding path again.
    assert!(
        measured > REMOVED_FEE_RATE_SAT_VB,
        "funding feerate {measured} sat/vB is at or below the removed hardcoded {REMOVED_FEE_RATE_SAT_VB} sat/vB"
    );

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);
}
