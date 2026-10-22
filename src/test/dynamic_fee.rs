use super::*;
use crate::ldk_chain_backend::{MAX_FEERATE, MIN_FEERATE};

use std::collections::HashSet;

const TEST_DIR_BASE: &str = "tmp/dynamic_fee/";

// 1 sat/vB == 250 sat/kWu; both units describe the same rate.
const SAT_PER_KWU_PER_SAT_VB: f64 = 250.0;

// A funding tx priced at or below 7 sat/vB can only come from the reintroduced hardcode.
const REMOVED_FEE_RATE_SAT_VB: f64 = 7.0;

// rgb-lib overpays slightly: its size model overestimates witness sizes, so measured rates
// deviate only by small percentages unless rates are resolved wrongly.
const FEERATE_REL_TOLERANCE: f64 = 0.015;
const FEERATE_MIN_TOLERANCE_SAT_VB: f64 = 0.10;

// Asserts measured sits in [expected - 0.5*tol, expected + tol]; tol = 1.5% or the 0.1 floor.
fn assert_feerate(measured: f64, expected: f64, context: &str) {
    let tol = (expected * FEERATE_REL_TOLERANCE).max(FEERATE_MIN_TOLERANCE_SAT_VB);
    let lo = expected - 0.5 * tol;
    let hi = expected + tol;
    let dev = (measured - expected) / expected * 100.0;
    println!(
        "{context}: measured {measured:.3} sat/vB vs expected {expected:.3} (dev {dev:+.3}%, band {lo:.3}..{hi:.3})"
    );
    assert!(
        lo <= measured && measured <= hi,
        "{context}: feerate {measured:.3} sat/vB must be within [{lo:.3}, {hi:.3}] (expected {expected:.3})"
    );
}

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

// Txids currently in the regtest mempool.
fn mempool_txids() -> HashSet<String> {
    let raw = bitcoind(&["getrawmempool"]);
    serde_json::from_str::<Vec<String>>(&raw)
        .expect("valid mempool txid array")
        .into_iter()
        .collect()
}

// Effective feerate of `txid` in sats per vsize; `fees.base` is a BTC float.
fn mempool_feerate(txid: &str) -> f64 {
    let raw = bitcoind(&["getmempoolentry", txid]);
    let entry: serde_json::Value = serde_json::from_str(&raw).expect("valid mempool entry");
    let sats = (entry["fees"]["base"].as_f64().expect("fees.base") * 1e8).round() as u64;
    sats as f64 / entry["vsize"].as_u64().expect("vsize") as f64
}

// Waits for exactly one new tx; broadcasting is async so it appears after the API returns.
async fn wait_for_new_mempool_tx(before: &HashSet<String>) -> String {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let now = mempool_txids();
        let new: Vec<&String> = now.difference(before).collect();
        match new.len() {
            1 => return new[0].clone(),
            n if n > 1 => panic!("expected one new mempool tx, got {n}"),
            _ => {}
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("no new tx appeared in the mempool within 90 seconds");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// createutxos with an explicit fee_rate, or None to exercise the estimator fallback.
async fn create_utxos_with_fee(node_address: SocketAddr, fee_rate: Option<u64>) {
    let payload = CreateUtxosRequest {
        up_to: false,
        num: Some(1),
        size: Some(32_000),
        fee_rate,
        skip_sync: false,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/createutxos"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
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

    // Sanity band: the poll loops never store values outside [MIN_FEERATE, MAX_FEERATE].
    let min_sat_vb = MIN_FEERATE as f64 / SAT_PER_KWU_PER_SAT_VB;
    let max_sat_vb = MAX_FEERATE as f64 / SAT_PER_KWU_PER_SAT_VB;
    assert!(
        min_sat_vb <= measured && measured <= max_sat_vb,
        "funding feerate {measured} sat/vB must stay within the sane band [{min_sat_vb}, {max_sat_vb}] sat/vB"
    );

    // /estimatefee serves its background tier from the same cache that priced the funding tx:
    // the measured on-chain rate must agree with it.
    let estimated = estimate_fee(node1_addr, 1).await;
    let expected = estimated.fee_rates.background as f64 / SAT_PER_KWU_PER_SAT_VB;
    assert_feerate(measured, expected, "funding vs /estimatefee background");

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_2.len(), 1);

    // ---- fee_rate is now optional; absent/0 falls back to the estimator's output-spending tier. ----

    fund_and_create_utxos(node1_addr, None).await;

    stop_mining();
    let before = mempool_txids();
    create_utxos_with_fee(node1_addr, Some(120)).await;
    let txid = wait_for_new_mempool_tx(&before).await;
    assert_feerate(mempool_feerate(&txid), 120.0, "create_utxos explicit fee");

    let expected_fallback =
        estimate_fee(node1_addr, 1).await.fee_rates.background as f64 / SAT_PER_KWU_PER_SAT_VB;
    let before = mempool_txids();
    create_utxos_with_fee(node1_addr, None).await;
    let txid = wait_for_new_mempool_tx(&before).await;
    assert_feerate(
        mempool_feerate(&txid),
        expected_fallback,
        "create_utxos omitted-fee fallback",
    );
    resume_mining();
}
