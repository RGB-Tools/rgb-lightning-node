use super::*;
use crate::routes::HTLC_MIN_MSAT;
use lightning::chain::chaininterface::ConfirmationTarget;

const TEST_DIR_BASE: &str = "tmp/anchor_cpfp_force_close/";
// UrgentOnChainSweep, in sat per 1000 weight units: 1.2 sat/vB, just above the commitment's
// ~1 sat/vB feerate so LDK requires an anchor child, but low enough that the 330 sat anchor
// output plus the commitment's own fee can satisfy the target without an external sponsor
// input. The regtest wallet only holds P2TR UTXOs, which the bump PSBT signing path cannot
// sign into a valid package here, so any sponsor input would make bitcoind reject the package.
const TARGET_FEE_RATE_SAT_PER_KW: u32 = 300;
const TARGET_FEE_RATE_SAT_PER_VB: f64 = TARGET_FEE_RATE_SAT_PER_KW as f64 / 250.0;
const CHANNEL_CAPACITY_SAT: u64 = 100_000;

struct TargetFeeOverride;

impl Drop for TargetFeeOverride {
    fn drop(&mut self) {
        fee_mock::set_target_fee_for_tests(ConfirmationTarget::UrgentOnChainSweep, None);
    }
}

fn mempool_txids() -> Vec<String> {
    serde_json::from_str(&bitcoind(&["getrawmempool"])).expect("invalid getrawmempool response")
}

fn mempool_entry(txid: &str) -> serde_json::Value {
    serde_json::from_str(&bitcoind(&["getmempoolentry", txid]))
        .unwrap_or_else(|e| panic!("invalid getmempoolentry {txid}: {e}"))
}

fn mempool_tx(txid: &str) -> serde_json::Value {
    serde_json::from_str(&bitcoind(&["getrawtransaction", txid, "true"]))
        .unwrap_or_else(|e| panic!("invalid getrawtransaction {txid}: {e}"))
}

fn fee_sat(entry: &serde_json::Value) -> u64 {
    (entry["fees"]["base"]
        .as_f64()
        .expect("mempool entry has no base fee")
        * 100_000_000.0)
        .round() as u64
}

async fn wait_for_package(
    commitment_txid: &str,
    child_txid: &str,
) -> (serde_json::Value, serde_json::Value) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let mempool = mempool_txids();
        if mempool.iter().any(|txid| txid == commitment_txid)
            && mempool.iter().any(|txid| txid == child_txid)
        {
            return (mempool_tx(commitment_txid), mempool_tx(child_txid));
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("package {commitment_txid}/{child_txid} not in mempool: {mempool:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn anchor_cpfp_force_close() {
    initialize();
    let _fee_override = TargetFeeOverride;
    fee_mock::set_target_fee_for_tests(
        ConfirmationTarget::UrgentOnChainSweep,
        Some(TARGET_FEE_RATE_SAT_PER_KW),
    );

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CHANNEL_CAPACITY_SAT),
        Some(50_000_000),
        Some(600),
        Some(&asset_id),
    )
    .await;

    // A held incoming payment keeps an HTLC on node2's commitment, which is what makes LDK
    // treat the close as urgent and require an anchor child.
    HELD_PAYMENT_CLAIMABLE_COUNT.store(0, Ordering::SeqCst);
    let _hold_guard = NodeOverrideGuard::set(&HOLD_PAYMENT_CLAIMABLE_ON_NODE, &node2_pubkey);
    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        Some(HTLC_MIN_MSAT),
        Some(&asset_id),
        Some(10),
        900,
    )
    .await;
    send_payment_raw(node1_addr, invoice).await;
    let t_0 = OffsetDateTime::now_utc();
    while HELD_PAYMENT_CLAIMABLE_COUNT.load(Ordering::SeqCst) == 0 {
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 40.0 {
            panic!("node2 did not receive the payment to hold");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Force close without mining, so the package stays observable in the mempool.
    close_channel(node2_addr, &channel.channel_id, &node1_pubkey, true).await;

    // The status is written before the handler runs, so an absent record means the event has not
    // been processed yet. Wait for the handler's outcome instead of sleeping.
    let t_0 = OffsetDateTime::now_utc();
    let record = loop {
        if let Some(record) = bump_force_close_fee(node2_addr, &channel.channel_id).await {
            if record.status != "pending" {
                break record;
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("no bump outcome for channel {}", channel.channel_id);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    assert_eq!(
        record.status, "broadcast",
        "unexpected bump status for channel {}: {record:?}",
        channel.channel_id
    );
    assert_eq!(record.channel_id, channel.channel_id);
    assert_eq!(record.claim_id.len(), 64);
    assert_eq!(record.target_fee_rate_sat_vb, TARGET_FEE_RATE_SAT_PER_VB);
    assert_eq!(record.message, None);
    let commitment_txid = record.commitment_txid;
    let child_txid = record
        .child_txid
        .expect("broadcast status has no child txid");
    assert_ne!(child_txid, commitment_txid);

    let (commitment, child) = wait_for_package(&commitment_txid, &child_txid).await;

    // The package must contain exactly one child spending the commitment, and that input must be
    // the 330 sat anchor output.
    let child_inputs = child["vin"].as_array().expect("child has no inputs");
    let anchor_inputs = child_inputs
        .iter()
        .filter(|input| input["txid"] == serde_json::json!(commitment_txid))
        .collect::<Vec<_>>();
    assert_eq!(
        anchor_inputs.len(),
        1,
        "child must spend the commitment exactly once: {child}"
    );
    let anchor_vout = anchor_inputs[0]["vout"]
        .as_u64()
        .expect("anchor input has no vout") as usize;
    assert_eq!(
        commitment["vout"][anchor_vout]["value"]
            .as_f64()
            .expect("anchor output has no value"),
        0.000_003_30,
        "child did not spend an anchor output"
    );

    // The commitment alone must be below target, otherwise the child proves nothing.
    let commitment_outputs = commitment["vout"]
        .as_array()
        .expect("commitment has no outputs")
        .iter()
        .map(|output| {
            (output["value"].as_f64().expect("output has no value") * 100_000_000.0).round() as u64
        })
        .sum::<u64>();
    let commitment_fee_sat = CHANNEL_CAPACITY_SAT - commitment_outputs;
    let commitment_entry = mempool_entry(&commitment_txid);
    assert_eq!(
        commitment_fee_sat,
        fee_sat(&commitment_entry),
        "commitment fee does not match its inputs minus outputs"
    );
    let commitment_vsize = commitment_entry["vsize"]
        .as_u64()
        .expect("commitment entry has no vsize");
    let commitment_feerate = commitment_fee_sat as f64 / commitment_vsize as f64;
    assert!(
        commitment_feerate < TARGET_FEE_RATE_SAT_PER_VB,
        "commitment already pays {commitment_feerate} sat/vB, target {TARGET_FEE_RATE_SAT_PER_VB}"
    );

    // Aggregated package fee, computed from both mempool entries, must meet the target. Allow 1%
    // for Core's vsize rounding.
    let child_entry = mempool_entry(&child_txid);
    let child_vsize = child_entry["vsize"].as_u64().expect("child has no vsize");
    let package_feerate = (commitment_fee_sat + fee_sat(&child_entry)) as f64
        / (commitment_vsize + child_vsize) as f64;
    assert!(
        package_feerate >= TARGET_FEE_RATE_SAT_PER_VB * 0.99,
        "package pays {package_feerate} sat/vB, target {TARGET_FEE_RATE_SAT_PER_VB}"
    );

    // Mine one block: the package must confirm together and leave the mempool.
    mine_n_blocks(false, 1);
    let block_hash = bitcoind(&["getbestblockhash"]);
    let block: serde_json::Value =
        serde_json::from_str(&bitcoind(&["getblock", &block_hash, "1"])).expect("invalid getblock");
    let block_txids = block["tx"]
        .as_array()
        .expect("block has no transactions")
        .iter()
        .filter_map(|txid| txid.as_str())
        .collect::<Vec<_>>();
    assert!(block_txids.contains(&commitment_txid.as_str()));
    assert!(block_txids.contains(&child_txid.as_str()));
    let mempool = mempool_txids();
    assert!(!mempool.contains(&commitment_txid));
    assert!(!mempool.contains(&child_txid));

    // Wait for the node's confirmation poll to flip the record to `confirmed`.
    let t_0 = OffsetDateTime::now_utc();
    let mut last = None;
    let confirmed = loop {
        if let Some(record) = bump_force_close_fee(node2_addr, &channel.channel_id).await {
            if record.status == "confirmed" {
                break record;
            }
            last = Some(record);
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!(
                "bump record for channel {} did not reach confirmed: {last:?}",
                channel.channel_id
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    assert_eq!(confirmed.commitment_txid, commitment_txid);
    assert_eq!(confirmed.child_txid.as_deref(), Some(child_txid.as_str()));
    assert_eq!(confirmed.message, None);
}
