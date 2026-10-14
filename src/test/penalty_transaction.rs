use super::*;

const TEST_DIR_BASE: &str = "tmp/penalty_transaction/";
const CHANNEL_CAPACITY_SAT: u64 = 100_000;
const RGB_ON_NODE_A: u64 = 600;
// B RGB units held at the backed-up state: 0 (A's to_local carries the full balance) and
// 100 (the revoked commitment carries RGB on both sides, so the justice sweep only
// colors A's to_local and B separately claims its to_remote).
const B_HELD_RGB_ITERATIONS: [u64; 2] = [0, 100];

// Recursive copy of an entire directory tree.
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

// Waits for `needle` to appear in the node's LDK log.
async fn wait_for_ldk_log(node_test_dir: &str, needle: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if ldk_log_lines(node_test_dir)
            .iter()
            .any(|l| l.contains(needle))
        {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("log marker {needle:?} not found in node logs");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// Returns the txids currently in the regtest mempool.
fn mempool_txids() -> Vec<String> {
    let raw = bitcoind(&["getrawmempool"]);
    serde_json::from_str::<Vec<String>>(&raw).expect("valid mempool txid array")
}

// Returns the JSON object of `txid` as returned by getrawtransaction.
fn tx_json(txid: &str) -> serde_json::Value {
    let raw = bitcoind(&["getrawtransaction", txid, "true"]);
    serde_json::from_str(&raw).expect("valid tx JSON")
}

// Returns true when `txid` spends the output `(prev_txid, prev_vout)`.
fn tx_spends_output(txid: &str, prev_txid: &str, prev_vout: u64) -> bool {
    tx_json(txid)["vin"]
        .as_array()
        .expect("vin array")
        .iter()
        .any(|vin| {
            vin["txid"].as_str() == Some(prev_txid) && vin["vout"].as_u64() == Some(prev_vout)
        })
}

// Returns true when `txid` spends any output of `prev_txid`.
fn tx_spends_output_any(txid: &str, prev_txid: &str) -> bool {
    tx_json(txid)["vin"]
        .as_array()
        .expect("vin array")
        .iter()
        .any(|vin| vin["txid"].as_str() == Some(prev_txid))
}

// Returns true when a tx spending `(prev_txid, prev_vout)` is in the mempool.
fn mempool_spender_exists(prev_txid: &str, prev_vout: u64) -> bool {
    mempool_txids()
        .into_iter()
        .any(|t| tx_spends_output(&t, prev_txid, prev_vout))
}

// Returns true when a tx spending any output of `prev_txid` is in the mempool.
fn mempool_funding_spender_exists(prev_txid: &str) -> bool {
    mempool_txids()
        .into_iter()
        .any(|t| tx_spends_output_any(&t, prev_txid))
}

// Polls the mempool until some tx spending `(prev_txid, prev_vout)` appears,
// i.e. the counterparty's justice or balance sweep has been broadcast.
async fn wait_for_mempool_spender(prev_txid: &str, prev_vout: u64) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if mempool_spender_exists(prev_txid, prev_vout) {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("no tx spending {prev_txid}:{prev_vout} in the mempool");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// Polls the mempool until some tx spending any output of `prev_txid` appears,
// i.e. the force-closed commitment transaction that revokes the prior state.
async fn wait_for_mempool_funding_spender(prev_txid: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if mempool_funding_spender_exists(prev_txid) {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("no tx spending any output of {prev_txid} in the mempool");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// Returns the largest output of `tx` (the to_local side's balance); the
// counterparty's to_remote output is much smaller, so the max is unambiguous.
fn to_local_output(tx: &serde_json::Value) -> (usize, u64) {
    tx["vout"]
        .as_array()
        .expect("vout array")
        .iter()
        .enumerate()
        .map(|(i, v)| {
            (
                i,
                Amount::from_btc(v["value"].as_f64().expect("output value"))
                    .expect("valid amount")
                    .to_sat(),
            )
        })
        .max_by_key(|(_, sat)| *sat)
        .map(|(i, sat)| {
            assert!(
                sat > 0,
                "revoked commitment has a non-empty to_local output"
            );
            (i, sat)
        })
        .expect("revoked commitment has a to_local output")
}

// Returns the (index, value) of B's to_remote balance output on the broadcast
// commitment. All commitment outputs are witness_v0_scripthash, so the output
// is identified by value: it is the only one above the anchor amount (330 sats)
// after excluding the to_local output (the others are the two anchor outputs and
// the zero-value RGB OP_RETURN).
fn to_remote_output(tx: &serde_json::Value, to_local_index: usize) -> (usize, u64) {
    let candidates: Vec<(usize, u64)> = tx["vout"]
        .as_array()
        .expect("vout array")
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != to_local_index)
        .map(|(i, v)| {
            (
                i,
                Amount::from_btc(v["value"].as_f64().expect("output value"))
                    .expect("valid amount")
                    .to_sat(),
            )
        })
        .filter(|(_, sat)| *sat > 330)
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "expected exactly one to_remote output, got {}: {candidates:?}",
        candidates.len()
    );
    candidates[0]
}

// Waits until the node's spendable BTC balance is exactly `expected_sat`.
async fn wait_for_btc_balance_exact(node_address: SocketAddr, expected_sat: u64) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let bal = btc_balance(node_address).await.vanilla.spendable;
        if bal == expected_sat {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("BTC balance ({bal}) did not reach expected ({expected_sat})");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// Waits until the node's spendable RGB balance for `asset_id` is `expected_sat`.
async fn wait_for_asset_balance_exact(node_address: SocketAddr, asset_id: &str, expected_sat: u64) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let bal = asset_balance_spendable(node_address, asset_id).await;
        if bal == expected_sat {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("asset balance ({bal}) did not reach expected ({expected_sat})");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// Full penalty scenario against one B-held-RGB fixture. `b_held_rgb` is B's balance
// at the state A is cheated back to: with 0 the revoked commitment colors only A's
// to_local; with 100 it also colors B's to_remote, which B must claim separately.
async fn run_penalty_scenario(iter_dir_base: &str, b_held_rgb: u64) {
    let test_dir_node1 = format!("{iter_dir_base}node1");
    let test_dir_node2 = format!("{iter_dir_base}node2");
    let backup_dir = format!("{iter_dir_base}node1_backup");

    // Start and fund both nodes.
    let (mut node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (mut node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // Record B's spendable balance before the channel.
    let node2_btc_before = btc_balance(node2_addr).await.vanilla.spendable;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;

    // State 0: open a channel with 600 RGB units on A's side.
    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CHANNEL_CAPACITY_SAT),
        None,
        Some(RGB_ON_NODE_A),
        Some(&asset_id),
    )
    .await;

    // State 1: when B must already hold RGB before the cheat, settle a payment first
    // so the state A is cheated back to carries RGB on both the to_local and to_remote.
    if b_held_rgb > 0 {
        keysend_with_ln_balance(
            node1_addr,
            node2_addr,
            &node2_pubkey,
            Some(6_000_000),
            Some(&asset_id),
            Some(b_held_rgb),
            Some(RGB_ON_NODE_A),
            Some(0),
        )
        .await;
    }

    // Snapshot A's State 1 balance (A's wallet is untouched by the channel);
    // back up its directory as the "honest" state to rewind the cheat from.
    let node1_btc_after_open = btc_balance(node1_addr).await.vanilla.spendable;
    shutdown(&[node1_addr]).await;
    if Path::new(&backup_dir).exists() {
        std::fs::remove_dir_all(&backup_dir).unwrap();
    }
    copy_dir_all(&test_dir_node1, &backup_dir).unwrap();

    // Restart A from its State 1 state.
    (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;

    // State 2: a payment revokes State 1 on both sides, leaving 100 RGB to B.
    keysend_with_ln_balance(
        node1_addr,
        node2_addr,
        &node2_pubkey,
        Some(6_000_000),
        Some(&asset_id),
        Some(100),
        Some(RGB_ON_NODE_A - b_held_rgb),
        Some(b_held_rgb),
    )
    .await;

    // Stop both nodes, then rewind A to its State 1 backup (the cheat).
    shutdown(&[node1_addr, node2_addr]).await;
    std::fs::remove_dir_all(&test_dir_node1).unwrap();
    copy_dir_all(&backup_dir, &test_dir_node1).unwrap();

    // Restart A with the stale State 1 state.
    (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;

    // Force-close from A, which broadcasts the revoked State 1 commitment.
    let close = CloseChannelRequest {
        channel_id: channel.channel_id.clone(),
        peer_pubkey: node2_pubkey.clone(),
        force: true,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/closechannel"))
        .json(&close)
        .send()
        .await
        .unwrap();
    check_response_is_ok(res).await;

    // Wait for the revoked commitment to hit the mempool (the close is async),
    // then locate the outputs B must sweep: A's to_local (the justice target) and
    // B's own to_remote when it carried RGB at the revoked state.
    let funding_txid = channel
        .funding_txid
        .as_ref()
        .expect("funded channel has a funding txid");
    wait_for_mempool_funding_spender(funding_txid).await;
    let revoked_txid = mempool_txids()
        .into_iter()
        .find(|t| tx_spends_output_any(t, funding_txid))
        .expect("revoked commitment tx spending the funding output");
    let revoked = tx_json(&revoked_txid);
    let (to_local_index, to_local_value) = to_local_output(&revoked);
    let (to_remote_index, to_remote_value) = if b_held_rgb > 0 {
        to_remote_output(&revoked, to_local_index)
    } else {
        (0, 0)
    };
    mine(false);

    // Restart B so it syncs and detects the breach.
    shutdown(&[node1_addr]).await;
    (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    wait_for_ldk_log(
        &test_dir_node2,
        "Got broadcast of revoked counterparty commitment transaction",
    )
    .await;

    // Wait for B's justice tx, mine it, then confirm it to ANTI_REORG_DELAY depth
    // so the OutputSweeper emits the SpendableOutputs consolidating sweeps.
    wait_for_mempool_spender(&revoked_txid, to_local_index as u64).await;
    let justice_txid = mempool_txids()
        .into_iter()
        .find(|t| tx_spends_output(t, &revoked_txid, to_local_index as u64))
        .expect("justice tx spending the revoked to_local output");
    mine(false);
    mine_n_blocks(true, 10);

    // Wait for and mine the OutputSweeper sweeps: at minimum the one spending the
    // justice output; when B held RGB on its to_remote, also B's claim of that output.
    wait_for_mempool_funding_spender(&justice_txid).await;
    let sweep_txid = mempool_txids()
        .into_iter()
        .find(|t| tx_spends_output_any(t, &justice_txid))
        .expect("sweep tx spending the justice output");
    let to_remote_claim_txid = if b_held_rgb > 0 {
        wait_for_mempool_spender(&revoked_txid, to_remote_index as u64).await;
        Some(
            mempool_txids()
                .into_iter()
                .find(|t| tx_spends_output(t, &revoked_txid, to_remote_index as u64))
                .expect("to_remote claim tx spending the revoked to_remote output"),
        )
    } else {
        None
    };
    mine(false);

    // Confirm and settle the sweeps: the sweeper self-provided the swept RGB to B's
    // own wallet, so B must refresh to sync the confirmed sweeps and accept the
    // self-provided consignments before the balance is spendable.
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;

    // Assert justice tx structure: one input (the revoked to_local), two outputs
    // (vout 0 = the BTC destination, vout 1 = the RGB OP_RETURN).
    let justice_tx = tx_json(&justice_txid);
    let justice_inputs = justice_tx["vin"].as_array().expect("justice vin");
    assert_eq!(justice_inputs.len(), 1, "justice tx has one input");
    assert_eq!(
        justice_inputs[0]["txid"].as_str(),
        Some(revoked_txid.as_str()),
        "justice input spends the revoked commitment"
    );
    assert_eq!(
        justice_inputs[0]["vout"].as_u64(),
        Some(to_local_index as u64),
        "justice input spends the to_local outpoint"
    );
    let justice_outputs = justice_tx["vout"].as_array().expect("justice vout");
    assert_eq!(justice_outputs.len(), 2, "justice tx has two outputs");
    assert_eq!(
        justice_outputs[1]["scriptPubKey"]["type"].as_str(),
        Some("nulldata"),
        "justice second output is the RGB OP_RETURN"
    );
    assert_eq!(
        justice_outputs[1]["value"].as_f64(),
        Some(0.0),
        "justice RGB OP_RETURN output has zero value"
    );

    // Assert the sweep structure: in the single-claim iteration (B held no RGB at
    // the revoked state) the sweeper colors exactly the one justice output and
    // emits one input, three outputs (OP_RETURN, P2WPKH destination, Taproot RGB
    // receive output at dust). When B also claims its to_remote, the sweeps may
    // consolidate into one tx, so only the BTC totals are asserted below.
    if b_held_rgb == 0 {
        let sweep_tx = tx_json(&sweep_txid);
        let sweep_inputs = sweep_tx["vin"].as_array().expect("sweep vin");
        assert_eq!(sweep_inputs.len(), 1, "sweep tx has one input");
        assert_eq!(
            sweep_inputs[0]["txid"].as_str(),
            Some(justice_txid.as_str()),
            "sweep input spends the justice output"
        );
        assert_eq!(
            sweep_inputs[0]["vout"].as_u64(),
            Some(0),
            "sweep input spends justice:0"
        );
        let sweep_outputs = sweep_tx["vout"].as_array().expect("sweep vout");
        assert_eq!(sweep_outputs.len(), 3, "sweep tx has three outputs");
        assert_eq!(
            sweep_outputs[0]["scriptPubKey"]["type"].as_str(),
            Some("nulldata"),
            "sweep first output is the RGB OP_RETURN"
        );
        assert_eq!(
            sweep_outputs[0]["value"].as_f64(),
            Some(0.0),
            "sweep RGB OP_RETURN output has zero value"
        );
    }

    // The to_remote claim may consolidate with the justice sweep (same digest) or
    // broadcast separately; either way B must receive the sats of both claims.
    let sweep_out = to_local_output(&tx_json(&sweep_txid)).1;
    let to_remote_out = match to_remote_claim_txid.as_deref() {
        Some(claim) if claim != sweep_txid => to_local_output(&tx_json(claim)).1,
        _ => 0,
    };
    let expected_node2_btc = node2_btc_before + sweep_out + to_remote_out;
    // the fee estimator's feerate varies with chain state; the bound only guards
    // against gross overpaying
    assert!(
        to_local_value + to_remote_value - sweep_out - to_remote_out < 10_000,
        "total fees ({}) must be under 10 000 sats",
        to_local_value + to_remote_value - sweep_out - to_remote_out
    );
    wait_for_btc_balance_exact(node2_addr, expected_node2_btc).await;

    // B ends up with the full 600: when B held RGB at the revoked state that is
    // the spent to_local (500) plus the claimed to_remote (100); a justice tx that
    // double-colored or burned the to_local would leave B at a different balance.
    wait_for_asset_balance_exact(node2_addr, &asset_id, RGB_ON_NODE_A).await;

    // A's wallet was never touched by the channel; its balance must be unchanged.
    (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    refresh_transfers(node1_addr).await;
    wait_for_btc_balance_exact(node1_addr, node1_btc_after_open).await;
    // A issued 1000 RGB; the 600 put in the channel went to B on the penalty,
    // so A is left with the 400 it never committed.
    wait_for_asset_balance_exact(node1_addr, &asset_id, ISSUE_AMT - RGB_ON_NODE_A).await;

    // Stop both nodes and release their sockets.
    shutdown(&[node1_addr, node2_addr]).await;
}

// BOLT #3 / BOLT #5: after Node A broadcasts a revoked commitment transaction,
// Node B must detect the breach and sweep the channel funds with a justice tx.
// Run once with B holding no RGB before the cheat (all 600 on A's to_local) and
// once with B holding 100 (the revoked commitment colors both sides).
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn penalty_transaction() {
    initialize();

    for b_held_rgb in B_HELD_RGB_ITERATIONS {
        let iter_dir_base = format!("{TEST_DIR_BASE}b_held_{b_held_rgb}/");
        run_penalty_scenario(&iter_dir_base, b_held_rgb).await;
    }
}
