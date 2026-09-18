use super::*;

const TEST_DIR_BASE: &str = "tmp/penalty_transaction/";
const CHANNEL_CAPACITY_SAT: u64 = 100_000;
const RGB_ON_NODE_A: u64 = 600;

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
// i.e. the counterparty's justice (penalty) sweep has been broadcast.
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
// counterparty's to_remote output is dust-sized, so the max is unambiguous.
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

// BOLT #3 / BOLT #5: after Node A broadcasts a revoked commitment transaction,
// Node B must detect the breach and sweep the channel funds with a justice tx.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn penalty_transaction() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}revoked_commitment/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let backup_dir = format!("{test_dir_base}node1_backup");

    // Start and fund both nodes.
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
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

    // State 1: open a channel with 600 RGB units on A's side.
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

    // Snapshot A's State 1 balance (A's wallet is untouched by the channel);
    // back up its directory as the "honest" state to rewind the cheat from.
    let node1_btc_after_open = btc_balance(node1_addr).await.vanilla.spendable;
    shutdown(&[node1_addr]).await;
    if Path::new(&backup_dir).exists() {
        std::fs::remove_dir_all(&backup_dir).unwrap();
    }
    copy_dir_all(&test_dir_node1, &backup_dir).unwrap();

    // Restart A from its State 1 state.
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    connect_peer(
        node1_addr,
        &node2_pubkey,
        &format!("127.0.0.1:{NODE2_PEER_PORT}"),
    )
    .await;

    // State 2: a payment revokes State 1 on both sides.
    keysend_with_ln_balance(
        node1_addr,
        node2_addr,
        &node2_pubkey,
        Some(6_000_000),
        Some(&asset_id),
        Some(100),
        Some(RGB_ON_NODE_A),
        Some(0),
    )
    .await;

    // Stop both nodes, then rewind A to its State 1 backup (the cheat).
    shutdown(&[node1_addr, node2_addr]).await;
    std::fs::remove_dir_all(&test_dir_node1).unwrap();
    copy_dir_all(&backup_dir, &test_dir_node1).unwrap();

    // Restart A with the stale State 1 state.
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;

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
    // then read its to_local output: the fund B must sweep with a justice tx.
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
    mine(false);

    // Restart B so it syncs and detects the breach.
    shutdown(&[node1_addr]).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let node2_dir = format!("{test_dir_base}node2");
    wait_for_ldk_log(
        &node2_dir,
        "Got broadcast of revoked counterparty commitment transaction",
    )
    .await;

    // Wait for B's justice tx, mine it, then confirm it to ANTI_REORG_DELAY depth
    // so the OutputSweeper emits a SpendableOutputs consolidating sweep.
    wait_for_mempool_spender(&revoked_txid, to_local_index as u64).await;
    let justice_txid = mempool_txids()
        .into_iter()
        .find(|t| tx_spends_output(t, &revoked_txid, to_local_index as u64))
        .expect("justice tx spending the revoked to_local output");
    mine(false);
    // ANTI_REORG_DELAY confirmations are required before LDK arms the sweep.
    mine_n_blocks(true, 10);

    // Wait for and mine the OutputSweeper consolidating sweep.
    wait_for_mempool_funding_spender(&justice_txid).await;
    let sweep_txid = mempool_txids()
        .into_iter()
        .find(|t| tx_spends_output_any(t, &justice_txid))
        .expect("sweep tx spending the justice output");
    mine(false);

    // Assert justice tx structure: one input (the revoked to_local), one output.
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
    assert_eq!(justice_outputs.len(), 1, "justice tx has one output");

    // Assert sweep tx structure: one input (justice:0), one output.
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
    assert_eq!(sweep_outputs.len(), 1, "sweep tx has one output");

    let sweep_out = to_local_output(&sweep_tx).1;
    let expected_node2_btc = node2_btc_before + sweep_out;
    assert!(
        to_local_value - sweep_out < 5_000,
        "total fees ({}) must be under 5 000 sats",
        to_local_value - sweep_out,
    );
    wait_for_btc_balance_exact(node2_addr, expected_node2_btc).await;

    // The 600 RGB on the revoked to_local were swept to the honest node (B).
    wait_for_asset_balance_exact(node2_addr, &asset_id, RGB_ON_NODE_A).await;

    // A's wallet was never touched by the channel; its balance must be unchanged.
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    wait_for_btc_balance_exact(node1_addr, node1_btc_after_open).await;
    // A issued 1000 RGB; the 600 put in the channel went to B on the penalty,
    // so A is left with the 400 it never committed.
    wait_for_asset_balance_exact(node1_addr, &asset_id, ISSUE_AMT - RGB_ON_NODE_A).await;

    // Stop both nodes and release their sockets.
    shutdown(&[node1_addr, node2_addr]).await;
}
