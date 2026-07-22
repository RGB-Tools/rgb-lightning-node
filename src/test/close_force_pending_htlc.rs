use super::*;

const TEST_DIR_BASE: &str = "tmp/close_force_pending_htlc/";

/// Force close with a pending RGB HTLC: both nodes must still recover their
/// BTC and node1 its assets. The HTLC is held pending by construction: node2
/// is set to hold incoming payments (HOLD_PAYMENT_CLAIMABLE_ON_NODE), so the
/// commitment provably carries the asset HTLC when node2 force-closes.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn close_force_pending_htlc() {
    initialize();

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
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id),
    )
    .await;

    // Baselines before the close: sweeps can confirm while close_channel is
    // still mining the 144 maturity blocks.
    let node1_spendable_before = spendable_sats(node1_addr).await;
    let node2_spendable_before = spendable_sats(node2_addr).await;

    // node2 holds the incoming payment: the 10-asset HTLC stays pending.
    HELD_PAYMENT_CLAIMABLE_COUNT.store(0, Ordering::SeqCst);
    let _hold_guard = NodeOverrideGuard::set(&HOLD_PAYMENT_CLAIMABLE_ON_NODE, &node2_pubkey);

    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        Some(crate::routes::HTLC_MIN_MSAT),
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

    // Force close from node2 with the HTLC held: its commitment carries it.
    close_channel(node2_addr, &channel.channel_id, &node1_pubkey, true).await;
    let commitment_txid = wait_for_funding_spend_txid(&test_dir_node1, &channel.channel_id).await;
    assert!(
        tx_output_sats(&commitment_txid).contains(&(crate::routes::HTLC_MIN_MSAT / 1000)),
        "confirmed commitment must carry the pending HTLC output"
    );

    let mut node1_btc_ok = false;
    let mut node2_btc_ok = false;
    let mut node1_assets_ok = false;
    for _ in 0..60 {
        mine_n_blocks(false, 10);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        refresh_transfers_tolerant(node1_addr).await;
        refresh_transfers_tolerant(node2_addr).await;
        if !node1_btc_ok && spendable_sats(node1_addr).await > node1_spendable_before + 30_000 {
            node1_btc_ok = true;
        }
        if !node2_btc_ok && spendable_sats(node2_addr).await > node2_spendable_before + 30_000 {
            node2_btc_ok = true;
        }
        let node1_assets = asset_balance_spendable(node1_addr, &asset_id).await;
        if node1_assets == 990 {
            node1_assets_ok = true;
        }
        println!(
            "recovery: node1_btc_ok={node1_btc_ok} node2_btc_ok={node2_btc_ok} node1_assets={node1_assets}"
        );
        if node1_btc_ok && node2_btc_ok && node1_assets_ok {
            break;
        }
    }
    assert!(
        node1_btc_ok && node2_btc_ok && node1_assets_ok,
        "recovery failed: node1_btc_ok={node1_btc_ok} node2_btc_ok={node2_btc_ok} node1_assets_ok={node1_assets_ok}"
    );
    // The payment was never claimed: node2 must have no assets.
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 0);
}
