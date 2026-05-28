//! End-to-end VSS happy path: init → unlock → state (BTC + RGB asset +
//! channel) → shutdown + wipe → init + clear-fence + unlock → assert that
//! every piece of state came back through VSS.
//!
//! This guards the "VSS should restore everything" invariant. If anyone
//! removes the RGB-restore call from `start_ldk`, the asset/balance/channel
//! assertions below fail.
//!
//! Requires the regtest stack (`./regtest.sh start`) and the VSS server
//! (`docker compose --profile vss up -d`).

use crate::helpers::*;
use serial_test::serial;
use std::{fs, time::Duration};

const VSS_URL: &str = "http://127.0.0.1:8081/vss";
const NODE_A_PORT_OFFSET: u16 = 90;
const NODE_B_PORT_OFFSET: u16 = 90;
const PASSWORD_A: &str = "nodeApass";
const PASSWORD_B: &str = "nodeBpass";

fn vss_server_available() -> bool {
    std::net::TcpStream::connect_timeout(&"127.0.0.1:8081".parse().unwrap(), Duration::from_secs(2))
        .is_ok()
}

#[test]
#[serial]
fn vss_restores_btc_assets_and_channels_on_fresh_device() {
    ensure_regtest_available();
    if !vss_server_available() {
        eprintln!("SKIP: VSS server not available at {VSS_URL}");
        return;
    }

    let test_dir = test_dir("vss_restore");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("clean previous test dir");
    }
    fs::create_dir_all(&test_dir).expect("create test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");

    // --- Phase 1: original node A (with VSS) + peer B (no VSS) ---
    let node_a = make_node_with_vss(
        &node_a_dir,
        NODE_A_DAEMON_PORT + NODE_A_PORT_OFFSET,
        NODE_A_PEER_PORT + NODE_A_PORT_OFFSET,
        VSS_URL,
    );
    let node_b = make_node(
        &node_b_dir,
        NODE_B_DAEMON_PORT + NODE_B_PORT_OFFSET,
        NODE_B_PEER_PORT + NODE_B_PORT_OFFSET,
    );

    let mnemonic_a = node_a
        .init(PASSWORD_A.to_string(), None)
        .expect("node A init");
    node_b
        .init(PASSWORD_B.to_string(), None)
        .expect("node B init");

    node_a
        .unlock(unlock_request(PASSWORD_A))
        .expect("node A initial unlock");
    node_b
        .unlock(unlock_request(PASSWORD_B))
        .expect("node B initial unlock");

    fund_and_create_utxos(&node_a, "node A");
    fund_and_create_utxos(&node_b, "node B");

    // Pre-restore balance baseline (BTC).
    let btc_pre = node_a
        .btc_balance(false)
        .expect("node A btc_balance pre")
        .vanilla
        .spendable;
    assert!(btc_pre > 0, "node A must have BTC after funding");

    // Issue an RGB asset on node A.
    let asset = node_a
        .issueassetnia(SdkIssueAssetNiaRequest {
            amounts: vec![1_000],
            ticker: "USDT".to_string(),
            name: "Tether".to_string(),
            precision: 0,
        })
        .expect("node A issueassetnia");
    let asset_id = asset.asset_id;
    assert_eq!(asset_balance_spendable(&node_a, &asset_id), 1_000);

    // Open an RGB-asset channel A → B.
    let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;
    let peer_uri = format!(
        "{node_b_pubkey}@127.0.0.1:{}",
        NODE_B_PEER_PORT + NODE_B_PORT_OFFSET
    );
    node_a
        .connectpeer(peer_uri.clone())
        .expect("node A connectpeer");

    let open_channel = node_a
        .openchannel(SdkOpenChannelRequest {
            peer_pubkey_and_opt_addr: peer_uri.clone(),
            capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
            push_msat: 0,
            public: true,
            with_anchors: true,
            fee_base_msat: None,
            fee_proportional_millionths: None,
            temporary_channel_id: None,
            asset_id: Some(asset_id.clone()),
            asset_amount: Some(600),
            push_asset_amount: None,
            virtual_open_mode: None,
        })
        .expect("node A openchannel");
    wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(120));
    mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
    wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));
    let channel_id = node_a
        .get_channel_id(open_channel.temporary_channel_id)
        .expect("node A get_channel_id");

    // After channel funding, 400 stays liquid, 600 is committed to the channel.
    assert_eq!(asset_balance_spendable(&node_a, &asset_id), 400);
    let btc_after_channel = node_a
        .btc_balance(false)
        .expect("node A btc_balance post-channel")
        .vanilla
        .spendable;

    // Deterministic RGB push to VSS — the auto-backup path is Async, so an
    // explicit synchronous call is what guarantees state is in VSS before
    // we wipe.
    let backup_version = node_a.vss_backup().expect("node A vss_backup");
    assert!(
        backup_version > 0,
        "vss_backup must return a positive version"
    );

    // --- Phase 2: shut node A down and wipe its local state. ---
    node_a.shutdown();
    drop(node_a);

    fs::remove_dir_all(&node_a_dir).expect("wipe node A storage");
    assert!(!node_a_dir.exists(), "node A storage must be gone");

    // --- Phase 3: fresh node A with the same VSS URL and mnemonic. ---
    let node_a = make_node_with_vss(
        &node_a_dir,
        NODE_A_DAEMON_PORT + NODE_A_PORT_OFFSET,
        NODE_A_PEER_PORT + NODE_A_PORT_OFFSET,
        VSS_URL,
    );

    // The mnemonic returned by init must round-trip (same seed → same
    // VSS identity → same backup).
    let mnemonic_returned = node_a
        .init(PASSWORD_A.to_string(), Some(mnemonic_a.clone()))
        .expect("node A re-init");
    assert_eq!(mnemonic_returned, mnemonic_a);

    // The previous owner's fence is still on VSS. Clear it before unlock.
    node_a
        .vss_clear_fence(SdkVssClearFenceRequest {
            password: PASSWORD_A.to_string(),
        })
        .expect("node A vss_clear_fence");

    // Unlock restores both the KV stream (channels, monitors, payments) and
    // the RGB wallet (assets, allocations) from VSS.
    node_a
        .unlock(unlock_request(PASSWORD_A))
        .expect("node A unlock after restore");

    // Reconnect to B so on-chain channel state can resync.
    node_a
        .connectpeer(peer_uri)
        .expect("node A connectpeer after restore");
    wait_for_channel_ready(&node_a, channel_id, Duration::from_secs(30));
    wait_for_usable_channels(&node_a, 1, Duration::from_secs(60));

    // --- Phase 4: assert the restored state matches what we wrote. ---
    assert_eq!(
        asset_balance_spendable(&node_a, &asset_id),
        400,
        "asset spendable balance must survive VSS restore"
    );

    let btc_post = node_a
        .btc_balance(false)
        .expect("node A btc_balance post-restore")
        .vanilla
        .spendable;
    assert_eq!(
        btc_post, btc_after_channel,
        "BTC balance must match pre-shutdown after VSS restore"
    );

    let channels = node_a.list_channels().expect("node A list_channels");
    assert!(
        channels.iter().any(|c| c.channel_id == channel_id),
        "the channel opened before restore must still be listed"
    );

    // Cleanup
    node_a.shutdown();
    node_b.shutdown();
}
