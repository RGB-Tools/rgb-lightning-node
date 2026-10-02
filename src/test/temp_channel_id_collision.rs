//! a caller-supplied `temporary_channel_id` can collide with another live channel.
//!
//! `POST /openchannel` rejects a caller-supplied temporary channel ID only when it is a **key** of
//! the former-temporary -> final channel ID map (`src/routes.rs`, `channel_ids().contains_key`),
//! and LDK's own duplicate check is per peer (`ChannelManager::create_channel`). A live channel's
//! **final** ID is a *value* of that map and belongs to a different peer's channel set, so it
//! passes both checks.
//!
//! Both halves of the claim are exercised here:
//!
//! - [`collision_with_final_channel_id`] — reuse channel A's final ID as the temporary ID of a
//!   channel to another peer. This is the half the guards do not cover.
//! - [`collision_with_temporary_channel_id`] — reuse channel A's temporary ID. The map key
//!   check covers this one; the test pins that it stays covered.
//! - [`baseline_distinct_temporary_ids`] — the same two-channel flow with a fresh temporary ID
//!   for channel B, so that anything the collision run leaves behind can be compared against the
//!   happy path (rule 4 of the plan).

use lightning::rgb_utils::parse_rgb_channel_info;

use super::repro_util::{channel_ids_on_disk, snapshot_node_dir};
use super::*;

const TEST_DIR_BASE: &str = "tmp/temp_channel_id_collision/";

/// Caller-supplied temporary channel ID for channel A (node1 -> node2).
const TEMP_ID_A: &str = "0011223344556677889900112233445566778899001122334455667788990011";
/// A fresh, unused temporary channel ID — the baseline run gives it to channel B.
const TEMP_ID_B: &str = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff";

const CHAN_A_ASSET_AMT: u64 = 400;
const CHAN_B_ASSET_AMT: u64 = 300;

/// Path of the RGB channel-info file for `channel_id`, relative to a node's data directory.
/// `.ldk/<channel_id>` holds the final info, `.ldk/<channel_id>.pending` the pending one.
fn rgb_info_rel(channel_id: &str) -> String {
    format!("{LDK_DIR}/{channel_id}")
}

fn rgb_info_pending_rel(channel_id: &str) -> String {
    format!("{LDK_DIR}/{channel_id}.pending")
}

fn rgb_info_path(node_test_dir: &str, channel_id: &str) -> PathBuf {
    PathBuf::from(node_test_dir).join(rgb_info_rel(channel_id))
}

/// `(local, remote)` asset amounts recorded in a channel's RGB info file, or `None` if the node
/// has no RGB info for that channel ID at all.
fn rgb_amounts_on_disk(node_test_dir: &str, channel_id: &str) -> Option<(u64, u64)> {
    let path = rgb_info_path(node_test_dir, channel_id);
    if !path.exists() {
        return None;
    }
    let info = parse_rgb_channel_info(&path);
    Some((info.local_rgb_amount, info.remote_rgb_amount))
}

/// `(asset_id, local, remote)` as the node's own API reports them for `channel_id`.
async fn channel_asset_view(
    node_address: SocketAddr,
    channel_id: &str,
) -> (Option<String>, Option<u64>, Option<u64>) {
    let channels = list_channels(node_address).await;
    let channel = channels
        .iter()
        .find(|c| c.channel_id == channel_id)
        .unwrap_or_else(|| panic!("channel {channel_id} is gone from list_channels"));
    (
        channel.asset_id.clone(),
        channel.asset_local_amount,
        channel.asset_remote_amount,
    )
}

/// `AssetBalanceResponse` is not `Debug`, and the off-chain fields are the interesting ones here.
async fn balance_str(node_address: SocketAddr, asset_id: &str) -> String {
    let b = asset_balance(node_address, asset_id).await;
    format!(
        "settled {} / future {} / spendable {} / offchain_outbound {} / offchain_inbound {}",
        b.settled, b.future, b.spendable, b.offchain_outbound, b.offchain_inbound
    )
}

/// Whether the node still answers `/listchannels`. A panic inside the `ChannelManager` poisons its
/// locks, after which this stops being true.
async fn channel_manager_alive(node_address: SocketAddr) -> bool {
    reqwest::Client::new()
        .get(format!("http://{node_address}/listchannels"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Shared prologue: three nodes, funded, with an NIA asset issued on node1 and a funded colored
/// channel A from node1 to node2 opened under the caller-supplied [`TEMP_ID_A`].
struct Setup {
    node1_addr: SocketAddr,
    node2_addr: SocketAddr,
    node3_addr: SocketAddr,
    test_dir_node1: String,
    node2_pubkey: String,
    node3_pubkey: String,
    asset_id: String,
    chan_a_id: String,
}

async fn setup(test_dir_base: &str) -> Setup {
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let node3_pubkey = node_info(node3_addr).await.pubkey;

    println!("\nopening channel A (node1 -> node2) with the caller-supplied temporary ID");
    let channel_a = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(CHAN_A_ASSET_AMT),
        Some(&asset_id),
        None,
        None,
        None,
        Some(TEMP_ID_A),
        true,
    )
    .await;
    let chan_a_id = channel_a.channel_id.clone();

    // the map now holds TEMP_ID_A -> chan_a_id: the temporary ID is a key, the final ID a value
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_A).await, chan_a_id);
    assert_eq!(
        rgb_amounts_on_disk(&test_dir_node1, &chan_a_id),
        Some((CHAN_A_ASSET_AMT, 0)),
        "channel A's RGB info should record the amount it was opened with"
    );
    assert_eq!(
        asset_balance_spendable(node1_addr, &asset_id).await,
        ISSUE_AMT - CHAN_A_ASSET_AMT
    );

    Setup {
        node1_addr,
        node2_addr,
        node3_addr,
        test_dir_node1,
        node2_pubkey,
        node3_pubkey,
        asset_id,
        chan_a_id,
    }
}

/// The claim itself: channel A's **final** ID is accepted as the temporary ID of a new channel to
/// a different peer. Channel B's RGB info is written over channel A's, and funding channel B then
/// renames channel A's RGB info away — after which node1's block-sync task panics reading it and
/// the poisoned `ChannelManager` locks make every later channel operation fail.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn collision_with_final_channel_id() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}final_id/");
    let s = setup(&test_dir_base).await;
    let chan_a_id = s.chan_a_id.clone();

    let before = snapshot_node_dir("node1 with only channel A", &s.test_dir_node1);
    assert!(before.contains(&rgb_info_rel(&chan_a_id)));
    assert!(before.contains(&rgb_info_pending_rel(&chan_a_id)));
    assert_eq!(
        channel_ids_on_disk(&s.test_dir_node1),
        vec![(TEMP_ID_A.to_string(), chan_a_id.clone())],
        "the map holds channel A's temporary ID as a key and its final ID as a value"
    );

    // --- the request itself: neither guard rejects a live channel's final ID
    println!(
        "\nopening channel B (node1 -> node3) reusing channel A's FINAL ID as the temporary one"
    );
    let opened = open_channel_raw(
        s.node1_addr,
        &s.node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        Some(CHAN_B_ASSET_AMT),
        Some(&s.asset_id),
        None,
        None,
        None,
        Some(&chan_a_id),
        true,
        true,
    )
    .await;

    let accepted = match opened {
        Ok(response) => {
            println!(
                "request ACCEPTED, temporary channel ID: {}",
                response.temporary_channel_id
            );
            assert_eq!(response.temporary_channel_id, chan_a_id);
            true
        }
        Err(response) => {
            println!("request REJECTED with status {}", response.status());
            println!("body: {}", response.text().await.unwrap());
            false
        }
    };
    // EXPECTED AFTER FIX: a caller-supplied temporary channel ID that collides with a LIVE
    // channel's FINAL ID is rejected, exactly as a collision with a temporary ID already is.
    assert!(
        !accepted,
        "a caller-supplied temporary channel ID that collides with a live channel's final ID \
         must be REJECTED, not accepted"
    );

    // EXPECTED AFTER FIX: the rejected open leaves channel A's RGB records untouched
    let after_open = snapshot_node_dir("node1 right after the rejected open", &s.test_dir_node1);
    let diff = before.diff(&after_open).excluding_volatile();
    diff.print();
    assert!(
        !diff.changed_paths().contains(&rgb_info_rel(&chan_a_id)),
        "channel A's RGB info file must be untouched by the rejected colliding open"
    );
    assert!(
        !diff
            .changed_paths()
            .contains(&rgb_info_pending_rel(&chan_a_id)),
        "channel A's pending RGB info file must be untouched by the rejected colliding open"
    );

    let preserved = rgb_amounts_on_disk(&s.test_dir_node1, &chan_a_id);
    println!("channel A RGB info after the rejected open: {preserved:?}");
    assert_eq!(
        preserved,
        Some((CHAN_A_ASSET_AMT, 0)),
        "channel A's RGB info must still hold channel A's own amounts"
    );
    assert_eq!(
        channel_asset_view(s.node1_addr, &chan_a_id).await,
        (Some(s.asset_id.clone()), Some(CHAN_A_ASSET_AMT), Some(0)),
        "node1 still reports channel A's own asset amounts"
    );
    assert_eq!(
        channel_asset_view(s.node2_addr, &chan_a_id).await,
        (Some(s.asset_id.clone()), Some(0), Some(CHAN_A_ASSET_AMT)),
        "node2, which was not asked to reuse an ID, still has channel A right"
    );

    // EXPECTED AFTER FIX: channel A's RGB info files are NOT renamed away; both stay on disk
    let chan_a_info_path = rgb_info_path(&s.test_dir_node1, &chan_a_id);
    assert!(
        chan_a_info_path.exists(),
        "channel A's RGB info file must still exist after the rejected open"
    );
    assert!(
        after_open.contains(&rgb_info_pending_rel(&chan_a_id)),
        "channel A's pending RGB info file must still be present after the rejected open"
    );

    // EXPECTED AFTER FIX: the channel ID map still holds ONLY channel A's own entry — no
    // A_tmp -> A -> B chain, and channel A's final ID never becomes a temporary key.
    let map = channel_ids_on_disk(&s.test_dir_node1);
    println!("channel_ids map on disk: {map:?}");
    assert_eq!(
        map,
        vec![(TEMP_ID_A.to_string(), chan_a_id.clone())],
        "the map must still hold only channel A's temporary -> final entry: {map:?}"
    );

    // EXPECTED AFTER FIX: node1 stays alive, still reports channel A as its own RGB channel, and
    // its off-chain accounting still holds channel A's amount.
    assert!(
        channel_manager_alive(s.node1_addr).await,
        "node1's ChannelManager must survive a rejected colliding open"
    );
    let view = channel_asset_view(s.node1_addr, &chan_a_id).await;
    println!("node1's view of channel A after the rejected open: {view:?}");
    assert_eq!(
        view,
        (Some(s.asset_id.clone()), Some(CHAN_A_ASSET_AMT), Some(0)),
        "node1 still reports channel A as its own RGB channel"
    );
    let balance = asset_balance(s.node1_addr, &s.asset_id).await;
    println!(
        "node1 asset balance after the rejected open: {}",
        balance_str(s.node1_addr, &s.asset_id).await
    );
    assert_eq!(
        balance.offchain_outbound, CHAN_A_ASSET_AMT,
        "channel A's {CHAN_A_ASSET_AMT} units must still be in node1's off-chain accounting"
    );

    // EXPECTED AFTER FIX: channel A's own temporary ID still resolves to channel A
    assert_eq!(
        get_channel_id(s.node1_addr, TEMP_ID_A).await,
        chan_a_id,
        "channel A's own temporary ID still resolves to channel A"
    );

    // node2 is untouched: it still holds channel A with the right amounts
    assert_eq!(
        channel_asset_view(s.node2_addr, &chan_a_id).await,
        (Some(s.asset_id.clone()), Some(0), Some(CHAN_A_ASSET_AMT))
    );

    // EXPECTED AFTER FIX: channel A closes cleanly and returns its asset; node1's ChannelManager
    // survives the close (the coloured-close path finds channel A's RGB info intact).
    println!("\nasking node1 to close channel A");
    close_channel(s.node1_addr, &chan_a_id, &s.node2_pubkey, false).await;
    wait_for_balance(s.node1_addr, &s.asset_id, ISSUE_AMT).await;
    assert!(
        channel_manager_alive(s.node1_addr).await,
        "node1's ChannelManager must survive closing channel A after a rejected colliding open"
    );
    println!(
        "node1 asset balance after closing channel A: {}",
        balance_str(s.node1_addr, &s.asset_id).await
    );

    let _ = s.node3_addr;
}

/// The other half of the claim: reusing channel A's **temporary** ID is caught by the map key
/// check, so the request never reaches `create_channel`.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn collision_with_temporary_channel_id() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}temp_id/");
    let s = setup(&test_dir_base).await;

    let before = snapshot_node_dir("node1 with only channel A", &s.test_dir_node1);

    println!("\nopening channel B (node1 -> node3) reusing channel A's TEMPORARY ID");
    let opened = open_channel_raw(
        s.node1_addr,
        &s.node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        Some(CHAN_B_ASSET_AMT),
        Some(&s.asset_id),
        None,
        None,
        None,
        Some(TEMP_ID_A),
        true,
        true,
    )
    .await;

    let response = opened.expect_err(
        "reusing a temporary ID that is a key of the channel_ids map should have been rejected",
    );
    check_response_is_nok(
        *response,
        reqwest::StatusCode::FORBIDDEN,
        "Temporary channel ID already used",
        "TemporaryChannelIdAlreadyUsed",
    )
    .await;

    // a rejected request must not have touched any RGB state
    let after = snapshot_node_dir("node1 after the rejected open", &s.test_dir_node1);
    let diff = before.diff(&after).rgb_only();
    diff.print();
    assert!(
        diff.is_empty(),
        "the rejected open still changed RGB state: {}",
        diff.pretty()
    );
    assert_eq!(
        rgb_amounts_on_disk(&s.test_dir_node1, &s.chan_a_id),
        Some((CHAN_A_ASSET_AMT, 0))
    );
    assert_eq!(
        get_channel_id(s.node1_addr, TEMP_ID_A).await,
        s.chan_a_id,
        "the map entry for channel A must still point at channel A"
    );

    let _ = (s.node2_addr, s.node3_addr);
}

/// Baseline for rule 4: the same two-channel flow with a fresh temporary ID for channel B. Channel
/// A keeps its own RGB info, both channels are reported with their own amounts, and channel A
/// closes returning its asset — so anything different in the collision run is caused by the
/// collision and not by opening a second channel.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn baseline_distinct_temporary_ids() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}baseline/");
    let s = setup(&test_dir_base).await;
    let chan_a_id = s.chan_a_id.clone();

    let before = snapshot_node_dir("node1 with only channel A", &s.test_dir_node1);

    println!("\nopening channel B (node1 -> node3) with a fresh temporary ID");
    let channel_b = open_channel_with_custom_data(
        s.node1_addr,
        &s.node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        Some(CHAN_B_ASSET_AMT),
        Some(&s.asset_id),
        None,
        None,
        None,
        Some(TEMP_ID_B),
        true,
    )
    .await;
    let chan_b_id = channel_b.channel_id.clone();

    let after = snapshot_node_dir("node1 after channel B funded", &s.test_dir_node1);
    before.diff(&after).excluding_volatile().print();

    // both channels keep their own records
    assert_eq!(
        rgb_amounts_on_disk(&s.test_dir_node1, &chan_a_id),
        Some((CHAN_A_ASSET_AMT, 0))
    );
    assert_eq!(
        rgb_amounts_on_disk(&s.test_dir_node1, &chan_b_id),
        Some((CHAN_B_ASSET_AMT, 0))
    );
    assert_eq!(
        channel_asset_view(s.node1_addr, &chan_a_id).await,
        (Some(s.asset_id.clone()), Some(CHAN_A_ASSET_AMT), Some(0))
    );
    assert_eq!(
        channel_asset_view(s.node1_addr, &chan_b_id).await,
        (Some(s.asset_id.clone()), Some(CHAN_B_ASSET_AMT), Some(0))
    );
    let balance = asset_balance(s.node1_addr, &s.asset_id).await;
    assert_eq!(
        balance.offchain_outbound,
        CHAN_A_ASSET_AMT + CHAN_B_ASSET_AMT
    );
    assert_eq!(get_channel_id(s.node1_addr, TEMP_ID_A).await, chan_a_id);
    assert_eq!(get_channel_id(s.node1_addr, TEMP_ID_B).await, chan_b_id);

    // and channel A closes returning its asset
    println!("\nclosing channel A");
    close_channel(s.node1_addr, &chan_a_id, &s.node2_pubkey, false).await;
    wait_for_balance(s.node1_addr, &s.asset_id, ISSUE_AMT - CHAN_B_ASSET_AMT).await;
    println!(
        "node1 asset balance after closing channel A: {}",
        balance_str(s.node1_addr, &s.asset_id).await
    );

    let _ = s.node3_addr;
}
