//! close cleanup removes the first reverse match in the channel-ID map.
//!
//! Two separate claims about the former-temporary -> final channel ID map live in `src/ldk.rs`:
//!
//! - [`UnlockedAppState::delete_channel_id`] (~429) scans the map for the *first* temporary key
//!   whose **value** equals the closing channel's final ID and removes only that one, so a map
//!   holding several temporary keys for one final ID keeps the rest.
//! - [`UnlockedAppState::save_channel_ids_map`] (~448) `unwrap()`s the store write while holding
//!   the map's `MutexGuard`, so a failed write panics with the guard alive.
//!
//! The tests here take them in order:
//!
//! - [`natural_flow_never_duplicates_a_final_id`] — route (a) of the plan and the baseline
//!   (rule 4): a two-channel flow plus a re-open that reuses a freed temporary ID. It records what
//!   correct cleanup looks like and whether the node can build the duplicate state on its own.
//! - [`duplicate_reverse_entries_leave_a_stale_one`] — route (b): the duplicate entry is
//!   written into the stopped node's `channel_ids` store, which is **weaker evidence** and is
//!   labelled as such in the verdict.
//! - [`channel_ids_write_failure_panics_and_poisons_the_map`] — the `unwrap()` probe: the
//!   store write is made to fail by replacing `.ldk/channel_ids` with a directory, so `rename()`
//!   onto it cannot succeed.

use crate::test::repro_util::{
    channel_ids_on_disk, channel_ids_path, inject_channel_id_entry, snapshot_node_dir,
};

use super::*;

const TEST_DIR_BASE: &str = "tmp/delete_channel_id/";

/// Caller-supplied temporary channel ID for channel A (node1 -> node2).
const TEMP_ID_A: &str = "0011223344556677889900112233445566778899001122334455667788990011";
/// Caller-supplied temporary channel ID for channel B (node1 -> node3).
const TEMP_ID_B: &str = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff";
/// The second temporary ID injected into the stopped node's map, pointing at channel A.
const TEMP_ID_DUP: &str = "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000";

const CHAN_A_ASSET_AMT: u64 = 400;
const CHAN_B_ASSET_AMT: u64 = 300;

/// `/getchannelid` without the helper's built-in "must be 200" assertion, so a poisoned map — a
/// panic in the handler, which drops the connection — is observable instead of fatal.
async fn get_channel_id_res(
    node_address: SocketAddr,
    temporary_channel_id: &str,
) -> Result<Response, reqwest::Error> {
    let payload = GetChannelIdRequest {
        temporary_channel_id: temporary_channel_id.to_string(),
    };
    reqwest::Client::new()
        .post(format!("http://{node_address}/getchannelid"))
        .json(&payload)
        .send()
        .await
}

/// `/openchannel` with only a temporary channel ID that is expected to be rejected before any
/// channel work starts, tolerating a node that no longer answers at all.
async fn open_channel_res(
    node_address: SocketAddr,
    peer_pubkey: &str,
    peer_port: u16,
    asset_id: &str,
    temporary_channel_id: &str,
) -> Result<Response, reqwest::Error> {
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{peer_pubkey}@127.0.0.1:{peer_port}"),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(CHAN_B_ASSET_AMT),
        asset_id: Some(asset_id.to_string()),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: Some(temporary_channel_id.to_string()),
    };
    reqwest::Client::new()
        .post(format!("http://{node_address}/openchannel"))
        .json(&payload)
        .send()
        .await
}

/// `/openchannel` for a plain vanilla channel, which never touches the channel ID map on the
/// request path.
async fn open_vanilla_channel_res(
    node_address: SocketAddr,
    peer_pubkey: &str,
    peer_port: u16,
) -> Result<Response, reqwest::Error> {
    let payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!("{peer_pubkey}@127.0.0.1:{peer_port}"),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: None,
        asset_id: None,
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    reqwest::Client::new()
        .post(format!("http://{node_address}/openchannel"))
        .json(&payload)
        .send()
        .await
}

/// Assert that `temporary_channel_id` is a live key of the map: `/openchannel` refuses to reuse it.
async fn assert_temporary_id_is_taken(
    node_address: SocketAddr,
    peer_pubkey: &str,
    peer_port: u16,
    asset_id: &str,
    temporary_channel_id: &str,
) {
    let res = open_channel_res(
        node_address,
        peer_pubkey,
        peer_port,
        asset_id,
        temporary_channel_id,
    )
    .await
    .expect("the node should still be answering /openchannel");
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Temporary channel ID already used",
        "TemporaryChannelIdAlreadyUsed",
    )
    .await;
}

/// Assert that the map has no entry for `temporary_channel_id`, i.e. the ID is free again.
async fn assert_temporary_id_is_unknown(node_address: SocketAddr, temporary_channel_id: &str) {
    let res = get_channel_id_res(node_address, temporary_channel_id)
        .await
        .expect("the node should still be answering /getchannelid");
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Unknown temporary channel ID",
        "UnknownTemporaryChannelId",
    )
    .await;
}

/// Poll the persisted map until `pred` holds, then return it. The map is written from the LDK
/// event handler, so it lags the API state a close request reports.
async fn wait_for_channel_ids<F>(node_test_dir: &str, what: &str, pred: F) -> Vec<(String, String)>
where
    F: Fn(&[(String, String)]) -> bool,
{
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let map = channel_ids_on_disk(node_test_dir);
        if pred(&map) {
            return map;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            panic!("timed out waiting for the channel_ids map to {what}, it holds {map:?}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// The temporary keys the persisted map points at `final_id`.
fn keys_pointing_at(map: &[(String, String)], final_id: &str) -> Vec<String> {
    map.iter()
        .filter(|(_, v)| v == final_id)
        .map(|(k, _)| k.clone())
        .collect()
}

/// Whether any final channel ID appears as the value of more than one temporary key — the
/// precondition `delete_channel_id`'s first-match scan needs to pick the wrong entry.
fn has_duplicate_values(map: &[(String, String)]) -> bool {
    let mut values: Vec<&String> = map.iter().map(|(_, v)| v).collect();
    values.sort();
    let total = values.len();
    values.dedup();
    values.len() != total
}

async fn wait_for_channel_gone(node_address: SocketAddr, channel_id: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if !list_channels(node_address)
            .await
            .iter()
            .any(|c| c.channel_id == channel_id)
        {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            panic!("channel {channel_id} is still open on node {node_address}");
        }
        mine_n_blocks(false, 1);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn wait_for_channel_ready(node_address: SocketAddr, channel_id: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if list_channels(node_address)
            .await
            .iter()
            .any(|c| c.channel_id == channel_id && c.ready)
        {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("channel {channel_id} did not become ready again on node {node_address}");
        }
    }
}

/// Route (a) of the plan, and the baseline for rules 4 and 5: two live channels with
/// caller-supplied temporary IDs, one of them closed, then re-opened reusing the freed temporary
/// ID. Records what correct cleanup looks like and whether the node builds a map with two
/// temporary keys for one final ID on its own.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn natural_flow_never_duplicates_a_final_id() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}natural/");
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

    println!("\nopening channel A (node1 -> node2) and channel B (node1 -> node3)");
    let chan_a_id = open_channel_with_custom_data(
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
    .await
    .channel_id;
    let chan_b_id = open_channel_with_custom_data(
        node1_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        Some(CHAN_B_ASSET_AMT),
        Some(&asset_id),
        None,
        None,
        None,
        Some(TEMP_ID_B),
        true,
    )
    .await
    .channel_id;

    let map = wait_for_channel_ids(&test_dir_node1, "hold both channels", |m| m.len() == 2).await;
    println!("channel_ids map with both channels open: {map:?}");
    assert_eq!(
        map,
        {
            let mut expected = vec![
                (TEMP_ID_A.to_string(), chan_a_id.clone()),
                (TEMP_ID_B.to_string(), chan_b_id.clone()),
            ];
            expected.sort();
            expected
        },
        "each channel contributes exactly one entry, keyed by its own temporary ID"
    );
    assert!(
        !has_duplicate_values(&map),
        "two live channels never share a final ID"
    );
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_A).await, chan_a_id);
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_B).await, chan_b_id);

    // --- baseline: closing channel A removes channel A's entry and nothing else
    let before_close = snapshot_node_dir("node1 with both channels open", &test_dir_node1);
    println!("\nclosing channel A");
    close_channel(node1_addr, &chan_a_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, ISSUE_AMT - CHAN_B_ASSET_AMT).await;

    let map =
        wait_for_channel_ids(&test_dir_node1, "drop channel A's entry", |m| m.len() == 1).await;
    println!("channel_ids map after closing channel A: {map:?}");
    before_close
        .diff(&snapshot_node_dir(
            "node1 after closing channel A",
            &test_dir_node1,
        ))
        .excluding_volatile()
        .print();
    assert_eq!(map, vec![(TEMP_ID_B.to_string(), chan_b_id.clone())]);
    assert_temporary_id_is_unknown(node1_addr, TEMP_ID_A).await;
    assert_eq!(
        get_channel_id(node1_addr, TEMP_ID_B).await,
        chan_b_id,
        "the surviving channel's entry is untouched"
    );

    // --- the other half of route (a): re-open reusing the freed temporary ID
    println!("\nre-opening a channel to node2 reusing channel A's temporary ID");
    let chan_a2_id = open_channel_with_custom_data(
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
    .await
    .channel_id;
    assert_ne!(
        chan_a2_id, chan_a_id,
        "the re-opened channel has its own final ID"
    );

    let map = wait_for_channel_ids(&test_dir_node1, "hold both channels again", |m| {
        m.len() == 2
    })
    .await;
    println!("channel_ids map after the re-open: {map:?}");
    assert_eq!(
        map,
        {
            let mut expected = vec![
                (TEMP_ID_A.to_string(), chan_a2_id.clone()),
                (TEMP_ID_B.to_string(), chan_b_id.clone()),
            ];
            expected.sort();
            expected
        },
        "the reused temporary ID points at the new channel, the old one is gone"
    );
    assert!(
        !has_duplicate_values(&map),
        "reusing a temporary ID does not create a second key for one final ID"
    );

    // --- and the reused entry is cleaned up correctly in turn
    println!("\nclosing the re-opened channel");
    close_channel(node1_addr, &chan_a2_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, ISSUE_AMT - CHAN_B_ASSET_AMT).await;
    let map =
        wait_for_channel_ids(&test_dir_node1, "drop the reused entry", |m| m.len() == 1).await;
    assert_eq!(map, vec![(TEMP_ID_B.to_string(), chan_b_id)]);
    assert_temporary_id_is_unknown(node1_addr, TEMP_ID_A).await;

    println!(
        "\nno step of this flow produced two temporary keys for one final ID: route (a) does not \
         reach the precondition"
    );
}

/// Route (b): the duplicate entry is injected into the stopped node's `channel_ids` store, since
/// route (a) does not produce it. Closing the channel then removes an arbitrary one of the two
/// keys and leaves the other pointing at a channel that no longer exists.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn duplicate_reverse_entries_leave_a_stale_one() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}duplicate/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    println!("\nopening channel A (node1 -> node2)");
    let chan_a_id = open_channel_with_custom_data(
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
    .await
    .channel_id;
    wait_for_channel_ids(&test_dir_node1, "hold channel A", |m| m.len() == 1).await;
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_A).await, chan_a_id);

    // --- the injection: a second temporary key for channel A's final ID
    println!("\nstopping node1 to add a second temporary key for channel A");
    shutdown(&[node1_addr]).await;
    inject_channel_id_entry(&test_dir_node1, TEMP_ID_DUP, &chan_a_id);
    let map = channel_ids_on_disk(&test_dir_node1);
    println!("channel_ids map written while node1 was down: {map:?}");
    assert_eq!(keys_pointing_at(&map, &chan_a_id).len(), 2);

    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    wait_for_channel_ready(node1_addr, &chan_a_id).await;

    // both keys are live as far as the node is concerned
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_A).await, chan_a_id);
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_DUP).await, chan_a_id);
    assert_temporary_id_is_taken(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        &asset_id,
        TEMP_ID_DUP,
    )
    .await;

    // --- the close: only one reverse match is removed
    let before_close = snapshot_node_dir("node1 before closing channel A", &test_dir_node1);
    println!("\nclosing channel A");
    close_channel(node1_addr, &chan_a_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, ISSUE_AMT).await;
    wait_for_channel_gone(node1_addr, &chan_a_id).await;
    wait_for_channel_gone(node2_addr, &chan_a_id).await;

    let map =
        wait_for_channel_ids(&test_dir_node1, "shrink after the close", |m| m.len() < 2).await;
    before_close
        .diff(&snapshot_node_dir(
            "node1 after closing channel A",
            &test_dir_node1,
        ))
        .excluding_volatile()
        .print();
    println!("channel_ids map after closing channel A: {map:?}");

    // EXPECTED AFTER FIX: close cleanup removes EVERY reverse entry pointing at the closed
    // channel's final ID, so no stale temporary key is left behind
    let survivors = keys_pointing_at(&map, &chan_a_id);
    assert!(
        survivors.is_empty(),
        "both temporary keys pointing at the closed channel must be removed, map is {map:?}"
    );
    assert!(
        map.is_empty(),
        "the channel_ids map holds no residual entry after the close, map is {map:?}"
    );

    // EXPECTED AFTER FIX: neither temporary key resolves any more — both are free again, the way
    // the baseline says a cleaned-up key should behave
    assert!(
        !list_channels(node1_addr)
            .await
            .iter()
            .any(|c| c.channel_id == chan_a_id),
        "node1 no longer has channel A"
    );
    assert_temporary_id_is_unknown(node1_addr, TEMP_ID_A).await;
    assert_temporary_id_is_unknown(node1_addr, TEMP_ID_DUP).await;
}

/// The `unwrap()` probe: `save_channel_ids_map` writes through the LDK filesystem store, which
/// renames a temporary file onto `.ldk/channel_ids`. Replacing that path with a directory makes
/// the rename fail, so the write returns an error while the map's `MutexGuard` is still held.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn channel_ids_write_failure_panics_and_poisons_the_map() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}write_fail/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    println!("\nopening channel A (node1 -> node2)");
    let chan_a_id = open_channel_with_custom_data(
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
    .await
    .channel_id;
    wait_for_channel_ids(&test_dir_node1, "hold channel A", |m| m.len() == 1).await;
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_A).await, chan_a_id);

    // --- the fault: the store can no longer write the map
    let map_path = channel_ids_path(&test_dir_node1);
    std::fs::remove_file(&map_path).unwrap();
    std::fs::create_dir(&map_path).unwrap();
    std::fs::write(map_path.join("keep"), "not empty").unwrap();
    println!("\nreplaced {} with a directory", map_path.display());

    // the in-memory map is untouched by that, so the node still answers from it
    assert_eq!(get_channel_id(node1_addr, TEMP_ID_A).await, chan_a_id);

    // --- the close reaches delete_channel_id -> save_channel_ids_map -> unwrap
    println!("\nclosing channel A");
    close_channel(node1_addr, &chan_a_id, &node2_pubkey, false).await;
    wait_for_channel_gone(node1_addr, &chan_a_id).await;

    // --- the map is dead: every read of it now hits the poisoned mutex and panics the handler,
    // which drops the connection rather than returning a status
    // EXPECTED AFTER FIX: a failed channel_ids write is handled gracefully, so the map is NOT
    // poisoned — /getchannelid keeps completing with a normal status rather than dropping the
    // connection or answering with a server error
    let t_0 = OffsetDateTime::now_utc();
    let mut poisoned = false;
    loop {
        match get_channel_id_res(node1_addr, TEMP_ID_A).await {
            Err(e) => {
                println!("/getchannelid no longer completes: {e}");
                poisoned = true;
                break;
            }
            Ok(res) => {
                if res.status().is_server_error() {
                    println!("/getchannelid answers {}", res.status());
                    poisoned = true;
                    break;
                }
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 15.0 {
            break;
        }
        mine_n_blocks(false, 1);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(
        !poisoned,
        "a failed channel_ids write must not take the map down or poison its mutex"
    );

    // EXPECTED AFTER FIX: the map is still healthy — /getchannelid completes with a normal status
    // rather than a poisoned-mutex panic
    let recovered = get_channel_id_res(node1_addr, TEMP_ID_A).await;
    assert!(
        recovered
            .map(|r| !r.status().is_server_error())
            .unwrap_or(false),
        "the channel_ids map must stay usable after a failed write, not poison itself"
    );
    let open_res = open_channel_res(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        &asset_id,
        TEMP_ID_B,
    )
    .await;
    println!("/openchannel with a temporary channel ID answers: {open_res:?}");
    // EXPECTED AFTER FIX: the duplicate check reads a healthy map, so /openchannel with a fresh
    // temporary ID is not knocked out by a poisoned mutex
    assert!(
        open_res
            .map(|r| !r.status().is_server_error())
            .unwrap_or(false),
        "/openchannel must still be able to run the channel_ids duplicate check"
    );

    // --- nothing was persisted: the map file is still the directory we put there
    assert!(
        channel_ids_path(&test_dir_node1).is_dir(),
        "the store write must not have succeeded"
    );

    // --- scope of the damage, part 1: the read-only API still answers, so this is not simply a
    // dead process
    let channels = list_channels(node1_addr).await;
    println!(
        "node1 still answers /listchannels with {} channels",
        channels.len()
    );
    assert!(!channels.iter().any(|c| c.channel_id == chan_a_id));
    println!(
        "node1 still answers /nodeinfo: {}",
        node_info(node1_addr).await.pubkey
    );

    // EXPECTED AFTER FIX: the background processor survives the failed write, so LDK events keep
    // being handled. A vanilla open skips the `channel_ids()` check, is accepted, and then funds
    // normally because `FundingGenerationReady` still has a handler.
    println!("\nopening a vanilla channel with no temporary channel ID");
    let opened = open_vanilla_channel_res(node1_addr, &node2_pubkey, NODE2_PEER_PORT)
        .await
        .expect("the node should still be answering /openchannel without a temporary ID");
    let status = opened.status();
    println!("/openchannel without a temporary channel ID answers {status}");
    assert!(
        status.is_success(),
        "nothing on the request path reads the channel ID map when no temporary ID is given"
    );

    let t_0 = OffsetDateTime::now_utc();
    let funded = loop {
        if list_channels(node1_addr).await.iter().any(|c| c.ready) {
            break true;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 45.0 {
            break false;
        }
        mine_n_blocks(false, 1);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    let channels = list_channels(node1_addr).await;
    println!(
        "45s after the accepted open, node1 has {} channel(s), ready: {:?}",
        channels.len(),
        channels.iter().map(|c| c.ready).collect::<Vec<_>>()
    );
    assert!(
        funded,
        "the background processor must survive the failed write and fund the channel"
    );
}
