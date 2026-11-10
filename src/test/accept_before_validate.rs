//! The acceptor imports a consignment before validating its contents.
//!
//! `handle_funding` (`rust-lightning/lightning/src/rgb_utils/mod.rs:599`) is called from
//! `internal_funding_created` (`channelmanager.rs:10504`) the moment a `funding_created` arrives,
//! before `inbound_chan.funding_created(...)` has looked at the message. Its first act is
//! `_accept_transfer` (`rgb_utils/mod.rs:157`), which hands the file the peer put on the p2p link
//! to `wallet.accept_transfer_consignment(...)` — not a query: it `store_secret_seal`s,
//! `import_contract`s and `accept_transfer`s into the acceptor's RGB stock
//! (`rgb-lib-0.3.0-beta.7/src/wallet/rust_only.rs:328-406`).
//!
//! Only afterwards does `handle_funding` ask whether the consignment says anything about this
//! channel:
//!
//! ```text
//! 655    if remote_rgb_assignments.len() != 1 { ...close... }
//! 661    let channel_rgb_amount = match remote_rgb_assignments[0] {
//! 662        Assignment::Fungible(amt) => amt,
//! 663        Assignment::NonFungible => 1,
//! 664        _ => unreachable!("unsupported schema"),
//! 665    };
//! ```
//!
//! Both faults are injected on the *sender*: [`SUBSTITUTE_CONSIGNMENT_ON_NODE`] makes node1 put a
//! different file on the p2p link, and [`DECOY_INFLATION_ASSIGNMENT`] makes the extra output
//! [`DECOY_FUNDING_OUTPUT_ON_NODE`] already builds carry an inflation right. The acceptor is an
//! unmodified node reacting to bytes a peer chose — and the peer is the one that builds the
//! funding transaction and the consignment for it.

use lightning::rgb_utils::parse_rgb_channel_info;

use crate::ldk::{
    DECOY_FUNDING_OUTPUT_ON_NODE, DECOY_INFLATION_ASSIGNMENT, DECOY_OUTPUT_SAT,
    SUBSTITUTE_CONSIGNMENT_ON_NODE, SUBSTITUTE_CONSIGNMENT_PATH,
};

use super::repro_util::{
    funding_psbt_outputs, print_outputs, snapshot_node_dir, DirSnapshot, TxOutput,
};
use super::*;

const TEST_DIR_BASE: &str = "tmp/accept_before_validate/";

/// The funding vout `_accept_transfer` hard-codes, and therefore the one the acceptor looks for
/// assignments at.
const ACCEPTOR_ASSUMED_VOUT: usize = 1;

const CHAN_ASSET_AMT: u64 = 400;

/// Sent to a third party before the substituted-consignment run, purely to produce a valid
/// consignment the acceptor has never seen.
const DECOY_SEND_AMT: u64 = 100;

/// Named so the tests can find the channel output by value.
const CAPACITY_SAT: u64 = 100_000;

/// How long to wait for a node to act on a message it has just been sent.
const REACTION_TIMEOUT_SECS: f32 = 60.0;

/// The RGB stock files, which is where `accept_transfer_consignment` writes. Their growth is the
/// evidence that the wallet was mutated before the consignment's contents were looked at.
fn stock_entries(snapshot: &DirSnapshot) -> Vec<(String, u64)> {
    snapshot
        .paths_matching(|p| p.contains("/rgb/") && p.ends_with(".dat"))
        .into_iter()
        .map(|p| {
            let size = snapshot.get(&p).expect("path came from this snapshot").size;
            (p, size)
        })
        .collect()
}

fn print_stock(label: &str, snapshot: &DirSnapshot) {
    println!("{label}:");
    for (path, size) in stock_entries(snapshot) {
        println!("  {path}: {size} bytes");
    }
}

/// Total bytes of the RGB stock, a single number to compare two snapshots by.
fn stock_size(snapshot: &DirSnapshot) -> u64 {
    stock_entries(snapshot).iter().map(|(_, size)| size).sum()
}

/// The consignment files a node holds in `.ldk/`, as `(relative path, sha256)`.
fn consignments(snapshot: &DirSnapshot) -> Vec<(String, String)> {
    snapshot
        .paths_matching(|p| {
            p.rsplit('/')
                .next()
                .unwrap_or(p)
                .starts_with("consignment_")
        })
        .into_iter()
        .map(|p| {
            let hash = snapshot
                .get(&p)
                .expect("path came from this snapshot")
                .sha256
                .clone()
                .expect("consignments are hashed by the snapshot");
            (p, hash)
        })
        .collect()
}

/// Every `consignment_out` rgb-lib has written under a node's wallet directory. This is where the
/// consignment for a completed send lives, and the file the substitution hook is pointed at.
fn sent_consignment_files(node_test_dir: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = walkdir::WalkDir::new(node_test_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.file_name() == "consignment_out")
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();
    paths
}

/// `(local, remote)` asset amounts a node recorded for `channel_id`, from either the pending or
/// the final RGB channel-info file. `handle_funding` writes both, *after* the checks under test.
fn rgb_amounts_on_disk(node_test_dir: &str, channel_id: &str) -> Option<(u64, u64)> {
    let ldk_dir = PathBuf::from(node_test_dir).join(LDK_DIR);
    for name in [channel_id.to_string(), format!("{channel_id}.pending")] {
        let path = ldk_dir.join(name);
        if path.exists() {
            let info = parse_rgb_channel_info(&path);
            return Some((info.local_rgb_amount, info.remote_rgb_amount));
        }
    }
    None
}

/// `/assetbalance` for a node that may not know the contract at all. A refused open leaves the
/// acceptor in exactly that state, so the plain helper (which panics on a non-200) cannot be used.
async fn balance_or_error(node_address: SocketAddr, asset_id: &str) -> String {
    let payload = AssetBalanceRequest {
        asset_id: asset_id.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/assetbalance"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    if res.status() != reqwest::StatusCode::OK {
        return format!("refused: {}", res.text().await.unwrap());
    }
    let b = res.json::<AssetBalanceResponse>().await.unwrap();
    format!(
        "settled {} / future {} / spendable {} / offchain_out {} / offchain_in {}",
        b.settled, b.future, b.spendable, b.offchain_outbound, b.offchain_inbound
    )
}

/// Whether `/assetbalance` answers at all, i.e. whether the node's rgb-lib **database** knows the
/// contract. The RGB stock is a separate store, and the two can disagree.
async fn db_knows_asset(node_address: SocketAddr, asset_id: &str) -> bool {
    let payload = AssetBalanceRequest {
        asset_id: asset_id.to_string(),
    };
    reqwest::Client::new()
        .post(format!("http://{node_address}/assetbalance"))
        .json(&payload)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Whether a node still answers `/listchannels`. A panic inside the `ChannelManager` poisons its
/// locks, after which this stops being true.
async fn channel_manager_alive(node_address: SocketAddr) -> bool {
    reqwest::Client::new()
        .get(format!("http://{node_address}/listchannels"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn wait_for_dead_channel_manager(node_address: SocketAddr) -> bool {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if !channel_manager_alive(node_address).await {
            println!("node {node_address} no longer answers /listchannels");
            return true;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > REACTION_TIMEOUT_SECS {
            return false;
        }
        mine_n_blocks(false, 1);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Waits for `needle` to show up in a node's LDK log and returns the matching lines.
async fn wait_for_ldk_log(node_test_dir: &str, needle: &str) -> Vec<String> {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let matching: Vec<String> = ldk_log_lines(node_test_dir)
            .into_iter()
            .filter(|line| line.contains(needle))
            .collect();
        if !matching.is_empty() {
            return matching;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > REACTION_TIMEOUT_SECS {
            panic!("{node_test_dir} never logged {needle:?}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn wait_for_no_channels(node_address: SocketAddr) -> bool {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if list_channels(node_address).await.is_empty() {
            return true;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > REACTION_TIMEOUT_SECS {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn channel_summaries(node_address: SocketAddr) -> Vec<String> {
    list_channels(node_address)
        .await
        .iter()
        .map(|c| {
            format!(
                "{} {:?} ready={} local={:?} remote={:?}",
                c.channel_id, c.status, c.ready, c.asset_local_amount, c.asset_remote_amount
            )
        })
        .collect()
}

/// Wait for the initiator to persist the funding PSBT and return the transaction it built. A
/// funding the acceptor refuses is never broadcast, so the PSBT on disk is the only place it can
/// be read from.
async fn wait_for_funding_psbt(node_test_dir: &str) -> (String, Vec<TxOutput>) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let psbt_written = std::fs::read_dir(PathBuf::from(node_test_dir).join(LDK_DIR))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .any(|e| e.file_name().to_string_lossy().starts_with("psbt_"))
            })
            .unwrap_or(false);
        if psbt_written {
            return funding_psbt_outputs(node_test_dir);
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > REACTION_TIMEOUT_SECS {
            panic!("{node_test_dir} never persisted a funding PSBT");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// The index of the only P2WSH output worth `capacity_sat` — the channel output — found without
/// assuming anything about the layout.
fn channel_output_index(outputs: &[TxOutput], capacity_sat: u64) -> u16 {
    let matches: Vec<u16> = outputs
        .iter()
        .filter(|o| o.script_type == "witness_v0_scripthash" && o.sats == capacity_sat)
        .map(|o| o.index as u16)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one P2WSH output of {capacity_sat} sat, got {matches:?}"
    );
    matches[0]
}

/// Resets [`DECOY_INFLATION_ASSIGNMENT`] on drop, so a panicking test cannot leak it into the
/// next one.
struct InflationDecoyGuard;

impl InflationDecoyGuard {
    fn set() -> Self {
        DECOY_INFLATION_ASSIGNMENT.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for InflationDecoyGuard {
    fn drop(&mut self) {
        DECOY_INFLATION_ASSIGNMENT.store(false, Ordering::SeqCst);
    }
}

/// Points [`SUBSTITUTE_CONSIGNMENT_ON_NODE`] at a node and a file, and clears both on drop.
struct SubstituteConsignmentGuard(#[allow(dead_code)] NodeOverrideGuard);

impl SubstituteConsignmentGuard {
    fn set(node_pubkey: &str, path: &Path) -> Self {
        *SUBSTITUTE_CONSIGNMENT_PATH.lock().unwrap() = Some(path.to_path_buf());
        Self(NodeOverrideGuard::set(
            &SUBSTITUTE_CONSIGNMENT_ON_NODE,
            node_pubkey,
        ))
    }
}

impl Drop for SubstituteConsignmentGuard {
    fn drop(&mut self) {
        // the node override goes first: the inner `NodeOverrideGuard` only runs after this body,
        // so clearing the path first would leave a window where the node is still flagged as a
        // substituter with no path, which the `FundingGenerationReady` handler `expect`s on
        *SUBSTITUTE_CONSIGNMENT_ON_NODE
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *SUBSTITUTE_CONSIGNMENT_PATH
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Baseline: a successful colored open, so the state the rejection runs leave on the acceptor can
/// be told apart from what every open produces. The acceptor imports the contract on the happy
/// path too — the difference is whether a channel backs the import.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn baseline_a_good_open_imports_the_contract_and_keeps_the_channel() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}baseline/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let before = snapshot_node_dir("node2 before the open", &test_dir_node2);
    print_stock("node2 RGB stock before", &before);
    assert!(
        !db_knows_asset(node2_addr, &asset_id).await,
        "the acceptor starts out not knowing the contract"
    );

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CAPACITY_SAT),
        None,
        Some(CHAN_ASSET_AMT),
        Some(&asset_id),
    )
    .await;

    let after = snapshot_node_dir("node2 after the open", &test_dir_node2);
    println!("\n=== node2 (acceptor), successful open ===");
    before.diff(&after).rgb_only().print();
    print_stock("node2 RGB stock after", &after);
    println!(
        "node2 balance after: {}",
        balance_or_error(node2_addr, &asset_id).await
    );
    println!("node2 consignments after: {:?}", consignments(&after));

    assert!(channel.ready, "the baseline channel should be ready");
    assert_eq!(
        list_channels(node2_addr).await[0].asset_remote_amount,
        Some(CHAN_ASSET_AMT),
        "the acceptor credits the channel with what was actually sent"
    );

    // the acceptor's RGB stock grows on the happy path too, so growth by itself proves nothing —
    // what the rejection runs add is growth with no channel to show for it
    assert!(
        stock_size(&after) > stock_size(&before),
        "the acceptor imports the contract when it accepts the funding consignment"
    );
    // and here the import is backed by a channel and by an rgb-lib database that agrees
    assert!(
        db_knows_asset(node2_addr, &asset_id).await,
        "after a successful open the acceptor's database knows the contract"
    );
    assert_eq!(
        asset_balance(node2_addr, &asset_id).await.offchain_inbound,
        CHAN_ASSET_AMT
    );

    shutdown(&[node1_addr, node2_addr]).await;
}

/// node1 first makes an ordinary on-chain send to node3, which leaves a valid consignment on its
/// disk. It then opens a colored channel to node2 and puts *that* file on the p2p link instead of
/// the one for its funding transaction. The consignment is valid, so `accept_transfer_consignment`
/// succeeds and mutates node2's wallet; only afterwards does `handle_funding` notice it assigns
/// nothing to the funding output.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn acceptor_imports_an_unrelated_consignment_before_rejecting_the_funding() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}substituted/");
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
    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // an ordinary send to a third party, only so that node1 ends up holding a consignment that is
    // valid and that node2 has never seen
    println!("\n=== node1 sends {DECOY_SEND_AMT} to node3, to mint a spare consignment ===");
    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(DECOY_SEND_AMT),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(
        asset_balance_spendable(node3_addr, &asset_id).await,
        DECOY_SEND_AMT
    );

    let spare_consignments = sent_consignment_files(&test_dir_node1);
    println!(
        "node1 holds {} sent consignment(s):",
        spare_consignments.len()
    );
    for path in &spare_consignments {
        println!("  {}", path.display());
    }
    let spare = spare_consignments
        .first()
        .expect("the send to node3 left a consignment on node1's disk")
        .clone();
    let spare_sha = Sha256::hash(&std::fs::read(&spare).unwrap()).to_string();
    println!("substituting {} (sha256 {spare_sha})", spare.display());

    let before = snapshot_node_dir("node2 before the substituted open", &test_dir_node2);
    print_stock("node2 RGB stock before", &before);
    assert!(!db_knows_asset(node2_addr, &asset_id).await);

    let temporary_channel_id = {
        let _substitute = SubstituteConsignmentGuard::set(&node1_pubkey, &spare);
        let temporary_channel_id = open_channel_raw(
            node1_addr,
            &node2_pubkey,
            Some(NODE2_PEER_PORT),
            Some(CAPACITY_SAT),
            None,
            Some(CHAN_ASSET_AMT),
            Some(&asset_id),
            None,
            None,
            None,
            None,
            true,
            true,
        )
        .await
        .expect("the open request itself is accepted")
        .temporary_channel_id;

        let rejection =
            wait_for_ldk_log(&test_dir_node2, "Unexpected number of RGB assignments: 0").await;
        println!("\nnode2 rejection: {rejection:#?}");
        temporary_channel_id
    };

    let after = snapshot_node_dir("node2 after the substituted open", &test_dir_node2);
    println!("\n=== node2 (acceptor), substituted consignment ===");
    before.diff(&after).rgb_only().print();
    print_stock("node2 RGB stock after", &after);
    let held = consignments(&after);
    println!("node2 consignments after: {held:?}");
    println!(
        "node2 balance after: {}",
        balance_or_error(node2_addr, &asset_id).await
    );
    println!(
        "node2 RGB channel info for {temporary_channel_id}: {:?}",
        rgb_amounts_on_disk(&test_dir_node2, &temporary_channel_id)
    );

    // EXPECTED AFTER FIX: the acceptor validates the consignment before importing, so it never
    // stores the unrelated file node1 substituted onto the p2p link
    // 1. the acceptor must NOT be holding the attacker's bytes
    assert!(
        held.iter().all(|(_, sha)| *sha != spare_sha),
        "node2 must not be holding the unrelated file node1 sent; the consignment must be validated before it is imported"
    );

    // 2. and it ran it through its wallet before looking at it: the RGB stock grew
    println!(
        "node2 stock: {} -> {} bytes",
        stock_size(&before),
        stock_size(&after)
    );
    // EXPECTED AFTER FIX: the assignment check runs before `_accept_transfer`, so a consignment that
    // says nothing about the funding output is rejected without ever mutating the acceptor's stock
    assert!(
        stock_size(&after) == stock_size(&before),
        "the acceptor must not import the contract before the assignment check has accepted the funding"
    );

    // 3. the check then fired, so the channel never came up and nothing was bound to it
    assert!(
        wait_for_no_channels(node2_addr).await,
        "the acceptor must not keep a channel whose consignment says nothing about it"
    );
    assert_eq!(
        rgb_amounts_on_disk(&test_dir_node2, &temporary_channel_id),
        None,
        "the assignment check runs before `write_rgb_channel_info`, so no RGB info is written"
    );

    // 4. the node survives — this is a close, not a panic
    assert!(
        channel_manager_alive(node2_addr).await,
        "a zero-assignment consignment closes the channel rather than killing the node"
    );

    // EXPECTED AFTER FIX: a rejected open leaves neither store knowing the contract, so they agree
    assert!(
        !db_knows_asset(node2_addr, &asset_id).await,
        "a rejected open must leave the acceptor's database not knowing the contract"
    );

    println!("\n=== restarting node2 to see what survives ===");
    shutdown(&[node2_addr]).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let restarted = snapshot_node_dir("node2 after a restart", &test_dir_node2);
    println!(
        "node2 consignments after the restart: {:?}",
        consignments(&restarted)
    );
    println!(
        "node2 balance after the restart: {}",
        balance_or_error(node2_addr, &asset_id).await
    );
    // EXPECTED AFTER FIX: a refused funding leaves no consignment residue, even across a restart
    assert!(
        consignments(&restarted)
            .iter()
            .all(|(_, sha)| *sha != spare_sha),
        "a refused funding must leave no unrelated consignment on the acceptor, even across a restart"
    );
    // EXPECTED AFTER FIX: nothing was imported, so no contract residue survives a restart either
    assert!(
        stock_size(&restarted) <= stock_size(&before),
        "a refused funding must leave no imported contract on the acceptor, even across a restart"
    );

    // and the practical damage test: can this acceptor still take a real channel for this asset?
    println!("\n=== a good open for the same asset, after the rejection ===");
    let good = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CAPACITY_SAT),
        None,
        Some(CHAN_ASSET_AMT),
        Some(&asset_id),
    )
    .await;
    println!("node2 channels: {:?}", channel_summaries(node2_addr).await);
    assert!(
        good.ready,
        "the leftover state must not block a later channel for the same asset"
    );
    assert_eq!(
        list_channels(node2_addr).await[0].asset_remote_amount,
        Some(CHAN_ASSET_AMT)
    );
    assert_eq!(
        asset_balance(node2_addr, &asset_id).await.offchain_inbound,
        CHAN_ASSET_AMT,
        "and the acceptor's balance is the channel's, not the channel's plus the accepted transfer"
    );

    shutdown(&[node1_addr, node2_addr, node3_addr]).await;
}

/// `remote_rgb_assignments[0]` is matched with `_ => unreachable!("unsupported schema")`, and
/// `Assignment` has four variants.
///
/// node1 issues an IFA asset — the one schema that has inflation rights — and puts an
/// `InflationRight` on an output of its own placed in front of the channel output, so the
/// assignment the acceptor finds at its hard-coded vout 1 is one the match has no arm for. The
/// channel output itself keeps a proper fungible amount, which is what lets the initiator colour
/// its own commitment and get as far as sending `funding_created`.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn unsupported_assignment_variant_panics_the_acceptor() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}inflation_decoy/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_ifa(node1_addr).await.asset_id;
    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    println!(
        "node1 balance: {}",
        balance_or_error(node1_addr, &asset_id).await
    );

    let before = snapshot_node_dir("node2 before the open", &test_dir_node2);
    print_stock("node2 RGB stock before", &before);

    let _decoy = NodeOverrideGuard::set(&DECOY_FUNDING_OUTPUT_ON_NODE, &node1_pubkey);
    let _inflation = InflationDecoyGuard::set();

    println!("\nopening an IFA channel with an inflation right on the output in front of it");
    let temporary_channel_id = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CAPACITY_SAT),
        None,
        Some(CHAN_ASSET_AMT),
        Some(&asset_id),
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await
    .expect("the open request itself is accepted")
    .temporary_channel_id;

    let (funding_txid, outputs) = wait_for_funding_psbt(&test_dir_node1).await;
    let index = channel_output_index(&outputs, CAPACITY_SAT);
    print_outputs("funding transaction", &funding_txid, &outputs, Some(index));
    assert!(outputs[0].is_op_return());
    assert_eq!(
        outputs[ACCEPTOR_ASSUMED_VOUT].sats, DECOY_OUTPUT_SAT,
        "vout {ACCEPTOR_ASSUMED_VOUT} carries the inflation right, not the channel"
    );
    assert_eq!(
        index, 2,
        "the channel output, which holds the fungible amount, is at vout 2"
    );

    // EXPECTED AFTER FIX: the acceptor reaches `handle_funding`, finds an assignment variant it has
    // no channel use for, and rejects the funding cleanly instead of hitting `unreachable!` — so its
    // `ChannelManager` never panics and keeps answering.
    assert!(
        !wait_for_dead_channel_manager(node2_addr).await,
        "an assignment variant the match has no arm for must be rejected cleanly, not crash the acceptor's ChannelManager"
    );

    let after = snapshot_node_dir("node2 after the panic", &test_dir_node2);
    println!("\n=== node2 (acceptor), inflation-right assignment ===");
    before.diff(&after).rgb_only().print();
    print_stock("node2 RGB stock after", &after);
    println!("node2 consignments after: {:?}", consignments(&after));
    println!(
        "node2 RGB channel info for {temporary_channel_id}: {:?}",
        rgb_amounts_on_disk(&test_dir_node2, &temporary_channel_id)
    );
    println!(
        "node1 channels: {:?}\nnode1 balance: {}",
        channel_summaries(node1_addr).await,
        balance_or_error(node1_addr, &asset_id).await
    );

    // the wallet mutation happened before the panic, exactly as in the zero-assignment run
    // EXPECTED AFTER FIX: the assignment variant is checked before `_accept_transfer`, so a rejected
    // funding leaves the acceptor's stock unchanged
    assert!(
        stock_size(&after) == stock_size(&before),
        "the acceptor must not import the consignment before the assignment variant has been accepted"
    );
    // EXPECTED AFTER FIX: a rejected funding writes no RGB channel info
    assert_eq!(
        rgb_amounts_on_disk(&test_dir_node2, &temporary_channel_id),
        None,
        "a rejected funding must leave no RGB channel info bound to the channel"
    );
    // EXPECTED AFTER FIX: a rejected funding leaves no consignment residue on the acceptor
    assert!(
        consignments(&after).is_empty(),
        "a rejected funding must leave no consignment on the acceptor's disk"
    );

    // the initiator is not the one that misbehaved from LDK's point of view; it stays alive
    assert!(
        channel_manager_alive(node1_addr).await,
        "the initiator survives the rejected open"
    );
}
