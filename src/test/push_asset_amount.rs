//! A peer-supplied `push_asset_amount` must be validated on the acceptor.
//!
//! `push_asset_amount` rides on `open_channel` as part of the RGB TLV
//! (`rgb_asset: Option<(ContractId, Option<u64>)>` in `rust-lightning/lightning/src/ln/msgs.rs`).
//! The acceptor stores it verbatim on the inbound channel and reads it back in `handle_funding`
//! (`rgb_utils/mod.rs`), where `channel_rgb_amount.checked_sub(push_amount)` rejects a push
//! larger than what the funding output holds. It used to be an unchecked subtraction that
//! panicked the peer-message path (debug) or wrapped (release); these tests keep that covered.
//! The only other check lives in the *sender's* REST layer, so the sender has to be hostile to
//! reach the acceptor-side one.
//!
//! The fault is injected with [`FORCE_PUSH_ASSET_AMOUNT_ON_NODE`]: the named node puts
//! `asset_amount + 1` on the wire while its own channel accounting keeps the honest value — the
//! freedom any peer has, since the guard that would have stopped it runs on the sender, in code
//! a hostile peer is not running. Nothing is patched on the victim.

use lightning::rgb_utils::parse_rgb_channel_info;

use crate::ldk::FORCE_PUSH_ASSET_AMOUNT_ON_NODE;

use super::repro_util::snapshot_node_dir;
use super::*;

const TEST_DIR_BASE: &str = "tmp/push_asset_amount/";

/// RGB amount the channel is funded with — what the consignment really assigns to the funding
/// output, and what the acceptor's `channel_rgb_amount` is.
const CHAN_ASSET_AMT: u64 = 600;

/// A legal push, used for the baseline run.
const HONEST_PUSH: u64 = 250;

/// An oversized push for the REST-guard check; the wire-level hostile push is
/// `CHAN_ASSET_AMT + 1`, hard-coded by [`FORCE_PUSH_ASSET_AMOUNT_ON_NODE`].
const HOSTILE_PUSH: u64 = 1_000;

const CAPACITY_SAT: u64 = 100_000;

/// How long to wait for a node to act on a message it has just been sent.
const REACTION_TIMEOUT_SECS: f32 = 90.0;

/// RGB channel info is written to `.ldk/<channel_id>` and `.ldk/<channel_id>.pending`. Both the
/// temporary and the final channel ID can name one, so a scenario that does not know which ID a
/// node settled on reads them all.
fn channel_info_files(node_test_dir: &str) -> Vec<(String, u64, u64)> {
    let ldk_dir = PathBuf::from(node_test_dir).join(LDK_DIR);
    let Ok(entries) = std::fs::read_dir(&ldk_dir) else {
        return vec![];
    };
    let mut infos: Vec<(String, u64, u64)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let stem = name.strip_suffix(".pending").unwrap_or(&name);
            if stem.len() != 64 || !stem.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let info = parse_rgb_channel_info(&e.path());
            Some((name, info.local_rgb_amount, info.remote_rgb_amount))
        })
        .collect();
    infos.sort();
    infos
}

/// `(local, remote)` asset amounts a node recorded for `channel_id` in `.ldk/<channel_id>`,
/// falling back to the `.pending` file the acceptor writes first.
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

/// `/listchannels`, tolerating a node whose `ChannelManager` no longer answers.
async fn channel_summaries(node_address: SocketAddr) -> Vec<String> {
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/listchannels"))
        .send()
        .await;
    let Ok(res) = res else {
        return vec![s!("<node does not answer /listchannels>")];
    };
    if !res.status().is_success() {
        return vec![format!("<listchannels failed: {}>", res.status())];
    }
    res.json::<ListChannelsResponse>()
        .await
        .map(|r| {
            r.channels
                .iter()
                .map(|c| {
                    format!(
                        "{} ready={} local_asset={:?} remote_asset={:?} status={:?}",
                        c.channel_id,
                        c.ready,
                        c.asset_local_amount,
                        c.asset_remote_amount,
                        c.status
                    )
                })
                .collect()
        })
        .unwrap_or_else(|e| vec![format!("<unparseable listchannels: {e}>")])
}

/// `/assetbalance` for a node that may not know the contract, or may be dead.
async fn balance_line(node_address: SocketAddr, asset_id: &str) -> String {
    let payload = AssetBalanceRequest {
        asset_id: asset_id.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/assetbalance"))
        .json(&payload)
        .send()
        .await;
    let Ok(res) = res else {
        return s!("<node does not answer /assetbalance>");
    };
    if !res.status().is_success() {
        return format!("refused: {}", res.text().await.unwrap_or_default());
    }
    match res.json::<AssetBalanceResponse>().await {
        Ok(b) => format!(
            "settled {} / future {} / spendable {} / offchain_out {} / offchain_in {}",
            b.settled, b.future, b.spendable, b.offchain_outbound, b.offchain_inbound
        ),
        Err(e) => format!("<unparseable balance: {e}>"),
    }
}

/// The funding transaction a node built for its pending channel, and whether it ever reached the
/// mempool. `None` means the node never got as far as naming one.
async fn funding_broadcast_state(node_address: SocketAddr) -> Option<(String, bool)> {
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/listchannels"))
        .send()
        .await
        .ok()?;
    let channels = res.json::<ListChannelsResponse>().await.ok()?.channels;
    let txid = channels.into_iter().find_map(|c| c.funding_txid)?;
    let in_mempool = !get_txout(&txid).is_empty();
    Some((txid, in_mempool))
}

/// Panic messages raised anywhere in the process while a [`PanicCapture`] is installed. The nodes
/// run in-process, so a panic on a node's peer-message path lands here rather than in its LDK log
/// or in the tracing output — and *which* panic fires is the whole difference between the two
/// build profiles.
static CAPTURED_PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The panic hook that was installed before a [`PanicCapture`] took over.
type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send>;

/// Records every panic message for the lifetime of the guard, chaining to the hook that was
/// installed before so the test harness still reports failures normally.
struct PanicCapture {
    previous: Option<std::sync::Arc<PanicHook>>,
}

impl PanicCapture {
    fn install() -> Self {
        CAPTURED_PANICS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let previous = std::sync::Arc::new(std::panic::take_hook());
        let chained = previous.clone();
        std::panic::set_hook(Box::new(move |info| {
            CAPTURED_PANICS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("{info}"));
            chained(info);
        }));
        Self {
            previous: Some(previous),
        }
    }

    fn messages() -> Vec<String> {
        CAPTURED_PANICS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The first captured panic mentioning `needle`, if any.
    fn matching(needle: &str) -> Option<String> {
        Self::messages().into_iter().find(|m| m.contains(needle))
    }
}

impl Drop for PanicCapture {
    fn drop(&mut self) {
        // `take_hook`/`set_hook` abort the process when called from a panicking thread, and a
        // failing assertion in a test that holds one of these is exactly that thread. Leaving the
        // hook installed is harmless: it chains to the one it replaced and `install` clears the log.
        if std::thread::panicking() {
            return;
        }
        let _ = std::panic::take_hook();
        if let Some(previous) = self.previous.take() {
            match std::sync::Arc::try_unwrap(previous) {
                Ok(hook) => std::panic::set_hook(hook),
                Err(shared) => std::panic::set_hook(Box::new(move |info| shared(info))),
            }
        }
    }
}

fn print_panics(label: &str) {
    let messages = PanicCapture::messages();
    println!("{label}: {} panic(s)", messages.len());
    for message in &messages {
        for line in message.lines() {
            println!("  {line}");
        }
    }
}

fn print_ldk_tail(label: &str, node_test_dir: &str, needle: &str) {
    let lines: Vec<String> = ldk_log_lines(node_test_dir)
        .into_iter()
        .filter(|l| l.contains(needle))
        .collect();
    println!("{label} ({} line(s) matching {needle:?}):", lines.len());
    for line in lines.iter().rev().take(10).rev() {
        println!("  {line}");
    }
}

/// Baseline: the sender's REST guard refuses an oversized push at request level, and a legal
/// push produces the split both sides agree on.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn baseline_rest_guard_refuses_oversized_push_and_a_legal_push_splits() {
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

    // the guard: with the hook unset, the initiator refuses to send a push it cannot back
    println!("\n=== the sender's own REST guard, hook unset ===");
    let refused = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CAPACITY_SAT),
        None,
        Some(CHAN_ASSET_AMT),
        Some(&asset_id),
        Some(HOSTILE_PUSH),
        None,
        None,
        None,
        true,
        true,
    )
    .await;
    let response = refused.expect_err("the REST guard rejects a push larger than the amount");
    check_response_is_nok(
        *response,
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid amount: push_asset_amount cannot be higher than asset_amount",
        "InvalidAmount",
    )
    .await;
    assert!(
        list_channels(node1_addr).await.is_empty(),
        "the refused request must not have created a channel"
    );
    assert!(list_channels(node2_addr).await.is_empty());

    // the legal case, for comparison: the acceptor's `channel_rgb_amount - push_amount` with a
    // push the channel can actually back
    println!("\n=== a legal push of {HONEST_PUSH} out of {CHAN_ASSET_AMT} ===");
    let channel = open_channel_with_custom_data(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(CAPACITY_SAT),
        None,
        Some(CHAN_ASSET_AMT),
        Some(&asset_id),
        Some(HONEST_PUSH),
        None,
        None,
        None,
        true,
    )
    .await;

    let node1_amounts = rgb_amounts_on_disk(&test_dir_node1, &channel.channel_id);
    let node2_amounts = rgb_amounts_on_disk(&test_dir_node2, &channel.channel_id);
    println!("node1 (initiator) RGB channel info: {node1_amounts:?}");
    println!("node2 (acceptor)  RGB channel info: {node2_amounts:?}");
    println!("node1 channels: {:?}", channel_summaries(node1_addr).await);
    println!("node2 channels: {:?}", channel_summaries(node2_addr).await);

    assert_eq!(
        node1_amounts,
        Some((CHAN_ASSET_AMT - HONEST_PUSH, HONEST_PUSH)),
        "the initiator keeps what it did not push"
    );
    assert_eq!(
        node2_amounts,
        Some((HONEST_PUSH, CHAN_ASSET_AMT - HONEST_PUSH)),
        "the acceptor's arithmetic on a legal push: local = push, remote = amount - push"
    );

    // and the two sides' books add up to the amount the funding output holds
    let (node2_local, node2_remote) = node2_amounts.unwrap();
    assert_eq!(
        node2_local + node2_remote,
        CHAN_ASSET_AMT,
        "on the happy path the acceptor's two amounts sum to the channel's asset amount"
    );
}

/// node1 sends an `open_channel` whose `push_asset_amount` exceeds the RGB amount its
/// consignment assigns to the funding output; node2 must reject it cleanly, leaving no RGB
/// residue and taking neither node down.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn acceptor_takes_an_inflated_push_asset_amount_from_a_hostile_peer() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}inflated_push/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let node2_before = snapshot_node_dir("node2 before the open", &test_dir_node2);
    println!(
        "\nnode1 balance before: {}",
        balance_line(node1_addr, &asset_id).await
    );
    println!(
        "node2 balance before: {}",
        balance_line(node2_addr, &asset_id).await
    );

    println!(
        "\n=== node1 opens a {CHAN_ASSET_AMT}-asset channel but claims to push {} ===",
        CHAN_ASSET_AMT + 1
    );
    let _panics = PanicCapture::install();
    let _hostile = NodeOverrideGuard::set(&FORCE_PUSH_ASSET_AMOUNT_ON_NODE, &node1_pubkey);

    // the request itself is honest — no push at all — so the sender's REST guard has nothing to
    // object to; only the message on the wire carries the inflated value
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
    println!("temporary channel id: {temporary_channel_id}");

    // Either way the acceptor dies on the peer-message path, with the `ChannelManager`'s
    // `per_peer_state` and `PeerState` locks held: `handle_funding` runs inside
    // `internal_funding_created`. What differs between the profiles is *where*, and therefore what
    // the acceptor has already persisted by then.
    let died = wait_for_dead_channel_manager(node2_addr).await;

    let node2_after = snapshot_node_dir("node2 after the inflated open", &test_dir_node2);
    println!("\n=== node2 (acceptor) data dir ===");
    node2_before.diff(&node2_after).rgb_only().print();
    let node1_infos = channel_info_files(&test_dir_node1);
    let node2_infos = channel_info_files(&test_dir_node2);
    println!("node1 RGB channel info files: {node1_infos:?}");
    println!("node2 RGB channel info files: {node2_infos:?}");
    println!("node1 channels: {:?}", channel_summaries(node1_addr).await);
    println!("node2 channels: {:?}", channel_summaries(node2_addr).await);
    println!(
        "node1 funding transaction: {:?}",
        funding_broadcast_state(node1_addr).await
    );
    println!(
        "node1 balance after: {}",
        balance_line(node1_addr, &asset_id).await
    );
    println!(
        "node2 balance after: {}",
        balance_line(node2_addr, &asset_id).await
    );
    print_ldk_tail("node2 log", &test_dir_node2, "funding");
    print_panics("panics raised while the open was in flight");

    // the acceptor validates push_asset_amount and rejects the open cleanly, never panicking
    // under its ChannelManager locks
    assert!(
        !died,
        "an oversized peer-supplied amount must not take the acceptor's ChannelManager down"
    );
    assert!(
        PanicCapture::matching("PoisonError").is_none(),
        "the acceptor must not panic/poison its ChannelManager locks: {:?}",
        PanicCapture::messages()
    );

    // a clean rejection takes neither node down
    assert!(
        channel_manager_alive(node1_addr).await,
        "the initiator survives the clean rejection"
    );
    // the inflated open never becomes a live channel on the initiator either: the acceptor
    // rejects it, so no channel opens ready with mis-accounted assets
    let node1_channels = channel_summaries(node1_addr).await;
    assert!(
        !node1_channels.iter().any(|c| c.contains("ready=true")),
        "the inflated open must not have opened a ready channel on the initiator: {node1_channels:?}"
    );
    // the initiator's own books stay honest — the lie only ever lived on the wire
    assert!(
        node1_infos
            .iter()
            .all(|(_, local, remote)| (*local, *remote) == (CHAN_ASSET_AMT, 0)),
        "the initiator's own books stayed honest: {node1_infos:?}"
    );
    // the funding transaction is never broadcast, so the reserved UTXO returns to the wallet
    let funding = funding_broadcast_state(node1_addr).await;
    assert!(
        funding.as_ref().is_none_or(|(_, in_mempool)| !*in_mempool),
        "the funding transaction must not be broadcast for a rejected open: {funding:?}"
    );

    // the acceptor rejects the inflated push before writing RGB channel info, so no build
    // profile persists a bad split
    assert_eq!(
        rgb_amounts_on_disk(&test_dir_node2, &temporary_channel_id),
        None,
        "the acceptor must not persist any RGB split for the rejected inflated open"
    );
    assert!(
        node2_infos.is_empty(),
        "the acceptor must record no RGB channel info for the inflated open: {node2_infos:?}"
    );
}
