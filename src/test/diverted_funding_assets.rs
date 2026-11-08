use super::*;

const TEST_DIR_BASE: &str = "tmp/diverted_funding_assets/";
// The attacker seals this much to its own decoy output and a single unit to the real funding
// output, so it needs CHAN_ASSET_AMT + 1 <= ISSUE_AMT of its own assets
const CHAN_ASSET_AMT: u64 = 400;

static COLOR_PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static RECORD_COLOR_PANICS: Once = Once::new();

// Only the binary exits on a panic, so an in-process node needs this for a panic on a worker
// thread to be noticed. Records panics raised in `color_commitment` (rgb_utils/mod.rs)
fn record_color_panics() {
    RECORD_COLOR_PANICS.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info
                .location()
                .is_some_and(|location| location.file().ends_with("rgb_utils/mod.rs"))
            {
                COLOR_PANICS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(info.to_string());
            }
            default_hook(info);
        }));
    });
}

fn take_color_panics() -> Vec<String> {
    std::mem::take(&mut *COLOR_PANICS.lock().unwrap_or_else(|e| e.into_inner()))
}

// Clears the global on drop, so a panic mid-test cannot leak it into the rest of the test binary
struct SkipColoringGuard;

impl SkipColoringGuard {
    fn set(ldk_data_dir_substring: &str) -> Self {
        *SKIP_COMMITMENT_COLORING_FOR_DIR
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(ldk_data_dir_substring.to_string());
        Self
    }
}

impl Drop for SkipColoringGuard {
    fn drop(&mut self) {
        *SKIP_COMMITMENT_COLORING_FOR_DIR
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}

// The acceptor stores a channel's RGB accounting under the temporary channel ID in its LDK data
// dir. Returns the asset amount it credited to the counterparty, if it accepted a channel at all
fn credited_remote_amount(node_test_dir: &str) -> Option<u64> {
    let ldk_data_dir = PathBuf::from(node_test_dir).join(LDK_DIR);
    for entry in std::fs::read_dir(ldk_data_dir)
        .expect("LDK data dir exists")
        .flatten()
    {
        let path = entry.path();
        // the RgbInfo files are `<temporary channel ID>` and `<temporary channel ID>.pending`
        if !path.is_file() || path.extension().is_some() {
            continue;
        }
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(info) = serde_json::from_str::<RgbInfo>(&contents) {
                return Some(info.remote_rgb_amount);
            }
        }
    }
    None
}

/// The initiator builds the funding transaction, so it decides which output the channel assets go
/// to. `_accept_transfer` hardcodes `funding_vout = 1` instead of using `msg.funding_output_index`,
/// which is what the channel itself is built on, so the acceptor validates the consignment against
/// vout 1 whatever output LDK actually treats as the funding output.
///
/// The initiator here seals a full channel's worth of assets, with the static blinding, to its own
/// address at vout 1, and leaves a single unit on the real 2-of-2 funding output at vout 2 (an
/// honest funding has the OP_RETURN at vout 0 and that funding output at vout 1). It is a modified
/// node in two ways, both driven by test-only hooks: it builds that layout, and it does not
/// honestly color its own commitments, which an honest node could not do here because its own
/// coloring would refuse the near-empty funding output.
///
/// The acceptor must neither credit the channel with the assets sitting on the initiator's own
/// output nor crash. Today it does both: it reads `CHAN_ASSET_AMT` off vout 1, records it as the
/// channel's remote amount, and then panics coloring its first commitment, which spends a funding
/// output holding only the single unit. The panic needs nothing but a `funding_created`, so it
/// lands before the funding transaction is ever broadcast, and the amount is persisted first.
///
/// So this test fails until the acceptor validates the consignment against the funding output LDK
/// uses. The correct outcome is then a channel for the one unit actually on that output, the
/// initiator having wasted the rest; refusing the channel outright is equally correct.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn diverted_funding_assets() {
    initialize();
    record_color_panics();
    take_color_panics();

    let attacker_dir = format!("{TEST_DIR_BASE}attacker");
    let victim_dir = format!("{TEST_DIR_BASE}victim");
    let (attacker_addr, _) = start_node(&attacker_dir, NODE1_PEER_PORT, false).await;
    let (victim_addr, _) = start_node(&victim_dir, NODE2_PEER_PORT, false).await;
    fund_and_create_utxos(attacker_addr, None).await;
    let attacker_pubkey = node_info(attacker_addr).await.pubkey;
    let victim_pubkey = node_info(victim_addr).await.pubkey;

    let asset_id = issue_asset_nia(attacker_addr).await.asset_id;

    // the attacker is a modified node: it diverts the channel assets to its own output...
    let _divert_guard =
        NodeOverrideGuard::set(&DIVERT_COLORED_FUNDING_ASSETS_ON_NODE, &attacker_pubkey);
    // ...and doesn't honestly color its own commitments, so it doesn't panic on the near-empty
    // funding output (a real attacker runs arbitrary code; this models that minimally). Keyed on
    // the attacker's own data dir, so a panic recorded below can only be the victim's
    let _skip_guard = SkipColoringGuard::set(&attacker_dir);

    // `open_channel_raw` just sends the request and returns, unlike `open_channel`, which would
    // wait for a channel that never becomes usable here
    open_channel_raw(
        attacker_addr,
        &victim_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100_000),
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
    .unwrap();

    // let the attack play out: the victim handles the funding, then colors its first commitment
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let panicked = !COLOR_PANICS.lock().unwrap().is_empty();
        if panicked || credited_remote_amount(&victim_dir).is_some() {
            // the coloring follows the funding handling, so give it a moment to run
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let credited = credited_remote_amount(&victim_dir);
    let panics = take_color_panics();

    assert!(
        panics.is_empty(),
        "the victim panicked, so a peer funding a colored channel can crash it: {panics:?}"
    );
    assert_ne!(
        credited,
        Some(CHAN_ASSET_AMT),
        "the victim credited the channel with the {CHAN_ASSET_AMT} assets sealed to the \
         attacker's own output at vout 1, while the funding output LDK uses (vout 2) holds 1"
    );
}
