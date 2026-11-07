use super::*;

const TEST_DIR_BASE: &str = "tmp/junk_consignment_vanilla_bypass/";
const JUNK_CONSIGNMENT_PANIC: &str = "successful consignment load";

static LDK_PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static RECORD_LDK_PANICS: Once = Once::new();

// Only the binary exits on a panic, so an in-process node needs this for one to be noticed
fn record_ldk_panics() {
    RECORD_LDK_PANICS.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info
                .location()
                .is_some_and(|location| location.file().ends_with("src/ldk.rs"))
            {
                LDK_PANICS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(info.to_string());
            }
            default_hook(info);
        }));
    });
}

fn ldk_panicked() -> bool {
    !LDK_PANICS.lock().unwrap().is_empty()
}

fn take_ldk_panics() -> Vec<String> {
    std::mem::take(&mut *LDK_PANICS.lock().unwrap())
}

// Waits for the channel to be usable, then pays over it, which needs the victim to keep handling
// events. Gives up on a panic, which the caller asserts on after the restart.
async fn pay_victim(attacker_addr: SocketAddr, victim_addr: SocketAddr, victim_pubkey: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if ldk_panicked() {
            return;
        }
        if node_info(attacker_addr).await.num_usable_channels == 1
            && node_info(victim_addr).await.num_usable_channels == 1
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("channel is not becoming usable");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    keysend(attacker_addr, victim_pubkey, None, None, None).await;
}

// Runs the attack, then restarts the victim, asserting it never panics and the channel stays
// usable. With `unfunded_colored_channel` the attacker first opens a colored channel to the victim
// and never funds it, which lets its files past the transport's gate: the files name their own
// funding txid, so only `ChannelPending` learns that it belongs to a vanilla channel
async fn junk_consignment_attack(test_name: &str, unfunded_colored_channel: bool) {
    initialize();
    record_ldk_panics();
    take_ldk_panics();

    let victim_dir = format!("{TEST_DIR_BASE}{test_name}/victim");
    let attacker_dir = format!("{TEST_DIR_BASE}{test_name}/attacker");
    let (victim_addr, _) = start_node(&victim_dir, NODE2_PEER_PORT, false).await;
    let (attacker_addr, _) = start_node(&attacker_dir, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(attacker_addr, None).await;
    let victim_pubkey = node_info(victim_addr).await.pubkey;
    let attacker_pubkey = node_info(attacker_addr).await.pubkey;

    // the victim accepts it before the vanilla channel below, so it is pending when the junk comes
    let _unfunded_guard = if unfunded_colored_channel {
        let guard = NodeOverrideGuard::set(&LEAVE_COLORED_OPEN_UNFUNDED_ON_NODE, &attacker_pubkey);
        let asset_id = issue_asset_nia(attacker_addr).await.asset_id;
        open_channel_raw(
            attacker_addr,
            &victim_pubkey,
            Some(NODE2_PEER_PORT),
            None,
            None,
            Some(100),
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
        Some(guard)
    } else {
        None
    };

    // `open_channel_raw` just sends the request and returns, unlike `open_channel`, which would
    // fail on the panic before the restart below can run
    let _inject_guard = NodeOverrideGuard::set(
        &INJECT_FAKE_CONSIGNMENT_ON_VANILLA_OPEN_ON_NODE,
        &attacker_pubkey,
    );
    open_channel_raw(
        attacker_addr,
        &victim_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await
    .unwrap();

    // the attacker broadcasts the funding TX once the victim has accepted the funding
    let t_0 = OffsetDateTime::now_utc();
    while !ldk_panicked() {
        let funding_txid = list_channels(attacker_addr)
            .await
            .into_iter()
            .find_map(|channel| channel.funding_txid);
        if let Some(funding_txid) = funding_txid.filter(|txid| !get_txout(txid).is_empty()) {
            let victim_channels = list_channels(victim_addr).await;
            assert!(victim_channels
                .iter()
                .any(|channel| channel.funding_txid.as_ref() == Some(&funding_txid)));
            mine_n_blocks(false, 6);
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 50.0 {
            panic!("channel was not funded");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    pay_victim(attacker_addr, victim_addr, &victim_pubkey).await;
    let first_run_panics = take_ldk_panics();

    // crash loop check: restart whether or not the victim panicked, no attack repeated
    shutdown(&[victim_addr]).await;
    let (victim_addr, _) = start_node(&victim_dir, NODE2_PEER_PORT, true).await;
    pay_victim(attacker_addr, victim_addr, &victim_pubkey).await;
    let second_run_panics = take_ldk_panics();

    for panics in [&first_run_panics, &second_run_panics] {
        assert!(
            panics.is_empty() || panics.iter().any(|p| p.contains(JUNK_CONSIGNMENT_PANIC)),
            "victim panicked for an unexpected reason: {panics:?}"
        );
    }
    assert!(
        first_run_panics.is_empty() && second_run_panics.is_empty(),
        "victim panicked\nfirst run: {first_run_panics:?}\nsecond run: {second_run_panics:?}"
    );
}

/// A peer opens a vanilla channel and sends a junk consignment tagged with its funding txid.
/// The victim must not panic on the junk or after a restart, and the channel must stay usable.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn junk_consignment_vanilla_bypass() {
    junk_consignment_attack("vanilla_bypass", false).await;
}

/// The same, from a peer that also opened a colored channel to the victim, which it never funds.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn junk_consignment_vanilla_bypass_with_colored_channel() {
    junk_consignment_attack("with_colored_channel", true).await;
}
