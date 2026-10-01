use super::*;

use std::fs::File;
use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

const TEST_DIR_BASE: &str = "tmp/junk_consignment_vanilla_bypass/";
const VICTIM_PEER_PORT: u16 = 9820;

// Picks a free TCP port by binding then releasing it. Small race, but harmless here.
fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

// Builds and locates the real `rgb-lightning-node` binary. We need the actual OS process here --
// the rest of the suite runs nodes in-process via `app(args)`, which never hits the real panic
// hook / `std::process::exit`. Read the path from cargo's own `--message-format=json` output
// rather than guessing from `current_exe()`'s ancestors, since the two can land in different
// `--target-dir`s (e.g. under `cargo llvm-cov`).
fn victim_binary_path() -> PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        println!("building rgb-lightning-node binary for the vanilla-bypass repro...");
        let output = StdCommand::new("cargo")
            .args([
                "build",
                "--bin",
                "rgb-lightning-node",
                "--message-format=json",
            ])
            .output()
            .expect("failed to invoke cargo build");
        assert!(
            output.status.success(),
            "failed to build the rgb-lightning-node binary: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find_map(|msg| {
                if msg.get("reason")?.as_str()? != "compiler-artifact" {
                    return None;
                }
                if msg.get("target")?.get("name")?.as_str()? != "rgb-lightning-node" {
                    return None;
                }
                msg.get("executable")?.as_str().map(PathBuf::from)
            })
            .expect("cargo build did not report an executable path for rgb-lightning-node")
    })
    .clone()
}

// Kills the wrapped subprocess on drop, so a failed assertion doesn't leak it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_daemon_port_ready(port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!("victim daemon port {port} did not accept connections in time: {err}")
            }
        }
    }
}

// Launches the node binary against `storage_dir`, logging to a file (not a pipe, to avoid
// blocking on a full buffer) so we can inspect its panic message afterward.
fn spawn_victim(storage_dir: &str, daemon_port: u16) -> KillOnDrop {
    std::fs::create_dir_all(storage_dir).unwrap();
    let log = File::create(format!("{storage_dir}/subprocess.log")).unwrap();
    let child = StdCommand::new(victim_binary_path())
        .arg(storage_dir)
        .args(["--network", "regtest"])
        .args(["--daemon-listening-port", &daemon_port.to_string()])
        .args(["--ldk-peer-listening-port", &VICTIM_PEER_PORT.to_string()])
        .arg("--disable-authentication")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("failed to spawn victim node subprocess");
    KillOnDrop(child)
}

// Polls for exit within `timeout`. `None` (still running) is the expected, correct outcome.
async fn wait_for_exit(
    victim: &mut KillOnDrop,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = victim.0.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// SECURITY REPRO: a remote peer can crash the node by attaching a fake "consignment" to an
/// ordinary, uncolored (vanilla) channel open.
///
/// Asserts the correct behavior -- a vanilla channel open can never crash the node -- so this
/// FAILS against the code as it stands today, and will only pass once the bug is fixed.
///
/// Why: `handle_funding` validates a *colored* channel's consignment and cleanly force-closes on
/// bad content, but only runs when the channel is colored. `rgb_file_transfer.rs`'s chunk
/// acceptor has no such check -- it only requires that the sender has *a* channel with us. So a
/// peer can open a vanilla channel and separately send garbage over the same p2p file-transfer
/// link, tagged with that channel's funding txid. `ChannelPending` then decides whether to load a
/// consignment purely by `consignment_path.exists()`, with no link back to whether `handle_funding`
/// ever ran -- so it loads the junk and panics.
///
/// `INJECT_FAKE_CONSIGNMENT_ON_VANILLA_OPEN_ON_NODE` models the attacker side: a peer fully in
/// control of their own node sending bogus chunks their REST/RGB layer would never construct.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn junk_consignment_vanilla_bypass() {
    initialize();

    let victim_dir = format!("{TEST_DIR_BASE}victim");
    let attacker_dir = format!("{TEST_DIR_BASE}attacker");
    if Path::new(&victim_dir).is_dir() {
        std::fs::remove_dir_all(&victim_dir).unwrap();
    }

    let daemon_port = free_port();
    let mut victim = spawn_victim(&victim_dir, daemon_port);
    wait_for_daemon_port_ready(daemon_port).await;
    let victim_addr = SocketAddr::from(([127, 0, 0, 1], daemon_port));

    let password = "junk-consignment-vanilla-bypass";
    init(victim_addr, password, None).await;
    unlock(victim_addr, password).await;
    let victim_pubkey = node_info(victim_addr).await.pubkey;

    // attacker: an ordinary node, hooked to send a fake consignment alongside a vanilla open --
    // no asset ever issued or involved.
    let (attacker_addr, _) = start_node(&attacker_dir, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(attacker_addr, None).await;
    let attacker_pubkey = node_info(attacker_addr).await.pubkey;
    let _inject_guard = NodeOverrideGuard::set(
        &INJECT_FAKE_CONSIGNMENT_ON_VANILLA_OPEN_ON_NODE,
        &attacker_pubkey,
    );

    // open a plain vanilla channel attacker -> victim; auto-accepted, no mining needed since
    // `ChannelPending` fires on funding-message exchange, before any on-chain confirmation.
    // `open_channel_raw` just sends the request and returns, unlike `open_channel`/
    // `open_channel_funded_raw`, which poll channel status and would hang once the victim is dead.
    let open_result = tokio::time::timeout(
        Duration::from_secs(30),
        open_channel_raw(
            attacker_addr,
            &victim_pubkey,
            Some(VICTIM_PEER_PORT),
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
        ),
    )
    .await;
    println!("open_channel outcome while attacking the victim: {open_result:?}");

    // must survive: any exit here means it crashed loading the attacker's junk.
    if let Some(status) = wait_for_exit(&mut victim, Duration::from_secs(60)).await {
        let log =
            std::fs::read_to_string(format!("{victim_dir}/subprocess.log")).unwrap_or_default();
        panic!(
            "SECURITY BUG: a vanilla channel open + an injected fake consignment crashed the \
             victim (exit status: {status:?}). A remote peer can crash this node by opening an \
             ordinary, uncolored channel and separately sending garbage over the p2p \
             file-transfer link -- see ChannelPending's acceptor branch in src/ldk.rs, which \
             decides whether to load a consignment purely by consignment_path.exists(), with no \
             link back to whether handle_funding ever validated anything for this channel.\n\n\
             log:\n{log}"
        );
    }
    let info = node_info(victim_addr).await;
    println!(
        "confirmed: the victim survived the attack and is still responsive, pubkey {}",
        info.pubkey
    );

    // crash loop check: relaunch against the same data dir, no attack repeated.
    victim.0.kill().unwrap();
    victim.0.wait().unwrap();
    let daemon_port_2 = free_port();
    let mut victim_2 = spawn_victim(&victim_dir, daemon_port_2);
    wait_for_daemon_port_ready(daemon_port_2).await;
    let victim_addr_2 = SocketAddr::from(([127, 0, 0, 1], daemon_port_2));
    unlock(victim_addr_2, password).await;

    if let Some(status) = wait_for_exit(&mut victim_2, Duration::from_secs(30)).await {
        let log_2 =
            std::fs::read_to_string(format!("{victim_dir}/subprocess.log")).unwrap_or_default();
        panic!(
            "SECURITY BUG: the victim crashed again on restart (exit status: {status:?}), with \
             no attack repeated -- the node is bricked in a crash loop until the on-disk junk \
             consignment (or the channel state referencing it) is removed by hand.\n\nlog:\n{log_2}"
        );
    }
    let info_2 = node_info(victim_addr_2).await;
    println!(
        "confirmed: the victim also restarted cleanly, with no crash loop, pubkey {}",
        info_2.pubkey
    );
}
