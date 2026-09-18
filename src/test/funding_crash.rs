use super::*;

use crate::ldk::FUNDING_CHECKPOINT_AFTER_COLOR;

const TEST_DIR_BASE: &str = "tmp/funding_crash/";

/// Real daemon subprocess so the test can SIGKILL it at a funding checkpoint
/// (in-process nodes cannot model an OS crash). A debug build is required: the
/// crash checkpoint is compiled out under `--release`.
struct DaemonProcess {
    child: std::process::Child,
    address: SocketAddr,
}

impl DaemonProcess {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

fn daemon_binary() -> PathBuf {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| format!("{}/target", env!("CARGO_MANIFEST_DIR")));
    let bin = PathBuf::from(target_dir)
        .join("debug")
        .join("rgb-lightning-node");
    assert!(
        bin.exists(),
        "daemon binary not found at {}; run `cargo build` first (a debug build is required)",
        bin.display()
    );
    bin
}

async fn start_daemon_process(
    node_test_dir: &str,
    peer_port: u16,
    envs: &[(&str, &str)],
) -> DaemonProcess {
    let daemon_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    std::fs::create_dir_all(node_test_dir).unwrap();
    let log = std::fs::File::create(format!("{node_test_dir}/daemon.log")).unwrap();
    let mut cmd = std::process::Command::new(daemon_binary());
    cmd.arg(node_test_dir)
        .arg("--daemon-listening-port")
        .arg(daemon_port.to_string())
        .arg("--ldk-peer-listening-port")
        .arg(peer_port.to_string())
        .arg("--network")
        .arg("regtest")
        .arg("--disable-authentication")
        .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
        .stderr(std::process::Stdio::from(log));
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let child = cmd.spawn().expect("spawn daemon");
    let address: SocketAddr = format!("127.0.0.1:{daemon_port}").parse().unwrap();

    let t_0 = OffsetDateTime::now_utc();
    loop {
        if std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(200))
            .is_ok()
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 30.0 {
            panic!("daemon did not come up on {address}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    DaemonProcess { child, address }
}

/// Bind a free TCP port and release it, returning the number. Used for the
/// restarted node so it never races the just-killed process for its port.
fn free_peer_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Wait for the daemon to signal the checkpoint by writing the ready file.
/// Fails fast (rather than after the full timeout) if the daemon exits before
/// the checkpoint, so an unrelated crash reports its real cause.
async fn wait_for_checkpoint(daemon: &mut DaemonProcess, ready_path: &str, timeout_secs: f32) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if Path::new(ready_path).exists() {
            return;
        }
        if let Some(status) = daemon.child.try_wait().expect("poll daemon status") {
            panic!("daemon exited ({status}) before reaching the funding checkpoint");
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > timeout_secs {
            panic!("timeout waiting for the funding checkpoint at {ready_path}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// A sender killed after coloring the funding (allocations moved into a batch
/// transfer and the fascia consumed into the stock) but before the funding
/// transaction is handed to LDK must come back with its asset spendability
/// intact: the channel never existed, so nothing may stay locked. On current
/// code the entire asset balance (channel amount and change) remains locked
/// to the dead open, with no recovery at startup and `/failtransfers`
/// refusing to fail the batch because its fascia is already consumed.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sender_crash_after_color_leaves_assets_locked() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}sender_node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}sender_node2");
    let ready_path = format!("{TEST_DIR_BASE}sender_kill_ready");
    let _ = std::fs::remove_dir_all(&test_dir_node1);
    let _ = std::fs::remove_file(&ready_path);

    let mut node1 = start_daemon_process(
        &test_dir_node1,
        NODE1_PEER_PORT,
        &[
            ("RLN_FUNDING_KILL_AT", FUNDING_CHECKPOINT_AFTER_COLOR),
            ("RLN_FUNDING_KILL_READY_PATH", &ready_path),
        ],
    )
    .await;
    let password = "funding_crash_sender";
    init(node1.address, password, None).await;
    unlock(node1.address, password).await;

    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1.address, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset = issue_asset_nia(node1.address).await;
    let initial_spendable = asset_balance_spendable(node1.address, &asset.asset_id).await;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // Fire-only POST: the funding is deliberately halted at the checkpoint,
    // so we must not wait for the channel to fund.
    open_channel_raw(
        node1.address,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset.asset_id),
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await
    .expect("open channel request");

    // The child parks after rgb_send_begin + rgb_consume_fascia, before the
    // funding tx is signed or handed to LDK: allocations are locked and the
    // stock already holds the transition for a channel that will never exist.
    wait_for_checkpoint(&mut node1, &ready_path, 60.0).await;
    assert_eq!(
        std::fs::read_to_string(&ready_path).expect("read ready file"),
        FUNDING_CHECKPOINT_AFTER_COLOR,
        "the crash must fire at the post-coloring checkpoint, not another write"
    );
    node1.kill();

    // Restart over the same data dir with a fresh peer port (the dead channel
    // is not resumable, so node1b needs no specific port and must not race the
    // just-killed process for it). No crash injection this time.
    let node1b = start_daemon_process(&test_dir_node1, free_peer_port(), &[]).await;
    unlock(node1b.address, password).await;

    let spendable = asset_balance_spendable(node1b.address, &asset.asset_id).await;
    assert_eq!(
        spendable, initial_spendable,
        "restart after a crash mid-open must release the allocations colored \
         for the dead channel: they stay locked with no channel and no \
         automatic recovery"
    );

    shutdown(&[node2_addr]).await;
}
