use super::*;
use crate::gossip::GossipSourceConfig;
use std::process::Command;

const TEST_DIR_BASE: &str = "tmp/gossip_rgs/";
const RGS_HTTP_URL: &str = "http://localhost:8002";

fn start_rgs_stack(ln_peer: &str) {
    let status = Command::new("docker")
        .args([
            "compose",
            "--profile",
            "gossip",
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "rgs-postgres",
            "rgs-server",
            "rgs-http",
        ])
        .env("RGS_LN_PEERS", ln_peer)
        .status()
        .expect("failed to invoke docker compose");
    assert!(status.success(), "docker compose up failed");
}

fn stop_rgs_stack() {
    let _ = Command::new("docker")
        .args([
            "compose",
            "rm",
            "-fsv",
            "rgs-server",
            "rgs-postgres",
            "rgs-http",
        ])
        .status();
}

// RAII: ensure the docker stack is torn down even if a body assertion panics.
struct RgsStackGuard;
impl Drop for RgsStackGuard {
    fn drop(&mut self) {
        stop_rgs_stack();
    }
}

async fn wait_for_rgs_snapshot(timeout_secs: f32) {
    let t_0 = OffsetDateTime::now_utc();
    let dir = std::path::Path::new("datargs/symlinks");
    loop {
        if dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                if entries
                    .filter_map(Result::ok)
                    .any(|e| e.file_name().to_string_lossy().ends_with(".bin"))
                {
                    return;
                }
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > timeout_secs {
            panic!(
                "no RGS snapshot file appeared in datargs/symlinks/ within {timeout_secs}s; \
                 check `docker logs gossip-integration-rgs-server-1`"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgs_mode_consumes_real_server_snapshot() {
    initialize();

    // Three RLN nodes: A and B open a public channel that the RGS server
    // crawls from A; C consumes the resulting snapshot in RGS mode and should
    // observe the A↔B channel in its network graph.
    let test_dir_a = format!("{TEST_DIR_BASE}node1");
    let test_dir_b = format!("{TEST_DIR_BASE}node2");
    let test_dir_c = format!("{TEST_DIR_BASE}node3");

    let (addr_a, _pwd_a) = start_node(&test_dir_a, NODE1_PEER_PORT, false).await;
    let (addr_b, _pwd_b) = start_node(&test_dir_b, NODE2_PEER_PORT, false).await;

    let pubkey_a = node_info(addr_a).await.pubkey;
    let pubkey_b = node_info(addr_b).await.pubkey;

    // Fund A and open a public channel A→B.
    fund_and_create_utxos(addr_a, None).await;
    let _channel = open_channel(
        addr_a,
        &pubkey_b,
        Some(NODE2_PEER_PORT),
        None,
        None,
        None,
        None,
    )
    .await;

    // Channels become announceable after enough confirmations; mine extra blocks
    // so both endpoints can broadcast channel_announcement.
    mine_n_blocks(false, 6);
    wait_for_usable_channels(addr_a, 1).await;
    wait_for_usable_channels(addr_b, 1).await;

    // Bring up the gossip stack pointing at node A as the only crawl peer.
    let ln_peer = format!("{pubkey_a}@host.docker.internal:{NODE1_PEER_PORT}");
    start_rgs_stack(&ln_peer);
    let _stack_guard = RgsStackGuard;

    // The RGS server peers with A, performs initial gossip sync, and writes
    // its first snapshot file to /srv/cache/symlinks/ (mounted as datargs/).
    wait_for_rgs_snapshot(30.0).await;

    // Start node C in RGS mode pointing at the nginx that fronts the snapshots.
    let pwd_c = format!("{test_dir_c}.{NODE3_PEER_PORT}");
    let addr_c = start_daemon(&test_dir_c, NODE3_PEER_PORT, None, false).await;
    init(addr_c, &pwd_c, None).await;
    unlock_with_gossip_source(
        addr_c,
        &pwd_c,
        Some(GossipSourceConfig::RapidGossipSync {
            server_url: RGS_HTTP_URL.into(),
        }),
    )
    .await;

    // The background sync task fires immediately on first tick; poll until C
    // sees both the timestamp and at least one channel learned via RGS.
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let info = node_info(addr_c).await;
        if info.latest_rgs_snapshot_timestamp.is_some() && info.network_channels >= 1 {
            return;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 15.0 {
            panic!(
                "node C in RGS mode did not see channel via snapshot within timeout \
                 (latest_rgs_snapshot_timestamp={:?}, network_channels={})",
                info.latest_rgs_snapshot_timestamp, info.network_channels
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
