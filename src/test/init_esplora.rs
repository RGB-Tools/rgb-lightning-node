use std::process::Command;

use super::*;

const TEST_DIR_BASE: &str = "tmp/init_esplora/";

async fn start_esplora_profile() {
    // initialize() recreated the network — drop the stale esplora container.
    let _ = Command::new("docker")
        .args(["rm", "-f", "optional-bitcoind-esplora-sync-esplora-1"])
        .status();
    let status = Command::new("docker")
        .args(["compose", "--profile", "esplora", "up", "-d", "esplora"])
        .status()
        .expect("failed to start esplora service");
    assert!(status.success(), "docker compose esplora up failed");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let ready = client
            .get(format!(
                "{}/blocks/tip/hash",
                crate::utils::ESPLORA_URL_REGTEST
            ))
            .send()
            .await
            .ok();
        if let Some(resp) = ready {
            if let Ok(body) = resp.text().await {
                if body.trim().len() == 64 {
                    return;
                }
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            panic!("esplora REST never became ready");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Happy path for the esplora chain-sync mode: unlock without bitcoind creds, fund the wallet, confirm sync via esplora.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn init_esplora_path_unlocks_without_bitcoind() {
    initialize();
    start_esplora_profile().await;

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT, None, false).await;

    let mnemonic = s!(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    let init_1 = init(node1_addr, "password123", Some(mnemonic.clone())).await;
    assert_eq!(init_1.mnemonic, mnemonic);

    let payload = UnlockRequest {
        password: s!("password123"),
        bitcoind_rpc_username: None,
        bitcoind_rpc_password: None,
        bitcoind_rpc_host: None,
        bitcoind_rpc_port: None,
        indexer_url: Some(crate::utils::ESPLORA_URL_REGTEST.to_string()),
        proxy_endpoint: Some(PROXY_ENDPOINT_LOCAL.to_string()),
        announce_addresses: vec![],
        announce_alias: None,
        gossip_source: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/unlock"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "esplora unlock failed: {:?}",
        res.text().await
    );

    let info = node_info(node1_addr).await;
    assert!(
        !info.pubkey.is_empty(),
        "node has no pubkey after esplora unlock"
    );

    // Fund + mine: if esplora chain-sync is broken the balance never moves.
    let addr = address(node1_addr).await;
    let pre_balance = btc_balance(node1_addr).await;
    _fund_wallet(addr);
    mine(false);
    let t_0 = OffsetDateTime::now_utc();
    let mut post_balance = btc_balance(node1_addr).await;
    while post_balance.vanilla.settled <= pre_balance.vanilla.settled
        && (OffsetDateTime::now_utc() - t_0).as_seconds_f32() < 90.0
    {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        post_balance = btc_balance(node1_addr).await;
    }
    assert!(
        post_balance.vanilla.settled > pre_balance.vanilla.settled,
        "esplora sync did not pick up the new UTXO (pre={}, post={})",
        pre_balance.vanilla.settled,
        post_balance.vanilla.settled,
    );
}
