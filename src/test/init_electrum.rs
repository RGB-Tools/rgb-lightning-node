use super::*;

const TEST_DIR_BASE: &str = "tmp/init_electrum/";

/// Happy path for the electrum chain-sync mode: unlock without bitcoind creds, fund the wallet, confirm sync via electrs.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn init_electrum_path_unlocks_without_bitcoind() {
    initialize();

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
        indexer_url: Some(ELECTRUM_URL_REGTEST.to_string()),
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
        "electrum unlock failed: {:?}",
        res.text().await
    );

    let info = node_info(node1_addr).await;
    assert!(
        !info.pubkey.is_empty(),
        "node has no pubkey after electrum unlock"
    );

    // Fund + mine: if electrum chain-sync is broken the balance never moves.
    let addr = address(node1_addr).await;
    let pre_balance = btc_balance(node1_addr).await;
    fund_wallet(addr, 100_000_000);
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
        "electrum sync did not pick up the new UTXO (pre={}, post={})",
        pre_balance.vanilla.settled,
        post_balance.vanilla.settled,
    );
}
