use super::*;
use std::process::{Command, Stdio};

const TEST_DIR_BASE: &str = "tmp/cli_integration/";

// Helper function to run CLI commands
fn run_cli_command(
    server_url: &str,
    token: Option<&str>,
    args: &[&str],
) -> Result<serde_json::Value, String> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--bin")
        .arg("rln-cli")
        .arg("--")
        .arg("--server")
        .arg(server_url);

    if let Some(t) = token {
        cmd.arg("--token").arg(t);
    }

    for arg in args {
        cmd.arg(arg);
    }

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute CLI: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("CLI command failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).map_err(|e| format!("Failed to parse JSON: {}", e))
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_node_info() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test node info command
    let result = run_cli_command(&server_url, None, &["node", "info"]);
    assert!(result.is_ok(), "CLI node info failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("pubkey").is_some());
    assert!(json.get("num_peers").is_some());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_network_info() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_network");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test network info command
    let result = run_cli_command(&server_url, None, &["node", "network-info"]);
    assert!(result.is_ok(), "CLI network info failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("network").is_some());
    assert_eq!(json["network"], "Regtest");
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_onchain_address() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_address");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test address command
    let result = run_cli_command(&server_url, None, &["onchain", "address"]);
    assert!(result.is_ok(), "CLI address failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("address").is_some());
    let address = json["address"].as_str().unwrap();
    assert!(address.starts_with("bcrt1"));
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_onchain_btc_balance() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_btc_balance");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund the node first
    fund_and_create_utxos(node1_addr, None).await;

    // Test btc-balance command
    let result = run_cli_command(&server_url, None, &["onchain", "btc-balance"]);
    assert!(result.is_ok(), "CLI btc-balance failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("vanilla").is_some());
    assert!(json.get("colored").is_some());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_rgb_issue_nia() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_issue_nia");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund the node
    fund_and_create_utxos(node1_addr, None).await;

    // Test issue-nia command
    let result = run_cli_command(
        &server_url,
        None,
        &[
            "rgb",
            "issue-nia",
            "--amounts",
            "1000",
            "USDT",
            "Tether USD",
            "--precision",
            "8",
        ],
    );
    assert!(result.is_ok(), "CLI issue-nia failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("asset").is_some());
    assert!(json["asset"].get("asset_id").is_some());
    let asset_id = json["asset"]["asset_id"].as_str().unwrap();
    assert!(!asset_id.is_empty());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_rgb_list_assets() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_list_assets");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund and issue an asset
    fund_and_create_utxos(node1_addr, None).await;
    let asset_nia = issue_asset_nia(node1_addr).await;

    // Test list-assets command
    let result = run_cli_command(&server_url, None, &["rgb", "list-assets"]);
    assert!(result.is_ok(), "CLI list-assets failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("nia").is_some());
    let nia_assets = json["nia"].as_array().unwrap();
    assert_eq!(nia_assets.len(), 1);
    assert_eq!(nia_assets[0]["asset_id"], asset_nia.asset_id);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_rgb_asset_balance() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_asset_balance");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund and issue an asset
    fund_and_create_utxos(node1_addr, None).await;
    let asset_nia = issue_asset_nia(node1_addr).await;

    // Test asset-balance command
    let result = run_cli_command(
        &server_url,
        None,
        &["rgb", "asset-balance", &asset_nia.asset_id],
    );
    assert!(result.is_ok(), "CLI asset-balance failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("spendable").is_some());
    assert_eq!(json["spendable"], 1000);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_peer_connect_list_disconnect() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_peer");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2_peer");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Get node2 info for connection
    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;
    let peer_addr = format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT);

    // Test peer connect command
    let result = run_cli_command(&server_url, None, &["peer", "connect", &peer_addr]);
    assert!(result.is_ok(), "CLI peer connect failed: {:?}", result);

    // Wait a bit for connection to establish
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Test peer list command
    let result = run_cli_command(&server_url, None, &["peer", "list"]);
    assert!(result.is_ok(), "CLI peer list failed: {:?}", result);

    let json = result.unwrap();
    let peers = json["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["pubkey"], node2_pubkey);

    // Test peer disconnect command
    let result = run_cli_command(&server_url, None, &["peer", "disconnect", &node2_pubkey]);
    assert!(result.is_ok(), "CLI peer disconnect failed: {:?}", result);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_channel_open_list() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_channel");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2_channel");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund both nodes
    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // Get node2 info
    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;
    let peer_addr = format!("{}@127.0.0.1:{}", node2_pubkey, NODE2_PEER_PORT);

    // Test channel open command
    let result = run_cli_command(
        &server_url,
        None,
        &["channel", "open", &peer_addr, "100000"],
    );
    assert!(result.is_ok(), "CLI channel open failed: {:?}", result);

    // Mine blocks to confirm channel
    mine(false);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Test channel list command
    let result = run_cli_command(&server_url, None, &["channel", "list"]);
    assert!(result.is_ok(), "CLI channel list failed: {:?}", result);

    let json = result.unwrap();
    let channels = json["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0]["peer_pubkey"], node2_pubkey);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_invoice_create_decode() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_invoice");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test ln-invoice command
    let result = run_cli_command(&server_url, None, &["invoice", "ln-invoice", "10000"]);
    assert!(result.is_ok(), "CLI ln-invoice failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("invoice").is_some());
    let invoice = json["invoice"].as_str().unwrap();
    assert!(invoice.starts_with("lnbc"));

    // Test decode-ln command
    let result = run_cli_command(&server_url, None, &["invoice", "decode-ln", invoice]);
    assert!(result.is_ok(), "CLI decode-ln failed: {:?}", result);

    let decoded = result.unwrap();
    assert!(decoded.get("payment_hash").is_some());
    assert_eq!(decoded["amt_msat"], 10000);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_rgb_invoice_create_decode() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_rgb_invoice");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund and issue an asset
    fund_and_create_utxos(node1_addr, None).await;
    let asset_nia = issue_asset_nia(node1_addr).await;

    // Test rgb-invoice command
    let result = run_cli_command(
        &server_url,
        None,
        &["rgb", "rgb-invoice", &asset_nia.asset_id, "--amount", "100"],
    );
    assert!(result.is_ok(), "CLI rgb-invoice failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("invoice").is_some());
    let invoice = json["invoice"].as_str().unwrap();
    assert!(!invoice.is_empty());

    // Test decode-invoice command
    let result = run_cli_command(&server_url, None, &["rgb", "decode-invoice", invoice]);
    assert!(result.is_ok(), "CLI decode-invoice failed: {:?}", result);

    let decoded = result.unwrap();
    assert_eq!(decoded["asset_id"], asset_nia.asset_id);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_payment_keysend() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_keysend");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2_keysend");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund both nodes
    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // Open channel
    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey.clone();
    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(0),
        None,
        None,
    )
    .await;

    // Test keysend command (minimum amount is 3000000 msats)
    let result = run_cli_command(
        &server_url,
        None,
        &["payment", "keysend", &node2_pubkey, "3000000"],
    );
    assert!(result.is_ok(), "CLI keysend failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("payment_hash").is_some());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_payment_list() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_payment_list");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test payment list command (should be empty initially)
    let result = run_cli_command(&server_url, None, &["payment", "list"]);
    assert!(result.is_ok(), "CLI payment list failed: {:?}", result);

    let json = result.unwrap();
    let payments = json["payments"].as_array().unwrap();
    assert_eq!(payments.len(), 0);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_swap_maker_init() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_swap");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2_swap");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let server_url_1 = format!("http://{}", node1_addr);
    let server_url_2 = format!("http://{}", node2_addr);

    // Fund both nodes and create UTXOs
    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // Issue asset on node1
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // Open RGB channel from node1 to node2 with asset (600 units)
    let _channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;

    // Open BTC channel from node2 to node1 (for swap payment)
    let _channel_21 = open_channel(
        node2_addr,
        &node1_pubkey,
        Some(NODE1_PEER_PORT),
        Some(5000000),
        Some(546000),
        None,
        None,
    )
    .await;

    wait_for_usable_channels(node1_addr, 2).await;
    wait_for_usable_channels(node2_addr, 2).await;

    // Setup swap parameters
    let qty_from = 50000; // BTC msats
    let qty_to = 10; // RGB asset units

    // Test maker-init command via CLI (node1 initiates swap: receives BTC, sends asset)
    let result = run_cli_command(
        &server_url_1,
        None,
        &[
            "swap",
            "maker-init",
            &qty_from.to_string(),
            &qty_to.to_string(),
            "btc",     // from_asset (taker sends BTC)
            &asset_id, // to_asset (taker receives asset)
            "--timeout-sec",
            "3600",
        ],
    );
    assert!(result.is_ok(), "CLI maker-init failed: {:?}", result);

    let maker_init_json = result.unwrap();
    assert!(maker_init_json.get("swapstring").is_some());
    assert!(maker_init_json.get("payment_hash").is_some());
    assert!(maker_init_json.get("payment_secret").is_some());

    let swapstring = maker_init_json["swapstring"].as_str().unwrap();
    let payment_hash = maker_init_json["payment_hash"].as_str().unwrap();
    let payment_secret = maker_init_json["payment_secret"].as_str().unwrap();

    // Test swap list on maker (should show 1 maker swap)
    let result = run_cli_command(&server_url_1, None, &["swap", "list"]);
    assert!(result.is_ok(), "CLI swap list failed: {:?}", result);
    let json = result.unwrap();
    assert_eq!(json["maker"].as_array().unwrap().len(), 1);
    assert_eq!(json["taker"].as_array().unwrap().len(), 0);

    // Test taker command via CLI (node2 accepts swap)
    let result = run_cli_command(&server_url_2, None, &["swap", "taker", swapstring]);
    assert!(result.is_ok(), "CLI taker failed: {:?}", result);

    // Test swap list on taker (should show 1 taker swap)
    let result = run_cli_command(&server_url_2, None, &["swap", "list"]);
    assert!(result.is_ok(), "CLI swap list failed: {:?}", result);
    let json = result.unwrap();
    assert_eq!(json["maker"].as_array().unwrap().len(), 0);
    assert_eq!(json["taker"].as_array().unwrap().len(), 1);

    // Test maker-execute command via CLI (node1 executes swap)
    let result = run_cli_command(
        &server_url_1,
        None,
        &[
            "swap",
            "maker-execute",
            swapstring,
            payment_secret,
            &node2_pubkey,
        ],
    );
    assert!(result.is_ok(), "CLI maker-execute failed: {:?}", result);

    // Wait for swap to complete
    wait_for_swap_status(node1_addr, payment_hash, SwapStatus::Succeeded).await;
    wait_for_swap_status(node2_addr, payment_hash, SwapStatus::Succeeded).await;

    // Verify final balances
    wait_for_ln_balance(node1_addr, &asset_id, 590).await; // 600 - 10 = 590
    wait_for_ln_balance(node2_addr, &asset_id, 10).await; // 0 + 10 = 10

    // Test get swap command via CLI (from maker's perspective, no --taker flag)
    let result = run_cli_command(&server_url_1, None, &["swap", "get", payment_hash]);
    assert!(result.is_ok(), "CLI swap get failed: {:?}", result);
    let swap_response = result.unwrap();
    assert!(swap_response.get("swap").is_some());
    let swap_json = &swap_response["swap"];
    assert_eq!(swap_json["status"], "Succeeded");
    assert_eq!(swap_json["qty_from"], qty_from);
    assert_eq!(swap_json["qty_to"], qty_to);

    // Test get swap command from taker's perspective (with --taker flag)
    let result = run_cli_command(
        &server_url_2,
        None,
        &["swap", "get", payment_hash, "--taker"],
    );
    assert!(result.is_ok(), "CLI swap get (taker) failed: {:?}", result);
    let taker_swap_response = result.unwrap();
    assert!(taker_swap_response.get("swap").is_some());
    let taker_swap_json = &taker_swap_response["swap"];
    assert_eq!(taker_swap_json["status"], "Succeeded");
    assert_eq!(taker_swap_json["qty_from"], qty_from);
    assert_eq!(taker_swap_json["qty_to"], qty_to);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_swap_list() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_swap_list");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test swap list command (should be empty initially)
    let result = run_cli_command(&server_url, None, &["swap", "list"]);
    assert!(result.is_ok(), "CLI swap list failed: {:?}", result);

    let json = result.unwrap();
    assert!(json.get("maker").is_some());
    assert!(json.get("taker").is_some());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_onchain_list_transactions() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_list_tx");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund the node to create transactions
    fund_and_create_utxos(node1_addr, None).await;

    // Test list-transactions command
    let result = run_cli_command(&server_url, None, &["onchain", "list-transactions"]);
    assert!(result.is_ok(), "CLI list-transactions failed: {:?}", result);

    let json = result.unwrap();
    let transactions = json["transactions"].as_array().unwrap();
    assert!(!transactions.is_empty());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_onchain_list_unspents() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_list_unspents");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund the node to create UTXOs
    fund_and_create_utxos(node1_addr, None).await;

    // Test list-unspents command
    let result = run_cli_command(&server_url, None, &["onchain", "list-unspents"]);
    assert!(result.is_ok(), "CLI list-unspents failed: {:?}", result);

    let json = result.unwrap();
    let unspents = json["unspents"].as_array().unwrap();
    assert!(!unspents.is_empty());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_rgb_create_utxos() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_create_utxos");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Fund the node
    fund_and_create_utxos(node1_addr, None).await;

    let unspents_before = list_unspents(node1_addr).await;

    // Test create-utxos command
    let result = run_cli_command(
        &server_url,
        None,
        &["rgb", "create-utxos", "3", "5000", "1"],
    );
    assert!(result.is_ok(), "CLI create-utxos failed: {:?}", result);

    // Wait for transaction to be processed
    mine(false);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let unspents_after = list_unspents(node1_addr).await;
    assert!(unspents_after.len() >= unspents_before.len() + 3);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_with_custom_server_url() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_custom_url");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test that custom server URL works
    let result = run_cli_command(&server_url, None, &["node", "info"]);
    assert!(
        result.is_ok(),
        "CLI with custom server URL failed: {:?}",
        result
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn cli_error_handling_invalid_command() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1_invalid");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    let server_url = format!("http://{}", node1_addr);

    // Test that invalid asset ID returns error appropriately
    let result = run_cli_command(
        &server_url,
        None,
        &["rgb", "asset-balance", "invalid_asset_id"],
    );

    // This should fail gracefully
    assert!(result.is_err() || result.unwrap().get("error").is_some());
}
