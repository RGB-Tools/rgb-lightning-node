use crate::disk::LDK_LOGS_FILE;
use crate::utils::LDK_DIR;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use super::*;

const TEST_DIR_BASE: &str = "tmp/refuse_high_fees/";
const NODE1_PEER_PORT: u16 = 9931;
const NODE2_PEER_PORT: u16 = 9932;
const NODE3_PEER_PORT: u16 = 9933;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn refuse_high_fees() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1.clone(), NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;
    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 400, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);

    let _channel_12 =
        open_colored_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 500, &asset_id).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 100);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 400);

    let _channel_23 = open_colored_channel_custom_btc_amount(
        node2_addr,
        &node3_pubkey,
        NODE3_PEER_PORT,
        300,
        &asset_id,
        100_000,
        Some(2_000_000),
        None,
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 100);

    let LNInvoiceResponse { invoice } = ln_invoice(node3_addr, None, Some(&asset_id), Some(50), 900).await;
    let _ = send_payment_with_status(node1_addr, invoice, HTLCStatus::Failed).await;

    let file = File::open(
        PathBuf::from(test_dir_node1)
            .join(LDK_DIR)
            .join(LOGS_DIR)
            .join(LDK_LOGS_FILE),
    )
    .unwrap();
    let reader = BufReader::new(file);

    let mut found_log = false;
    for line in reader.lines() {
        if line
            .unwrap()
            .contains("due to exceeding max total routing fee limit")
        {
            found_log = true;
            break;
        }
    }
    if !found_log {
        panic!("expected log line not found")
    }
}
