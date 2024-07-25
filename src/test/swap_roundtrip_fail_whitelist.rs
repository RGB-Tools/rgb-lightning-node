use crate::disk::LDK_LOGS_FILE;
use crate::utils::LDK_DIR;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_whitelist/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_fail_whitelist() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    open_channel(
        node2_addr,
        &node1_pubkey,
        NODE2_PEER_PORT,
        Some(5000000),
        Some(546000),
        None,
        None,
    )
    .await;

    println!("\nsetup swap (skipping taker)");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 36000;
    let qty_to = 10;
    let maker_init_response =
        maker_init(maker_addr, qty_from, None, qty_to, Some(&asset_id), 5000).await;
    // We don't execute the taker command, so the swapstring is not going to be Waiting, and
    // the swap will fail.
    //let taker_response = taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert!(swaps_maker.taker.is_empty());
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);
    let swaps_taker = list_swaps(taker_addr).await;
    assert!(swaps_taker.maker.is_empty());
    assert!(swaps_taker.taker.is_empty());

    println!("\nexecute swap");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey,
    )
    .await;

    println!("\nwait for the swap to fail");
    for _ in 0..10 {
        let swaps = list_swaps(maker_addr).await;
        let swap = swaps.maker.first().unwrap();
        if matches!(swap.status, SwapStatus::Failed) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let file = File::open(
        PathBuf::from(test_dir_node1)
            .join(LDK_DIR)
            .join(LOGS_DIR)
            .join(LDK_LOGS_FILE),
    )
    .unwrap();
    let reader = BufReader::new(file);

    // check the payment failed for the correc reason
    let mut found_log = false;
    for line in reader.lines() {
        if line.unwrap().contains("rejecting non-Waiting swap") {
            found_log = true;
            break;
        }
    }
    if !found_log {
        panic!("expected log line not found")
    }

    let payments_maker = list_payments(maker_addr).await;
    assert!(payments_maker.is_empty());
    let payments_taker = list_payments(taker_addr).await;
    assert!(payments_taker.is_empty());
}
