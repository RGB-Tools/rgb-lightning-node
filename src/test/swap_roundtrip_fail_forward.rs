use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_forward/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_fail_forward_marks_taker_failed() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node2_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(5000000),
        Some(546000),
        None,
        None,
    )
    .await;
    open_channel(
        node2_addr,
        &node1_pubkey,
        Some(NODE1_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    wait_for_usable_channels(node1_addr, 2).await;
    wait_for_usable_channels(node2_addr, 2).await;

    println!("\nsetup swap");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 10;
    let qty_to = 50000;
    let maker_init_response =
        maker_init(maker_addr, qty_from, Some(&asset_id), qty_to, None, 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert!(swaps_maker.taker.is_empty());
    assert_eq!(swaps_maker.maker.len(), 1);
    assert_eq!(
        swaps_maker.maker.first().unwrap().status,
        SwapStatus::Waiting
    );

    let swaps_taker = list_swaps(taker_addr).await;
    assert!(swaps_taker.maker.is_empty());
    assert_eq!(swaps_taker.taker.len(), 1);
    assert_eq!(
        swaps_taker.taker.first().unwrap().status,
        SwapStatus::Waiting
    );

    crate::ldk::FORCE_NEXT_INTERCEPTED_SWAP_RGB_FORWARD_FAILURE
        .store(true, std::sync::atomic::Ordering::SeqCst);

    println!("\nexecute swap");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey,
    )
    .await;

    wait_for_swap_status(
        maker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Failed,
    )
    .await;

    // This assertion documents the expected behavior and currently fails because the
    // HTLCHandlingFailed event is ignored, leaving the taker swap stuck as Pending.
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Failed,
    )
    .await;
}
