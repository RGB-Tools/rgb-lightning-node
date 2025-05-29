use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_reverse_same_channel/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_reverse_same_channel() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id),
    )
    .await;

    let channels_1_before = list_channels(node1_addr).await;
    let channels_2_before = list_channels(node2_addr).await;
    let chan_1_12_before = channels_1_before
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_12_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();

    println!("\nsetup swap");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 25000;
    let qty_to = 10;
    let maker_init_response =
        maker_init(maker_addr, qty_from, None, qty_to, Some(&asset_id), 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

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
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, None);
    assert_eq!(swap_taker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_taker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    println!("\nexecute swap");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey.clone(),
    )
    .await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert!(swaps_maker.taker.is_empty());
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id, 590).await;
    wait_for_ln_balance(taker_addr, &asset_id, 10).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swaps_taker = list_swaps(taker_addr).await;
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    let chan_1_12 = channels_1
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_12 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    assert_eq!(
        chan_1_12.local_balance_sat,
        chan_1_12_before.local_balance_sat + qty_from / 1000
    );
    assert_eq!(
        chan_2_12.local_balance_sat,
        chan_2_12_before.local_balance_sat - qty_from / 1000
    );

    println!("\nsetup reverse swap");
    let maker_addr = node2_addr;
    let taker_addr = node1_addr;
    let qty_from = 10;
    let qty_to = 50000;
    let maker_init_response =
        maker_init(maker_addr, qty_from, Some(&asset_id), qty_to, None, 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.to_asset, None);
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swaps_taker = list_swaps(taker_addr).await;
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, Some(asset_id.clone()));
    assert_eq!(swap_taker.to_asset, None);
    assert_eq!(swap_taker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    println!("\nexecute swap");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node1_pubkey.clone(),
    )
    .await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id, 20).await;
    wait_for_ln_balance(taker_addr, &asset_id, 580).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swaps_taker = list_swaps(taker_addr).await;
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);
}
