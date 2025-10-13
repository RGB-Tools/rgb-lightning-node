use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_assets_liquidity_both_ways/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_assets_liquidity_both_ways() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let asset_id_2 = issue_asset_nia(node1_addr).await.asset_id;

    let _node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let _channel_12_asset1 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id),
    )
    .await;
    let _channel_12_asset2 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id_2),
    )
    .await;

    println!("\nsetup swap buy usdt");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 25000;
    let qty_to = 10;
    let maker_init_response =
        maker_init(maker_addr, qty_from, None, qty_to, Some(&asset_id), 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
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

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id, 590).await;
    wait_for_ln_balance(taker_addr, &asset_id, 10).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    println!("\nsetup swap buy test");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 25000;
    let qty_to = 10;
    let maker_init_response =
        maker_init(maker_addr, qty_from, None, qty_to, Some(&asset_id_2), 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, None);
    assert_eq!(swap_taker.to_asset, Some(asset_id_2.clone()));
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

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id_2, 590).await;
    wait_for_ln_balance(taker_addr, &asset_id_2, 10).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    println!("\nsetup asset-to-asset swap: usdt to test");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 5;
    let qty_to = 5;
    let maker_init_response = maker_init(
        maker_addr,
        qty_from,
        Some(&asset_id),
        qty_to,
        Some(&asset_id_2),
        3600,
    )
    .await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.to_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, Some(asset_id.clone()));
    assert_eq!(swap_taker.to_asset, Some(asset_id_2.clone()));
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

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id, 595).await;
    wait_for_ln_balance(maker_addr, &asset_id_2, 585).await;
    wait_for_ln_balance(taker_addr, &asset_id, 5).await;
    wait_for_ln_balance(taker_addr, &asset_id_2, 15).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);
}
