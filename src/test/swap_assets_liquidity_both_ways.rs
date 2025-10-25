use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_assets_liquidity_both_ways/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_assets_liquidity_both_ways() {
    initialize();

    let maker_peer_port = NODE1_PEER_PORT;
    let taker_peer_port = NODE2_PEER_PORT;

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (maker_addr, _) = start_node(&test_dir_node1, maker_peer_port, false).await;
    let (taker_addr, _) = start_node(&test_dir_node2, taker_peer_port, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(maker_addr, None).await;
    fund_and_create_utxos(taker_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id_1 = issue_asset_nia(maker_addr).await.asset_id;
    let asset_id_2 = issue_asset_nia(maker_addr).await.asset_id;

    let maker_pubkey = node_info(maker_addr).await.pubkey;
    let taker_pubkey = node_info(taker_addr).await.pubkey;

    let channel_mt_asset_1 = open_channel(
        maker_addr,
        &taker_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id_1),
    )
    .await;
    let channel_mt_asset_2 = open_channel(
        maker_addr,
        &taker_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(50000000),
        Some(600),
        Some(&asset_id_2),
    )
    .await;

    // part 1: swap, using part of the RGB balance on each side

    println!("\nsetup swap buy some asset 1");
    let qty_from = 25000;
    let qty_to = 10;
    let maker_init_response =
        maker_init(maker_addr, qty_from, None, qty_to, Some(&asset_id_1), 3600).await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, None);
    assert_eq!(swap_taker.to_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_taker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    println!("\nexecute swap buy some asset 1");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        taker_pubkey.clone(),
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

    wait_for_ln_balance(maker_addr, &asset_id_1, 590).await;
    wait_for_ln_balance(taker_addr, &asset_id_1, 10).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    println!("\nsetup swap buy some asset 2");
    let qty_from = 25000;
    let qty_to = 20;
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

    println!("\nexecute swap buy some asset 2");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        taker_pubkey.clone(),
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

    wait_for_ln_balance(maker_addr, &asset_id_2, 580).await;
    wait_for_ln_balance(taker_addr, &asset_id_2, 20).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    println!("\nsetup swap some asset 1 for some asset 2");
    let qty_from = 5;
    let qty_to = 12;
    let maker_init_response = maker_init(
        maker_addr,
        qty_from,
        Some(&asset_id_1),
        qty_to,
        Some(&asset_id_2),
        3600,
    )
    .await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_maker.to_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_taker.to_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_taker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    println!("\nexecute swap some asset 1 for some asset 2");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        taker_pubkey.clone(),
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

    wait_for_ln_balance(maker_addr, &asset_id_1, 595).await;
    wait_for_ln_balance(maker_addr, &asset_id_2, 568).await;
    wait_for_ln_balance(taker_addr, &asset_id_1, 5).await;
    wait_for_ln_balance(taker_addr, &asset_id_2, 32).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    // part 2: swap again, using all RGB balance on each side

    println!("\nsend most asset 1 to taker off-chain");
    let LNInvoiceResponse { invoice } =
        ln_invoice(taker_addr, None, Some(&asset_id_1), Some(530), 900).await;
    let _ = send_payment(maker_addr, invoice).await;

    wait_for_ln_balance(maker_addr, &asset_id_1, 65).await;
    wait_for_ln_balance(taker_addr, &asset_id_1, 535).await;

    println!("\nsetup swap all asset 2 for all asset 1");
    let qty_from = 32;
    let qty_to = 65;
    let maker_init_response = maker_init(
        maker_addr,
        qty_from,
        Some(&asset_id_2),
        qty_to,
        Some(&asset_id_1),
        3600,
    )
    .await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    let swap_maker = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_maker.to_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    let swap_taker = get_swap(taker_addr, &maker_init_response.payment_hash, true).await;
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_taker.to_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_taker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    println!("\nexecute swap all asset 2 for all asset 1");
    maker_execute(
        maker_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        taker_pubkey.clone(),
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id_1, 0).await;
    wait_for_ln_balance(maker_addr, &asset_id_2, 600).await;
    wait_for_ln_balance(taker_addr, &asset_id_1, 600).await;
    wait_for_ln_balance(taker_addr, &asset_id_2, 0).await;

    // part 3: close channels, spend assets on-chain, check final balances

    println!("\nclose channels");
    close_channel(
        maker_addr,
        &channel_mt_asset_1.channel_id,
        &taker_pubkey,
        false,
    )
    .await;
    wait_for_balance(maker_addr, &asset_id_1, 400).await;
    wait_for_balance(taker_addr, &asset_id_1, 600).await;

    close_channel(
        taker_addr,
        &channel_mt_asset_2.channel_id,
        &maker_pubkey,
        false,
    )
    .await;
    wait_for_balance(maker_addr, &asset_id_2, 1000).await;
    wait_for_balance(taker_addr, &asset_id_2, 0).await;

    println!("\nspend assets");
    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        maker_addr,
        &asset_id_1,
        Assignment::Fungible(300),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(maker_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        maker_addr,
        &asset_id_2,
        Assignment::Fungible(900),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(maker_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        taker_addr,
        &asset_id_1,
        Assignment::Fungible(500),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(taker_addr).await;

    assert_eq!(asset_balance_spendable(maker_addr, &asset_id_1).await, 100);
    assert_eq!(asset_balance_spendable(taker_addr, &asset_id_1).await, 100);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id_1).await, 800);
    assert_eq!(asset_balance_spendable(maker_addr, &asset_id_2).await, 100);
    assert_eq!(asset_balance_spendable(taker_addr, &asset_id_2).await, 0);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id_2).await, 900);
}
