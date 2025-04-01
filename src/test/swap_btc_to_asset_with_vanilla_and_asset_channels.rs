use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_btc_to_asset_with_vanilla_and_asset_channels/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_btc_to_asset_with_vanilla_and_asset_channels() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    // Fund both nodes
    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    // Issue asset for the test
    let asset_id = issue_asset_nia(node2_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // Open vanilla channel (node1 -> node2)
    let channel_vanilla = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(200_000), 
        Some(15_000_000),  
        None,
        None,
    )
    .await;

    // Open asset channel (node2 -> node1)
    let channel_asset = open_channel(
        node2_addr,
        &node1_pubkey,
        Some(NODE1_PEER_PORT),
        Some(200_000), 
        Some(15_000_000), 
        Some(1000),
        Some(&asset_id),
    )
    .await;
    wait_for_ln_balance(node2_addr, &asset_id, 1000).await;
    
    let asset_invoice = ln_invoice(node1_addr, None, Some(&asset_id), Some(500), 3600).await;
    send_payment(node2_addr, asset_invoice.invoice).await;

    // Verify initial balances
    wait_for_ln_balance(node1_addr, &asset_id, 500).await;
    wait_for_ln_balance(node2_addr, &asset_id, 500).await;

    // Setup swap where node2 is maker
    let maker_addr = node2_addr;
    let taker_addr = node1_addr;
    let qty_from = 18_000_000; // BTC amount
    let qty_to = 200;       // Asset amount

    assert!(can_forward_htlc(maker_addr, qty_from).await);

    println!("\nsetup swap");
    let maker_init_response = maker_init(
        maker_addr,
        qty_from,
        None, 
        qty_to,
        Some(&asset_id), 
        3600,
    )
    .await;
    taker(taker_addr, maker_init_response.swapstring.clone()).await;

    // Verify swap setup
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
        node1_pubkey.clone(),
    )
    .await;

    // Verify swap execution
    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Pending);

    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Succeeded,
    )
    .await;

    // Verify final balances
    wait_for_ln_balance(maker_addr, &asset_id, 300).await; 
    wait_for_ln_balance(taker_addr, &asset_id, 700).await; 

    println!("\nrestart nodes");
    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    wait_for_usable_channels(node1_addr, 2).await;
    wait_for_usable_channels(node2_addr, 2).await;

    // Verify final balances after restart
    let balance_1 = asset_balance(node1_addr, &asset_id).await;
    let balance_2 = asset_balance(node2_addr, &asset_id).await;
    assert_eq!(balance_1.offchain_outbound, 700);
    assert_eq!(balance_1.offchain_inbound, 300);
    assert_eq!(balance_2.offchain_outbound, 300);
    assert_eq!(balance_2.offchain_inbound, 700);

    // Close channels
    println!("\nclose channels");
    close_channel(node1_addr, &channel_vanilla.channel_id, &node2_pubkey, false).await;
    close_channel(node2_addr, &channel_asset.channel_id, &node1_pubkey, false).await;

    // Verify final on-chain balances
    wait_for_balance(node1_addr, &asset_id, 700).await;
    wait_for_balance(node2_addr, &asset_id, 300).await;
} 