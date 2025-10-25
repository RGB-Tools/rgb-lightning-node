use self::routes::HTLC_MIN_MSAT;

use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_assets/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_roundtrip_assets() {
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

    let asset_id_1 = issue_asset_nia(node1_addr).await.asset_id;
    let asset_id_2 = issue_asset_nia(node2_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id_1),
    )
    .await;
    let channel_21 = open_channel(
        node2_addr,
        &node1_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(150),
        Some(&asset_id_2),
    )
    .await;

    let channels_1_before = list_channels(node1_addr).await;
    let channels_2_before = list_channels(node2_addr).await;
    let chan_1_12_before = channels_1_before
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_1_21_before = channels_1_before
        .iter()
        .find(|c| c.channel_id == channel_21.channel_id)
        .unwrap();
    let chan_2_12_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_21_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_21.channel_id)
        .unwrap();

    println!("\nsetup swap");
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    let qty_from = 50;
    let qty_to = 10;
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

    let swaps_maker = list_swaps(maker_addr).await;
    assert!(swaps_maker.taker.is_empty());
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.qty_from, qty_from);
    assert_eq!(swap_maker.qty_to, qty_to);
    assert_eq!(swap_maker.from_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_maker.to_asset, Some(asset_id_1.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);
    let swap_maker_single = get_swap(maker_addr, &maker_init_response.payment_hash, false).await;
    assert_eq!(swap_maker_single, *swap_maker);
    let swaps_taker = list_swaps(taker_addr).await;
    assert!(swaps_taker.maker.is_empty());
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.qty_from, qty_from);
    assert_eq!(swap_taker.qty_to, qty_to);
    assert_eq!(swap_taker.from_asset, Some(asset_id_2.clone()));
    assert_eq!(swap_taker.to_asset, Some(asset_id_1.clone()));
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
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Pending);
    wait_for_swap_status(
        taker_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Pending,
    )
    .await;

    wait_for_ln_balance(maker_addr, &asset_id_1, 590).await;
    wait_for_ln_balance(maker_addr, &asset_id_2, 50).await;
    wait_for_ln_balance(taker_addr, &asset_id_1, 10).await;
    wait_for_ln_balance(taker_addr, &asset_id_2, 100).await;

    println!("\nrestart nodes");
    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let maker_addr = node1_addr;
    let taker_addr = node2_addr;
    wait_for_usable_channels(node1_addr, 2).await;
    wait_for_usable_channels(node2_addr, 2).await;

    println!("\ncheck balances and channels after nodes have restarted");
    let balance_1_1 = asset_balance(node1_addr, &asset_id_1).await;
    let balance_2_1 = asset_balance(node2_addr, &asset_id_1).await;
    let balance_1_2 = asset_balance(node1_addr, &asset_id_2).await;
    let balance_2_2 = asset_balance(node2_addr, &asset_id_2).await;
    assert_eq!(balance_1_1.offchain_outbound, 590);
    assert_eq!(balance_1_1.offchain_inbound, 10);
    assert_eq!(balance_2_1.offchain_outbound, 10);
    assert_eq!(balance_2_1.offchain_inbound, 590);
    assert_eq!(balance_1_2.offchain_outbound, 50);
    assert_eq!(balance_1_2.offchain_inbound, 100);
    assert_eq!(balance_2_2.offchain_outbound, 100);
    assert_eq!(balance_2_2.offchain_inbound, 50);

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Succeeded);
    let swaps_taker = list_swaps(taker_addr).await;
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.status, SwapStatus::Succeeded);

    let payments_maker = list_payments(maker_addr).await;
    assert!(payments_maker.is_empty());
    let payments_taker = list_payments(taker_addr).await;
    assert!(payments_taker.is_empty());

    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    let chan_1_12 = channels_1
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_1_21 = channels_1
        .iter()
        .find(|c| c.channel_id == channel_21.channel_id)
        .unwrap();
    let chan_2_12 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_21 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_21.channel_id)
        .unwrap();
    let htlc_min_sat = HTLC_MIN_MSAT / 1000;
    assert_eq!(
        chan_1_12.local_balance_sat,
        chan_1_12_before.local_balance_sat - htlc_min_sat
    );
    assert_eq!(
        chan_1_21.local_balance_sat,
        chan_1_21_before.local_balance_sat + htlc_min_sat
    );
    assert_eq!(
        chan_2_12.local_balance_sat,
        chan_2_12_before.local_balance_sat + htlc_min_sat
    );
    assert_eq!(
        chan_2_21.local_balance_sat,
        chan_2_21_before.local_balance_sat - htlc_min_sat
    );

    println!("\nclose channels");
    close_channel(node1_addr, &channel_12.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id_1, 990).await;
    wait_for_balance(node2_addr, &asset_id_1, 10).await;

    close_channel(node2_addr, &channel_21.channel_id, &node1_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id_2, 50).await;
    wait_for_balance(node2_addr, &asset_id_2, 950).await;

    println!("\nspend assets");
    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id_1,
        Assignment::Fungible(200),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id_2,
        Assignment::Fungible(20),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node2_addr,
        &asset_id_1,
        Assignment::Fungible(5),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node2_addr,
        &asset_id_2,
        Assignment::Fungible(200),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id_1).await, 790);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id_1).await, 5);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id_1).await, 205);
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id_2).await, 30);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id_2).await, 750);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id_2).await, 220);
}
