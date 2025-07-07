use super::*;

const TEST_DIR_BASE: &str = "tmp/swap_roundtrip_fail_timeout/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn swap_roundtrip_fail_timeout() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;

    let maker_addr = node1_addr;
    let taker_addr = node2_addr;

    println!("\nswap 1");
    // create a swap with a timeout of 1 second
    let qty_from_1 = 50000;
    let qty_to_1 = 10;
    let maker_init_response_1 =
        maker_init(maker_addr, qty_from_1, None, qty_to_1, Some(&asset_id), 1).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert!(swaps_maker.taker.is_empty());
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.qty_from, qty_from_1);
    assert_eq!(swap_maker.qty_to, qty_to_1);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response_1.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);

    // wait for the swap to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // try adding an expired swap, which should fail
    let payload = TakerRequest {
        swapstring: maker_init_response_1.swapstring.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{taker_addr}/taker"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let res_text = res.text().await;
    assert!(res_text.unwrap().contains("The swap offer has expired"));

    // check maker swap has expired and taker has not added it
    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 1);
    let swap_maker = swaps_maker.maker.first().unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Expired);
    let swaps_taker = list_swaps(taker_addr).await;
    assert!(swaps_taker.taker.is_empty());

    println!("\nswap 2");
    // create a swap with a timeout of 10 seconds
    let qty_from_2 = 40000;
    let qty_to_2 = 20;
    let maker_init_response_2 =
        maker_init(maker_addr, qty_from_2, None, qty_to_2, Some(&asset_id), 10).await;

    // add the swap
    taker(taker_addr, maker_init_response_2.swapstring.clone()).await;

    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 2);
    let swap_maker = swaps_maker
        .maker
        .iter()
        .find(|s| s.payment_hash == maker_init_response_2.payment_hash)
        .unwrap();
    assert_eq!(swap_maker.qty_from, qty_from_2);
    assert_eq!(swap_maker.qty_to, qty_to_2);
    assert_eq!(swap_maker.from_asset, None);
    assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_maker.payment_hash, maker_init_response_2.payment_hash);
    assert_eq!(swap_maker.status, SwapStatus::Waiting);
    let swaps_taker = list_swaps(taker_addr).await;
    assert!(swaps_taker.maker.is_empty());
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.qty_from, qty_from_2);
    assert_eq!(swap_taker.qty_to, qty_to_2);
    assert_eq!(swap_taker.from_asset, None);
    assert_eq!(swap_taker.to_asset, Some(asset_id.clone()));
    assert_eq!(swap_taker.payment_hash, maker_init_response_2.payment_hash);
    assert_eq!(swap_taker.status, SwapStatus::Waiting);

    // wait for the swap to expire
    tokio::time::sleep(Duration::from_secs(15)).await;

    // execute the expired swap
    let res = maker_execute_raw(
        maker_addr,
        maker_init_response_2.swapstring,
        maker_init_response_2.payment_secret,
        node2_pubkey.clone(),
    )
    .await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::BAD_REQUEST,
        "The swap offer has expired",
        "ExpiredSwapOffer",
    )
    .await;

    // check swaps
    let swaps_maker = list_swaps(maker_addr).await;
    assert_eq!(swaps_maker.maker.len(), 2);
    let swap_maker = swaps_maker
        .maker
        .iter()
        .find(|s| s.payment_hash == maker_init_response_2.payment_hash)
        .unwrap();
    assert_eq!(swap_maker.status, SwapStatus::Expired);
    let swaps_taker = list_swaps(taker_addr).await;
    assert_eq!(swaps_taker.taker.len(), 1);
    let swap_taker = swaps_taker.taker.first().unwrap();
    assert_eq!(swap_taker.status, SwapStatus::Expired);

    let payments_maker = list_payments(maker_addr).await;
    assert!(payments_maker.is_empty());
    let payments_taker = list_payments(taker_addr).await;
    assert!(payments_taker.is_empty());
}
