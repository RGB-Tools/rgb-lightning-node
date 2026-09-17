use super::super::*;
use super::*;

const TEST_DIR_BASE: &str = "tmp/interoperability_ldk/";
const CHANNEL_CAPACITY_SAT: u64 = 600_000;
const FORWARD_PAYMENT_MSAT: u64 = 20_000_000;
const RETURN_PAYMENT_MSAT: u64 = 10_000_000;
// the two payments settle on-chain balances only at close, so channel balances are compared with a
// tolerance covering the commitment transaction fees
const FEE_TOLERANCE_SAT: u64 = 2_000;

/// Pay in both directions over a ready channel, then close it cooperatively
async fn exercise_channel(rln_addr: SocketAddr, stock: &mut StockLdkNode, rln_funded: bool) {
    wait_for_usable_channels(rln_addr, 1).await;
    let rln_channel = list_channels(rln_addr)
        .await
        .into_iter()
        .find(|channel| channel.peer_pubkey == stock.node_id && channel.ready)
        .unwrap();
    let initial_stock = stock.balances();
    let initial_stock_spendable = stock.onchain_spendable();

    if rln_funded {
        let invoice = stock.invoice(FORWARD_PAYMENT_MSAT);
        send_payment(rln_addr, invoice).await;
        let invoice = ln_invoice(rln_addr, Some(RETURN_PAYMENT_MSAT), None, None, 900)
            .await
            .invoice;
        stock.pay(&invoice);
    } else {
        let invoice = ln_invoice(rln_addr, Some(FORWARD_PAYMENT_MSAT), None, None, 900)
            .await
            .invoice;
        stock.pay(&invoice);
        let invoice = stock.invoice(RETURN_PAYMENT_MSAT);
        send_payment(rln_addr, invoice).await;
    }

    let final_stock = stock.balances();
    let final_rln = list_channels(rln_addr)
        .await
        .into_iter()
        .find(|channel| channel.channel_id == rln_channel.channel_id)
        .unwrap();
    let net_sat = (FORWARD_PAYMENT_MSAT - RETURN_PAYMENT_MSAT) / 1000;
    if rln_funded {
        assert!(final_stock.outbound_msat > initial_stock.outbound_msat);
        assert!(final_stock.inbound_msat < initial_stock.inbound_msat);
        let spent_sat = rln_channel.local_balance_sat - final_rln.local_balance_sat;
        assert!((net_sat..=net_sat + FEE_TOLERANCE_SAT).contains(&spent_sat));
    } else {
        assert!(final_stock.outbound_msat < initial_stock.outbound_msat);
        assert!(final_stock.inbound_msat > initial_stock.inbound_msat);
        let received_sat = final_rln.local_balance_sat - rln_channel.local_balance_sat;
        assert!((net_sat - FEE_TOLERANCE_SAT..=net_sat).contains(&received_sat));
    }

    close_channel(rln_addr, &rln_channel.channel_id, &stock.node_id, false).await;
    wait_for_stock_channel_closed(stock, initial_stock_spendable).await;
    assert!(list_channels(rln_addr).await.is_empty());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
// run with `cargo test -- --ignored interoperability`, needs to build the stock ldk-node fixture
#[ignore]
async fn stock_ldk_opens_pays_both_ways_and_closes() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_stock = format!("{TEST_DIR_BASE}stock");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;
    let node1_pubkey = node_info(node1_addr).await.pubkey;

    let (mut stock, stock_address) = StockLdkNode::start(&test_dir_stock, NODE2_PEER_PORT);
    fund_wallet(stock_address, 100_000_000);
    wait_for_stock_funds(&mut stock).await;
    stock.open_channel(&node1_pubkey, NODE1_PEER_PORT);
    wait_for_stock_channel_ready(&mut stock).await;

    exercise_channel(node1_addr, &mut stock, false).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
// run with `cargo test -- --ignored interoperability`, needs to build the stock ldk-node fixture
#[ignore]
async fn stock_ldk_opens_announced_channel_and_keeps_it_usable() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_stock = format!("{TEST_DIR_BASE}stock");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;
    let node1_pubkey = node_info(node1_addr).await.pubkey;

    let (mut stock, stock_address) = StockLdkNode::start(&test_dir_stock, NODE2_PEER_PORT);
    fund_wallet(stock_address, 100_000_000);
    wait_for_stock_funds(&mut stock).await;
    stock.open_announced_channel(&node1_pubkey, NODE1_PEER_PORT);
    wait_for_stock_channel_ready(&mut stock).await;
    wait_for_usable_channels(node1_addr, 1).await;

    for _ in 0..8 {
        mine(false);
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let channels = list_channels(node1_addr).await;
    assert_eq!(channels.len(), 1);
    assert!(channels[0].public);
    assert!(channels[0].ready);
    assert!(channels[0].is_usable);

    exercise_channel(node1_addr, &mut stock, false).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
// run with `cargo test -- --ignored interoperability`, needs to build the stock ldk-node fixture
#[ignore]
async fn rln_opens_pays_both_ways_and_closes() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_stock = format!("{TEST_DIR_BASE}stock");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;

    let (mut stock, _) = StockLdkNode::start(&test_dir_stock, NODE2_PEER_PORT);
    open_channel_funded_raw(
        node1_addr,
        &stock.node_id,
        Some(NODE2_PEER_PORT),
        Some(CHANNEL_CAPACITY_SAT),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        true,
        false,
    )
    .await
    .unwrap();
    wait_for_stock_channel_ready(&mut stock).await;

    exercise_channel(node1_addr, &mut stock, true).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
// run with `cargo test -- --ignored interoperability`, needs to build the stock ldk-node fixture
#[ignore]
async fn rgb_channel_to_stock_ldk_fails() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_stock = format!("{TEST_DIR_BASE}stock");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;
    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let (mut stock, _) = StockLdkNode::start(&test_dir_stock, NODE2_PEER_PORT);
    open_channel_raw(
        node1_addr,
        &stock.node_id,
        Some(NODE2_PEER_PORT),
        Some(100_000),
        None,
        Some(100),
        Some(&asset_id),
        None,
        None,
        None,
        None,
        true,
        false,
    )
    .await
    .expect("RGB channel attempt should pass RLN's local validation");

    // the stock node rejects the colored funding, so while it may hold the channel as pending for a
    // while, the channel never becomes ready on either side
    let t_0 = OffsetDateTime::now_utc();
    while (OffsetDateTime::now_utc() - t_0).as_seconds_f32() < 10.0 {
        assert!(list_channels(node1_addr).await.iter().all(|c| !c.ready));
        assert_eq!(stock.channels().1, 0);
        mine(false);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
