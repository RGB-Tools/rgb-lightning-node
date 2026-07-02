use super::*;

const TEST_DIR_BASE: &str = "tmp/transaction_sync/";
#[cfg(feature = "esplora")]
const TEST_DIR_BASE_ESPLORA: &str = "tmp/transaction_sync_esplora/";
#[cfg(feature = "esplora")]
const ESPLORA_URL_REGTEST: &str = "http://127.0.0.1:3002";

// send `invoice` from `node_address`, retrying while the payer has not yet found a route: the only
// route to the payee is multihop and is discovered through gossip, whose channel-announcement UTXO
// lookup goes through the indexer
async fn pay_retrying_route(node_address: SocketAddr, invoice: String) -> String {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let payload = SendPaymentRequest {
            invoice: invoice.clone(),
            amt_msat: None,
            asset_id: None,
            asset_amount: None,
        };
        let res = reqwest::Client::new()
            .post(format!("http://{node_address}/sendpayment"))
            .json(&payload)
            .send()
            .await
            .unwrap();
        if res.status().is_success() {
            let resp: SendPaymentResponse = res.json().await.unwrap();
            // TODO: remove unwrap once RGB offers are enabled
            return resp.payment_hash.unwrap();
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            panic!("multihop route to the payee never became available");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// `ln_indexer_url` selects the indexer LDK syncs against: `None` reuses the wallet's `indexer_url`
// (electrum), while `Some(..)` points LDK at a dedicated indexer
async fn transaction_sync_roundtrip(test_dir_base: &str, ln_indexer_url: Option<String>) {
    initialize();

    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");

    let ldk_chain_sync = || LdkChainSync::TransactionSync {
        indexer_url: ln_indexer_url.clone(),
    };

    let (node1_addr, _) =
        start_node_with(&test_dir_node1, NODE1_PEER_PORT, false, ldk_chain_sync()).await;
    let (node2_addr, _) =
        start_node_with(&test_dir_node2, NODE2_PEER_PORT, false, ldk_chain_sync()).await;
    let (node3_addr, _) =
        start_node_with(&test_dir_node3, NODE3_PEER_PORT, false, ldk_chain_sync()).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let node3_pubkey = node_info(node3_addr).await.pubkey;

    // give node2 some asset so it can fund the second channel
    let recipient_id = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(400),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);

    // open two announced asset channels forming the node1 -> node2 -> node3 path
    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        Some(3500000),
        Some(500),
        Some(&asset_id),
    )
    .await;
    let _channel_23 = open_channel(
        node2_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        Some(3500000),
        Some(300),
        Some(&asset_id),
    )
    .await;

    // multihop RGB payment node1 -> node3, routed through node2: as the far channel is public,
    // node1 has no route hint for it and must resolve the route from gossip, verifying
    // node2 -> node3's funding output through the indexer
    let LNInvoiceResponse { invoice } =
        ln_invoice(node3_addr, None, Some(&asset_id), Some(50), 900).await;
    let payment_hash = pay_retrying_route(node1_addr, invoice).await;
    wait_for_ln_payment(node1_addr, &payment_hash, HTLCStatus::Succeeded).await;

    wait_for_ln_balance(node1_addr, &asset_id, 450).await;
    wait_for_ln_balance(node3_addr, &asset_id, 50).await;

    // restart all nodes: they must sync to the chain tip via the indexer and re-establish their
    // channels
    shutdown(&[node1_addr, node2_addr, node3_addr]).await;
    let (node1_addr, _) =
        start_node_with(&test_dir_node1, NODE1_PEER_PORT, true, ldk_chain_sync()).await;
    let (node2_addr, _) =
        start_node_with(&test_dir_node2, NODE2_PEER_PORT, true, ldk_chain_sync()).await;
    let (node3_addr, _) =
        start_node_with(&test_dir_node3, NODE3_PEER_PORT, true, ldk_chain_sync()).await;

    wait_for_usable_channels(node1_addr, 1).await;
    wait_for_usable_channels(node2_addr, 2).await;
    wait_for_usable_channels(node3_addr, 1).await;
    wait_for_ln_balance(node1_addr, &asset_id, 450).await;
    wait_for_ln_balance(node3_addr, &asset_id, 50).await;

    // cooperatively close the node1 -> node2 channel and check the asset returns on-chain to both
    // the initiating and the counterparty node
    close_channel(node2_addr, &channel_12.channel_id, &node1_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 550).await;
    wait_for_balance(node2_addr, &asset_id, 150).await;
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn transaction_sync_electrum() {
    transaction_sync_roundtrip(TEST_DIR_BASE, None).await;
}

// point LDK at a dedicated esplora source while the RGB wallet keeps using electrum
#[cfg(feature = "esplora")]
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn transaction_sync_esplora() {
    transaction_sync_roundtrip(TEST_DIR_BASE_ESPLORA, Some(ESPLORA_URL_REGTEST.to_string())).await;
}
