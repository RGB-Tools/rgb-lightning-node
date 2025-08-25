use crate::routes::{AssetSchema, BitcoinNetwork};

use super::*;

const TEST_DIR_BASE: &str = "tmp/send_receive/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn send_receive() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    let net_info = network_info(node1_addr).await;
    assert_eq!(net_info.network, BitcoinNetwork::Regtest);
    let height_1 = net_info.height;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let recipient_id = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(400),
        recipient_id,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 400);

    let RgbInvoiceResponse {
        recipient_id,
        invoice,
        ..
    } = rgb_invoice(node1_addr, Some(asset_id.clone()), false).await;
    send_asset(
        node2_addr,
        &asset_id,
        Assignment::Fungible(300),
        recipient_id.clone(),
    )
    .await;
    mine(false);
    refresh_transfers(node1_addr).await;
    refresh_transfers(node1_addr).await;
    refresh_transfers(node2_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 900);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 100);

    // check decoded RGB invoice (with asset ID)
    let decoded = decode_rgb_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.recipient_id, recipient_id);
    assert!(matches!(decoded.asset_schema, Some(AssetSchema::Nia)));
    assert_eq!(decoded.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded.assignment, Assignment::Fungible(0));
    assert!(matches!(decoded.network, BitcoinNetwork::Regtest));
    assert!(decoded.expiration_timestamp.is_some());
    assert_eq!(decoded.transport_endpoints, vec![PROXY_ENDPOINT_LOCAL]);

    let recipient_id = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(200),
        recipient_id,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 700);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 300);

    // send some BTC
    let addr = address(node2_addr).await;
    send_btc(node1_addr, 1000, &addr).await;

    // check network info reports the increased height
    let net_info = network_info(node1_addr).await;
    assert_eq!(net_info.height, height_1 + 7); // 4x from funding (2 each) + 3x from transfers)
}
