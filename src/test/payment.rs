use crate::routes::BitcoinNetwork;

use super::*;

const TEST_DIR_BASE: &str = "tmp/payment/";
const NODE1_PEER_PORT: u16 = 9821;
const NODE2_PEER_PORT: u16 = 9822;
const NODE3_PEER_PORT: u16 = 9823;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn payment() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), Some(100), 900).await;
    send_payment_with_ln_balance(node1_addr, node2_addr, invoice.clone(), Some(600), Some(0)).await;

    let decoded = decode_ln_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.expiry_sec, 900);
    assert_eq!(decoded.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded.asset_amount, Some(100));
    assert_eq!(decoded.payee_pubkey, Some(node2_pubkey.clone()));
    assert!(matches!(decoded.network, BitcoinNetwork::Regtest));
    let status = invoice_status(node2_addr, &invoice).await;
    assert!(matches!(status, InvoiceStatus::Succeeded));

    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), Some(50), 900).await;
    send_payment_with_ln_balance(
        node2_addr,
        node1_addr,
        invoice.clone(),
        Some(100),
        Some(500),
    )
    .await;

    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), Some(50), 900).await;
    let _ = send_payment(node1_addr, invoice.clone()).await;

    let LNInvoiceResponse { invoice } =
        ln_invoice(node1_addr, None, Some(&asset_id), Some(50), 900).await;
    let _ = send_payment(node2_addr, invoice.clone()).await;

    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 950).await;
    wait_for_balance(node2_addr, &asset_id, 50).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 925, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node2_addr, &asset_id, 25, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 25);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 25);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 950);
}
