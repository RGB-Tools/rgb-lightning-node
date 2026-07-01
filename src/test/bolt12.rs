use super::*;
use crate::routes::BitcoinNetwork as RouteBitcoinNetwork;

const TEST_DIR_BASE: &str = "tmp/bolt12/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn offer_roundtrip() {
    initialize();

    let test_dir_base = format!("{TEST_DIR_BASE}offer_roundtrip/");
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_pubkey = node_info(node2_addr).await.pubkey;
    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        None,
        None,
    )
    .await;

    let offer = ln_offer(node2_addr, Some(50_000), Some("bolt12 test"), Some(900))
        .await
        .offer;
    let decoded_offer = decode_offer(node1_addr, &offer).await;
    assert_eq!(decoded_offer.amt_msat, Some(50_000));
    assert_eq!(decoded_offer.description, Some("bolt12 test".to_string()));
    assert!(!decoded_offer.is_expired);
    assert_eq!(decoded_offer.chains, vec![RouteBitcoinNetwork::Regtest]);
    assert_eq!(decoded_offer.supported_quantity_max, None);
    assert!(decoded_offer.path_count > 0);

    let send_payment = send_payment_raw(node1_addr, offer).await;
    assert_eq!(send_payment.status, HTLCStatus::Pending);
    let payment_id = send_payment.payment_id;

    let sender_payment =
        wait_for_ln_payment_by_id(node1_addr, &payment_id, HTLCStatus::Succeeded).await;
    assert_eq!(sender_payment.amt_msat, Some(50_000));
    assert!(!sender_payment.inbound);
    assert_eq!(sender_payment.status, HTLCStatus::Succeeded);

    let receiver_payment = list_payments(node2_addr)
        .await
        .into_iter()
        .find(|payment| payment.inbound && payment.status == HTLCStatus::Succeeded)
        .expect("expected inbound BOLT12 payment");
    assert_eq!(receiver_payment.amt_msat, Some(50_000));
}
