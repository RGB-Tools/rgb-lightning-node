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
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    let net_info = network_info(node1_addr).await;
    assert_eq!(net_info.network, BitcoinNetwork::Regtest);
    let height_1 = net_info.height;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let recipient_id_n2a = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(400),
        recipient_id_n2a,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 400);

    let asset_id_2 = issue_asset_nia(node1_addr).await.asset_id;
    let recipient_id_n2a_asset2 = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id_2,
        Assignment::Fungible(300),
        recipient_id_n2a_asset2,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id_2).await, 300);

    let RgbInvoiceResponse {
        recipient_id: recipient_id_n1a,
        invoice,
        ..
    } = rgb_invoice_with_assignment(
        node1_addr,
        Some(asset_id.clone()),
        Some(Assignment::Fungible(200)),
        true,
    )
    .await;
    let recipient_id_n3a = rgb_invoice(node3_addr, None, true).await.recipient_id;
    let recipient_id_n1a_asset2 = rgb_invoice_with_assignment(
        node1_addr,
        Some(asset_id_2.clone()),
        Some(Assignment::Fungible(100)),
        false,
    )
    .await
    .recipient_id;
    send_assets(
        node2_addr,
        HashMap::from([
            (
                asset_id.clone(),
                vec![
                    Recipient {
                        recipient_id: recipient_id_n1a.clone(),
                        witness_data: Some(WitnessData {
                            amount_sat: 1200,
                            blinding: None,
                        }),
                        assignment: Assignment::Fungible(200),
                        transport_endpoints: vec![PROXY_ENDPOINT_LOCAL.to_string()],
                    },
                    Recipient {
                        recipient_id: recipient_id_n3a,
                        witness_data: Some(WitnessData {
                            amount_sat: 1200,
                            blinding: None,
                        }),
                        assignment: Assignment::Fungible(50),
                        transport_endpoints: vec![PROXY_ENDPOINT_LOCAL.to_string()],
                    },
                ],
            ),
            (
                asset_id_2.clone(),
                vec![Recipient {
                    recipient_id: recipient_id_n1a_asset2,
                    witness_data: None,
                    assignment: Assignment::Fungible(100),
                    transport_endpoints: vec![PROXY_ENDPOINT_LOCAL.to_string()],
                }],
            ),
        ]),
        true,
    )
    .await;
    mine(false);
    refresh_transfers(node1_addr).await;
    refresh_transfers(node1_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 800);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 150);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 50);
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id_2).await, 800);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id_2).await, 200);

    // check decoded RGB invoice (with asset ID)
    let decoded = decode_rgb_invoice(node1_addr, &invoice).await;
    assert_eq!(decoded.recipient_id, recipient_id_n1a);
    assert!(matches!(decoded.asset_schema, Some(AssetSchema::Nia)));
    assert_eq!(decoded.asset_id, Some(asset_id.clone()));
    assert_eq!(decoded.assignment, Assignment::Fungible(200));
    assert!(matches!(decoded.network, BitcoinNetwork::Regtest));
    assert!(decoded.expiration_timestamp.is_some());
    assert_eq!(decoded.transport_endpoints, vec![PROXY_ENDPOINT_LOCAL]);

    let recipient_id_n2b =
        rgb_invoice_with_assignment(node2_addr, None, Some(Assignment::Fungible(100)), false)
            .await
            .recipient_id;
    let recipient_id_n3b =
        rgb_invoice_with_assignment(node3_addr, None, Some(Assignment::Fungible(150)), false)
            .await
            .recipient_id;
    send_assets(
        node1_addr,
        HashMap::from([(
            asset_id.clone(),
            vec![
                Recipient {
                    recipient_id: recipient_id_n2b,
                    witness_data: None,
                    assignment: Assignment::Fungible(100),
                    transport_endpoints: vec![PROXY_ENDPOINT_LOCAL.to_string()],
                },
                Recipient {
                    recipient_id: recipient_id_n3b,
                    witness_data: None,
                    assignment: Assignment::Fungible(150),
                    transport_endpoints: vec![PROXY_ENDPOINT_LOCAL.to_string()],
                },
            ],
        )]),
        true,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 550);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 250);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 200);

    // send some BTC
    let addr = address(node2_addr).await;
    send_btc(node1_addr, 1000, &addr).await;

    // check network info reports the increased height
    // 6x from funding (2 each for 3 nodes) + 4x from transfers (1st transfer, 2nd asset transfer, batch transfer, 3rd transfer)
    let net_info = network_info(node1_addr).await;
    assert_eq!(net_info.height, height_1 + 10);
}
