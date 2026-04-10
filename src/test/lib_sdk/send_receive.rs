use crate::helpers::*;
use serial_test::serial;
use std::fs;
use std::time::Duration;

#[test]
#[serial]
fn send_receive() {
    ensure_regtest_available();

    let test_dir = test_dir("sdk_send_receive");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 10, NODE_A_PEER_PORT + 10);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 10, NODE_B_PEER_PORT + 10);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 10, NODE_C_PEER_PORT + 10);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node_a
            .init("nodeApass".to_string(), None)
            .expect("node A init");
        node_b
            .init("nodeBpass".to_string(), None)
            .expect("node B init");
        node_c
            .init("nodeCpass".to_string(), None)
            .expect("node C init");

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock");
        node_c
            .unlock(unlock_request("nodeCpass"))
            .expect("node C unlock");

        let net_info = node_a.network_info().expect("node A network_info");
        assert_eq!(net_info.network, "Regtest");
        let height_1 = net_info.height;

        fund_and_create_utxos(&node_a, "node A");
        fund_and_create_utxos(&node_b, "node B");
        fund_and_create_utxos(&node_c, "node C");

        let asset_id = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "USDT".to_string(),
                name: "Tether".to_string(),
                precision: 0,
            })
            .expect("node A issueassetnia")
            .asset_id;

        let recipient_id_n2a = node_b
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node B rgbinvoice first")
            .recipient_id;
        node_a
            .send_rgb(SendRgbRequest {
                donation: true,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                min_confirmations: 1,
                skip_sync: false,
                recipient_groups: vec![AssetRecipients {
                    asset_id: asset_id.clone(),
                    recipients: vec![RgbRecipient {
                        recipient_id: RecipientId(recipient_id_n2a.0),
                        witness_data: None,
                        assignment_kind: AssignmentKind::Fungible,
                        assignment_amount: Some(400),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb first");
        mine(1);
        refresh_transfers(&node_b);
        refresh_transfers(&node_b);
        refresh_transfers(&node_a);
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 600);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 400);

        let asset_id_2 = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "USDT2".to_string(),
                name: "Tether 2".to_string(),
                precision: 0,
            })
            .expect("node A issueassetnia second")
            .asset_id;
        let recipient_id_n2a_asset2 = node_b
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node B rgbinvoice second asset")
            .recipient_id;
        node_a
            .send_rgb(SendRgbRequest {
                donation: true,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                min_confirmations: 1,
                skip_sync: false,
                recipient_groups: vec![AssetRecipients {
                    asset_id: asset_id_2.clone(),
                    recipients: vec![RgbRecipient {
                        recipient_id: RecipientId(recipient_id_n2a_asset2.0),
                        witness_data: None,
                        assignment_kind: AssignmentKind::Fungible,
                        assignment_amount: Some(300),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb second asset");
        mine(1);
        refresh_transfers(&node_b);
        refresh_transfers(&node_b);
        refresh_transfers(&node_a);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id_2), 300);

        let node_a_invoice = node_a
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: Some(asset_id.clone()),
                assignment_kind: Some(AssignmentKind::Fungible),
                assignment_amount: Some(200),
                duration_seconds: None,
                min_confirmations: 1,
                witness: true,
            })
            .expect("node A rgbinvoice with assignment");
        let recipient_id_n1a = node_a_invoice.recipient_id;
        let recipient_id_n1a_str = recipient_id_n1a.0.clone();
        let invoice = node_a_invoice.invoice;

        let recipient_id_n3a = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: true,
            })
            .expect("node C rgbinvoice witness")
            .recipient_id;
        let recipient_id_n1a_asset2 = node_a
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: Some(asset_id_2.clone()),
                assignment_kind: Some(AssignmentKind::Fungible),
                assignment_amount: Some(100),
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node A rgbinvoice second asset receive")
            .recipient_id;
        node_b
            .send_rgb(SendRgbRequest {
                donation: true,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                min_confirmations: 1,
                skip_sync: false,
                recipient_groups: vec![
                    AssetRecipients {
                        asset_id: asset_id.clone(),
                        recipients: vec![
                            RgbRecipient {
                                recipient_id: RecipientId(recipient_id_n1a_str.clone()),
                                witness_data: Some(WitnessData {
                                    amount_sat: 1200,
                                    blinding: None,
                                }),
                                assignment_kind: AssignmentKind::Fungible,
                                assignment_amount: Some(200),
                                transport_endpoints: vec![TransportEndpoint(
                                    PROXY_ENDPOINT_LOCAL.to_string(),
                                )],
                            },
                            RgbRecipient {
                                recipient_id: RecipientId(recipient_id_n3a.0),
                                witness_data: Some(WitnessData {
                                    amount_sat: 1200,
                                    blinding: None,
                                }),
                                assignment_kind: AssignmentKind::Fungible,
                                assignment_amount: Some(50),
                                transport_endpoints: vec![TransportEndpoint(
                                    PROXY_ENDPOINT_LOCAL.to_string(),
                                )],
                            },
                        ],
                    },
                    AssetRecipients {
                        asset_id: asset_id_2.clone(),
                        recipients: vec![RgbRecipient {
                            recipient_id: RecipientId(recipient_id_n1a_asset2.0),
                            witness_data: None,
                            assignment_kind: AssignmentKind::Fungible,
                            assignment_amount: Some(100),
                            transport_endpoints: vec![TransportEndpoint(
                                PROXY_ENDPOINT_LOCAL.to_string(),
                            )],
                        }],
                    },
                ],
            })
            .expect("node B send_rgb batch");
        mine(1);
        refresh_transfers(&node_a);
        refresh_transfers(&node_a);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_b);
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 800);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 150);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 50);
        assert_eq!(asset_balance_spendable(&node_a, &asset_id_2), 800);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id_2), 200);

        let decoded = wait_for_decoded_rgb_invoice_with_expiration(
            &node_a,
            &invoice,
            Duration::from_secs(20),
        );
        assert_eq!(decoded.recipient_id, recipient_id_n1a_str);
        assert_eq!(decoded.asset_schema, Some("Nia".to_string()));
        assert_eq!(decoded.asset_id, Some(asset_id.clone()));
        assert_eq!(decoded.assignment, "Fungible(200)");
        assert_eq!(decoded.network, "Regtest");
        assert!(decoded.expiration_timestamp.is_some());
        assert_eq!(
            decoded.transport_endpoints,
            vec![PROXY_ENDPOINT_LOCAL.to_string()]
        );

        let recipient_id_n2b = node_b
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: Some(AssignmentKind::Fungible),
                assignment_amount: Some(100),
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node B rgbinvoice final transfer")
            .recipient_id;
        let recipient_id_n3b = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: Some(AssignmentKind::Fungible),
                assignment_amount: Some(150),
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice final transfer")
            .recipient_id;
        node_a
            .send_rgb(SendRgbRequest {
                donation: true,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                min_confirmations: 1,
                skip_sync: false,
                recipient_groups: vec![AssetRecipients {
                    asset_id: asset_id.clone(),
                    recipients: vec![
                        RgbRecipient {
                            recipient_id: RecipientId(recipient_id_n2b.0),
                            witness_data: None,
                            assignment_kind: AssignmentKind::Fungible,
                            assignment_amount: Some(100),
                            transport_endpoints: vec![TransportEndpoint(
                                PROXY_ENDPOINT_LOCAL.to_string(),
                            )],
                        },
                        RgbRecipient {
                            recipient_id: RecipientId(recipient_id_n3b.0),
                            witness_data: None,
                            assignment_kind: AssignmentKind::Fungible,
                            assignment_amount: Some(150),
                            transport_endpoints: vec![TransportEndpoint(
                                PROXY_ENDPOINT_LOCAL.to_string(),
                            )],
                        },
                    ],
                }],
            })
            .expect("node A send_rgb final");
        mine(1);
        refresh_transfers(&node_b);
        refresh_transfers(&node_b);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_a);
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 550);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 250);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 200);

        let addr = node_b.address().expect("node B address").address;
        node_a
            .sendbtc(SdkSendBtcRequest {
                amount: 1000,
                address: addr,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .expect("node A sendbtc");

        let net_info = node_a.network_info().expect("node A network_info final");
        assert_eq!(net_info.height, height_1 + 10);
    }));

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
