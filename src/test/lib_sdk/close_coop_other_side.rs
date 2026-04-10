use crate::helpers::*;
use serial_test::serial;
use std::{fs, time::Duration};

#[test]
#[serial]
fn close_coop_other_side() {
    ensure_regtest_available();

    let test_dir = test_dir("close_coop_other_side");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 60, NODE_A_PEER_PORT + 60);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 60, NODE_B_PEER_PORT + 60);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 60, NODE_C_PEER_PORT + 60);

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

        fund_and_create_utxos(&node_a, "node A");
        fund_and_create_utxos(&node_b, "node B");
        fund_and_create_utxos(&node_c, "node C");

        // Mirrors the HTTP test: use CFA to cover non-NIA assets in channel lifecycle tests.
        let asset_id = node_a
            .issueassetcfa(SdkIssueAssetCfaRequest {
                amounts: vec![2_000],
                name: "Collectible".to_string(),
                details: None,
                precision: 0,
                file_digest: None,
            })
            .expect("node A issueassetcfa")
            .asset_id;

        let node_a_pubkey = node_a.node_info().expect("node A node_info").pubkey;
        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;

        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 60);
        node_a
            .connectpeer(peer_uri.clone())
            .expect("node A connectpeer");

        let open_channel = node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat: 0,
                public: true,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(600),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("node A openchannel");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(120));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 1400);

        let channel_id = node_a
            .get_channel_id(open_channel.temporary_channel_id)
            .expect("node A get_channel_id");

        keysend(&node_a, node_b_pubkey, None, Some(&asset_id), Some(100));

        close_channel(&node_b, channel_id, node_a_pubkey);
        wait_for_balance(&node_a, &asset_id, 1900, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 100, Duration::from_secs(70));

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice first")
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
                        recipient_id: RecipientId(recipient_id.0),
                        witness_data: None,
                        assignment_kind: AssignmentKind::Fungible,
                        assignment_amount: Some(700),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb first");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_a);

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice second")
            .recipient_id;
        node_b
            .send_rgb(SendRgbRequest {
                donation: true,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                min_confirmations: 1,
                skip_sync: false,
                recipient_groups: vec![AssetRecipients {
                    asset_id: asset_id.clone(),
                    recipients: vec![RgbRecipient {
                        recipient_id: RecipientId(recipient_id.0),
                        witness_data: None,
                        assignment_kind: AssignmentKind::Fungible,
                        assignment_amount: Some(50),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node B send_rgb second");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_b);

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 1200);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 50);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 750);
    }));

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
