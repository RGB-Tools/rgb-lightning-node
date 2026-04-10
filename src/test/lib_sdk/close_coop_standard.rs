use crate::helpers::*;
use rgb_lightning_node::SdkDisconnectPeerRequest;
use serial_test::serial;
use std::{fs, time::Duration};

#[test]
#[serial]
fn close_coop_standard() {
    ensure_regtest_available();

    let test_dir = test_dir("sdk_close_coop_standard");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 20, NODE_A_PEER_PORT + 20);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 20, NODE_B_PEER_PORT + 20);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 20, NODE_C_PEER_PORT + 20);

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

        let unspents = node_a
            .list_unspents(false)
            .expect("node A list_unspents before");
        assert_eq!(unspents.len(), 0);

        fund_and_create_utxos(&node_a, "node A");
        fund_and_create_utxos(&node_b, "node B");
        fund_and_create_utxos(&node_c, "node C");

        let unspents = node_a
            .list_unspents(false)
            .expect("node A list_unspents after");
        assert_eq!(unspents.len(), 11);

        let assets = node_a
            .list_assets(vec![])
            .expect("node A list_assets before");
        assert_eq!(assets.nia.expect("nia before").len(), 0);
        assert_eq!(assets.uda.expect("uda before").len(), 0);
        assert_eq!(assets.cfa.expect("cfa before").len(), 0);

        let asset_id = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "USDT".to_string(),
                name: "Tether".to_string(),
                precision: 0,
            })
            .expect("node A issueassetnia")
            .asset_id;

        let assets = node_a
            .list_assets(vec![])
            .expect("node A list_assets after");
        assert_eq!(assets.nia.expect("nia after").len(), 1);
        assert_eq!(assets.uda.expect("uda after").len(), 0);
        assert_eq!(assets.cfa.expect("cfa after").len(), 0);

        let node_a_pubkey = node_a.node_info().expect("node A node_info").pubkey;
        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;

        let peers = node_a.list_peers().expect("node A list_peers before");
        assert!(!peers.iter().any(|peer| peer.pubkey == node_b_pubkey));

        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 20);
        node_a
            .connectpeer(peer_uri.clone())
            .expect("node A connectpeer");

        let peers = node_a
            .list_peers()
            .expect("node A list_peers after connect");
        assert!(peers.iter().any(|peer| peer.pubkey == node_b_pubkey));

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
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 400);

        let channel_id = node_a
            .get_channel_id(open_channel.temporary_channel_id)
            .expect("node A get_channel_id");

        keysend_with_ln_balance(
            &node_a,
            &node_b,
            node_b_pubkey,
            Some(6_000_000),
            &asset_id,
            150,
            600,
            0,
        );
        keysend_with_ln_balance(
            &node_b,
            &node_a,
            node_a_pubkey,
            None,
            &asset_id,
            50,
            150,
            450,
        );

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice pre-close")
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
                        assignment_amount: Some(10),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb pre-close");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_a);
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 390);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 10);

        close_channel(&node_a, channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 890, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 100, Duration::from_secs(70));

        let peers = node_a
            .list_peers()
            .expect("node A list_peers before disconnect");
        assert!(peers.iter().any(|peer| peer.pubkey == node_b_pubkey));
        node_a
            .disconnectpeer(SdkDisconnectPeerRequest {
                peer_pubkey: node_b_pubkey,
            })
            .expect("node A disconnectpeer");
        let peers = node_a
            .list_peers()
            .expect("node A list_peers after disconnect");
        assert!(!peers.iter().any(|peer| peer.pubkey == node_b_pubkey));

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice post-close node A")
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
                        assignment_amount: Some(690),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb post-close");
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
            .expect("node C rgbinvoice post-close node B")
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
            .expect("node B send_rgb post-close");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_b);

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 200);
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
