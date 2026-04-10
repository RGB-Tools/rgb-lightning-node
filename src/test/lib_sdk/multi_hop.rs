use crate::helpers::*;
use rgb_lightning_node::SdkDisconnectPeerRequest;
use serial_test::serial;
use std::{fs, time::Duration};

#[test]
#[serial]
fn multi_hop() {
    ensure_regtest_available();

    let test_dir = test_dir("multi_hop");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 70, NODE_A_PEER_PORT + 70);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 70, NODE_B_PEER_PORT + 70);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 70, NODE_C_PEER_PORT + 70);

    // Like the original HTTP test, this scenario restarts all three nodes mid-test on the same
    // storage dirs. That changes the active SDK handles inside the closure, so the final shutdown
    // of the restarted nodes happens in-closure rather than in the outer catch_unwind cleanup.
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

        let asset_id = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "USDT".to_string(),
                name: "Tether".to_string(),
                precision: 0,
            })
            .expect("node A issueassetnia")
            .asset_id;

        let node_a_info = node_a.node_info().expect("node A node_info initial");
        let node_b_info = node_b.node_info().expect("node B node_info initial");
        let node_c_info = node_c.node_info().expect("node C node_info initial");
        let node_a_pubkey = node_a_info.pubkey;
        let node_b_pubkey = node_b_info.pubkey;
        let node_c_pubkey = node_c_info.pubkey;

        assert_eq!(node_a_info.num_channels, 0);
        assert_eq!(node_a_info.num_usable_channels, 0);
        assert_eq!(node_a_info.local_balance_sat, 0);
        assert_eq!(node_a_info.num_peers, 0);
        assert_eq!(node_b_info.num_channels, 0);
        assert_eq!(node_b_info.num_usable_channels, 0);
        assert_eq!(node_b_info.local_balance_sat, 0);
        assert_eq!(node_b_info.num_peers, 0);
        assert_eq!(node_c_info.num_channels, 0);
        assert_eq!(node_c_info.num_usable_channels, 0);
        assert_eq!(node_c_info.local_balance_sat, 0);
        assert_eq!(node_c_info.num_peers, 0);

        let recipient_id = node_b
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node B rgbinvoice pre-channel")
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
                        assignment_amount: Some(400),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb pre-channel");
        mine(1);
        refresh_transfers(&node_b);
        refresh_transfers(&node_b);
        refresh_transfers(&node_a);
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 600);

        let push_msat = 3_500_000;

        let peer_uri_ab = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 70);
        let open_channel_12 = node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri_ab,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat,
                public: true,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(500),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("node A openchannel to node B");
        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(120));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 100);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 400);

        let peer_uri_bc = format!("{node_c_pubkey}@127.0.0.1:{}", NODE_C_PEER_PORT + 70);
        let open_channel_23 = node_b
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri_bc,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat,
                public: true,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(300),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("node B openchannel to node C");
        wait_for_channel_funding_tx(&node_b, &node_c, &asset_id, Duration::from_secs(120));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_b, &node_c, &asset_id, Duration::from_secs(300));
        wait_for_usable_channel_counts(
            &[(&node_a, 1), (&node_b, 2), (&node_c, 1)],
            Duration::from_secs(180),
        );
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 100);

        let balance_1 = wait_for_asset_balance(&node_a, &asset_id, Duration::from_secs(30));
        let balance_2 = wait_for_asset_balance(&node_b, &asset_id, Duration::from_secs(30));
        let balance_3 = wait_for_asset_balance(&node_c, &asset_id, Duration::from_secs(30));
        assert_eq!(balance_1.offchain_outbound, 500);
        assert_eq!(balance_1.offchain_inbound, 0);
        assert_eq!(balance_2.offchain_outbound, 300);
        assert_eq!(balance_2.offchain_inbound, 500);
        assert_eq!(balance_3.offchain_outbound, 0);
        assert_eq!(balance_3.offchain_inbound, 300);

        let channel_id_12 = node_a
            .get_channel_id(open_channel_12.temporary_channel_id)
            .expect("node A get_channel_id 12");
        let channel_id_23 = node_b
            .get_channel_id(open_channel_23.temporary_channel_id)
            .expect("node B get_channel_id 23");

        let channels_1_before = node_a.list_channels().expect("node A list_channels before");
        let channels_2_before = node_b.list_channels().expect("node B list_channels before");
        let channels_3_before = node_c.list_channels().expect("node C list_channels before");
        assert_eq!(channels_1_before.len(), 1);
        assert_eq!(channels_3_before.len(), 1);

        let chan_1_12_before = channels_1_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node A channel 12 before");
        let chan_2_12_before = channels_2_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node B channel 12 before");
        let chan_2_23_before = channels_2_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_23)
            .expect("node B channel 23 before");
        let chan_3_23_before = channels_3_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_23)
            .expect("node C channel 23 before");
        assert_eq!(chan_1_12_before.asset_local_amount, Some(500));
        assert_eq!(chan_1_12_before.asset_remote_amount, Some(0));
        assert_eq!(chan_2_12_before.asset_local_amount, Some(0));
        assert_eq!(chan_2_12_before.asset_remote_amount, Some(500));
        assert_eq!(chan_2_23_before.asset_local_amount, Some(300));
        assert_eq!(chan_2_23_before.asset_remote_amount, Some(0));
        assert_eq!(chan_3_23_before.asset_local_amount, Some(0));
        assert_eq!(chan_3_23_before.asset_remote_amount, Some(300));

        let node_a_info = node_a.node_info().expect("node A node_info before payment");
        let node_b_info = node_b.node_info().expect("node B node_info before payment");
        let node_c_info = node_c.node_info().expect("node C node_info before payment");
        let capacity = OPEN_CHANNEL_CAPACITY_SAT;
        let push_sat = push_msat / 1000;
        let max_expected_fee = 5_000;
        assert_eq!(node_a_info.num_channels, 1);
        assert_eq!(node_a_info.num_usable_channels, 1);
        assert!(node_a_info.local_balance_sat <= capacity - push_sat);
        assert!(node_a_info.local_balance_sat >= capacity - push_sat - max_expected_fee);
        assert_eq!(node_a_info.num_peers, 1);
        assert_eq!(node_b_info.num_channels, 2);
        assert_eq!(node_b_info.num_usable_channels, 2);
        assert!(node_b_info.local_balance_sat <= capacity);
        assert!(node_b_info.local_balance_sat >= capacity - max_expected_fee);
        assert_eq!(node_b_info.num_peers, 2);
        assert_eq!(node_c_info.num_channels, 1);
        assert_eq!(node_c_info.num_usable_channels, 1);
        assert_eq!(node_c_info.local_balance_sat, push_sat);
        assert_eq!(node_c_info.num_peers, 1);

        let invoice = node_c
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(50),
                payment_hash: None,
            })
            .expect("node C ln_invoice")
            .invoice;
        let send_payment = node_a
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("node A sendpayment");
        let payment_hash = send_payment
            .payment_hash
            .expect("payment hash for multi-hop payment");
        wait_for_payment_status(&node_a, &payment_hash, Duration::from_secs(60));
        wait_for_payment_status(&node_c, &payment_hash, Duration::from_secs(60));

        let balance_1 = wait_for_asset_balance(&node_a, &asset_id, Duration::from_secs(30));
        let balance_2 = wait_for_asset_balance(&node_b, &asset_id, Duration::from_secs(30));
        let balance_3 = wait_for_asset_balance(&node_c, &asset_id, Duration::from_secs(30));
        assert_eq!(balance_1.offchain_outbound, 450);
        assert_eq!(balance_1.offchain_inbound, 50);
        assert_eq!(balance_2.offchain_outbound, 300);
        assert_eq!(balance_2.offchain_inbound, 500);
        assert_eq!(balance_3.offchain_outbound, 50);
        assert_eq!(balance_3.offchain_inbound, 250);

        let channels_1 = node_a
            .list_channels()
            .expect("node A list_channels after payment");
        let channels_2 = node_b
            .list_channels()
            .expect("node B list_channels after payment");
        let channels_3 = node_c
            .list_channels()
            .expect("node C list_channels after payment");
        assert_eq!(channels_1.len(), 1);
        assert_eq!(channels_3.len(), 1);
        let chan_1_12 = channels_1
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node A channel 12 after payment");
        let chan_2_12 = channels_2
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node B channel 12 after payment");
        let chan_2_23 = channels_2
            .iter()
            .find(|channel| channel.channel_id == channel_id_23)
            .expect("node B channel 23 after payment");
        let chan_3_23 = channels_3
            .iter()
            .find(|channel| channel.channel_id == channel_id_23)
            .expect("node C channel 23 after payment");
        assert_eq!(chan_1_12.asset_local_amount, Some(450));
        assert_eq!(chan_1_12.asset_remote_amount, Some(50));
        assert_eq!(chan_2_12.asset_local_amount, Some(50));
        assert_eq!(chan_2_12.asset_remote_amount, Some(450));
        assert_eq!(chan_2_23.asset_local_amount, Some(250));
        assert_eq!(chan_2_23.asset_remote_amount, Some(50));
        assert_eq!(chan_3_23.asset_local_amount, Some(50));
        assert_eq!(chan_3_23.asset_remote_amount, Some(250));

        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 70, NODE_A_PEER_PORT + 70);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 70, NODE_B_PEER_PORT + 70);
        let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 70, NODE_C_PEER_PORT + 70);

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart");
        node_c
            .unlock(unlock_request("nodeCpass"))
            .expect("node C unlock after restart");

        let balance_1 = wait_for_asset_balance(&node_a, &asset_id, Duration::from_secs(30));
        let balance_2 = wait_for_asset_balance(&node_b, &asset_id, Duration::from_secs(30));
        let balance_3 = wait_for_asset_balance(&node_c, &asset_id, Duration::from_secs(30));
        assert_eq!(balance_1.offchain_outbound, 450);
        assert_eq!(balance_1.offchain_inbound, 50);
        assert_eq!(balance_2.offchain_outbound, 300);
        assert_eq!(balance_2.offchain_inbound, 500);
        assert_eq!(balance_3.offchain_outbound, 50);
        assert_eq!(balance_3.offchain_inbound, 250);

        let channels_1 = node_a
            .list_channels()
            .expect("node A list_channels after restart");
        let channels_2 = node_b
            .list_channels()
            .expect("node B list_channels after restart");
        let channels_3 = node_c
            .list_channels()
            .expect("node C list_channels after restart");
        assert_eq!(channels_1.len(), 1);
        assert_eq!(channels_3.len(), 1);
        let chan_1_12 = channels_1
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node A channel 12 after restart");
        let chan_2_12 = channels_2
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node B channel 12 after restart");
        let chan_2_23 = channels_2
            .iter()
            .find(|channel| channel.channel_id == channel_id_23)
            .expect("node B channel 23 after restart");
        let chan_3_23 = channels_3
            .iter()
            .find(|channel| channel.channel_id == channel_id_23)
            .expect("node C channel 23 after restart");
        assert_eq!(chan_1_12.asset_local_amount, Some(450));
        assert_eq!(chan_1_12.asset_remote_amount, Some(50));
        assert_eq!(chan_2_12.asset_local_amount, Some(50));
        assert_eq!(chan_2_12.asset_remote_amount, Some(450));
        assert_eq!(chan_2_23.asset_local_amount, Some(250));
        assert_eq!(chan_2_23.asset_remote_amount, Some(50));
        assert_eq!(chan_3_23.asset_local_amount, Some(50));
        assert_eq!(chan_3_23.asset_remote_amount, Some(250));

        let htlc_min_sat = node_a
            .node_info()
            .expect("node A node_info htlc min")
            .rgb_htlc_min_msat
            / 1000;
        let fees = 1;
        assert_eq!(
            chan_1_12.local_balance_sat,
            chan_1_12_before.local_balance_sat - htlc_min_sat - fees
        );
        assert_eq!(
            chan_2_12.local_balance_sat,
            chan_2_12_before.local_balance_sat + htlc_min_sat + fees
        );
        assert_eq!(
            chan_2_23.local_balance_sat,
            chan_2_23_before.local_balance_sat - htlc_min_sat
        );
        assert_eq!(
            chan_3_23.local_balance_sat,
            chan_3_23_before.local_balance_sat + htlc_min_sat
        );

        wait_for_usable_channel_counts(
            &[(&node_a, 1), (&node_b, 2), (&node_c, 1)],
            Duration::from_secs(180),
        );

        let node_a_info = node_a.node_info().expect("node A node_info after restart");
        let node_b_info = node_b.node_info().expect("node B node_info after restart");
        let node_c_info = node_c.node_info().expect("node C node_info after restart");
        assert_eq!(node_a_info.num_channels, 1);
        assert!(node_a_info.local_balance_sat <= 93_499);
        assert!(node_a_info.local_balance_sat >= 93_499 - max_expected_fee);
        assert_eq!(node_a_info.num_peers, 1);
        assert_eq!(node_b_info.num_channels, 2);
        assert!(node_b_info.local_balance_sat <= 100_001);
        assert!(node_b_info.local_balance_sat >= 100_001 - max_expected_fee);
        assert_eq!(node_b_info.num_peers, 2);
        assert_eq!(node_c_info.num_channels, 1);
        assert_eq!(node_c_info.local_balance_sat, 6_500);
        assert_eq!(node_c_info.num_peers, 1);

        close_channel(&node_b, channel_id_12, node_a_pubkey);
        wait_for_balance(&node_a, &asset_id, 550, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 150, Duration::from_secs(70));

        close_channel(&node_c, channel_id_23, node_b_pubkey);
        wait_for_balance(&node_b, &asset_id, 400, Duration::from_secs(70));
        wait_for_balance(&node_c, &asset_id, 50, Duration::from_secs(70));

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice after first close")
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
                        assignment_amount: Some(200),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb to node C");
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
            .expect("node C rgbinvoice second on-chain")
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
                        assignment_amount: Some(150),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node B send_rgb to node C");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_b);

        let recipient_id = node_b
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node B rgbinvoice final on-chain")
            .recipient_id;
        node_c
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
                        assignment_amount: Some(375),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node C send_rgb to node B");
        mine(1);
        refresh_transfers(&node_b);
        refresh_transfers(&node_b);
        refresh_transfers(&node_c);

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 350);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 625);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 25);

        let node_a_info = node_a.node_info().expect("node A node_info final");
        let node_b_info = node_b.node_info().expect("node B node_info final");
        let node_c_info = node_c.node_info().expect("node C node_info final");
        assert_eq!(node_a_info.num_channels, 0);
        assert_eq!(node_a_info.num_usable_channels, 0);
        assert_eq!(node_a_info.local_balance_sat, 0);
        assert_eq!(node_a_info.num_peers, 1);
        assert_eq!(node_b_info.num_channels, 0);
        assert_eq!(node_b_info.num_usable_channels, 0);
        assert_eq!(node_b_info.local_balance_sat, 0);
        assert_eq!(node_b_info.num_peers, 2);
        assert_eq!(node_c_info.num_channels, 0);
        assert_eq!(node_c_info.num_usable_channels, 0);
        assert_eq!(node_c_info.local_balance_sat, 0);
        assert_eq!(node_c_info.num_peers, 1);

        node_a
            .disconnectpeer(SdkDisconnectPeerRequest {
                peer_pubkey: node_b_pubkey,
            })
            .expect("node A disconnectpeer");
        wait_for_num_peers(&node_a, 0, Duration::from_secs(30));
        wait_for_num_peers(&node_b, 1, Duration::from_secs(30));
        let node_a_info = node_a
            .node_info()
            .expect("node A node_info after disconnect");
        let node_b_info = node_b
            .node_info()
            .expect("node B node_info after disconnect");
        assert_eq!(node_a_info.num_peers, 0);
        assert_eq!(node_b_info.num_peers, 1);

        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();
    }));

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
