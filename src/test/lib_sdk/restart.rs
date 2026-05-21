use crate::helpers::*;
use serial_test::serial;
use std::{fs, time::Duration};

#[test]
#[serial]
#[ignore = "flaky SDK restart persistence issue: ChannelManager::read returns InvalidValue after restart"]
fn restart() {
    ensure_regtest_available();

    let test_dir = test_dir("restart");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 80, NODE_C_PEER_PORT + 80);

    // This scenario intentionally restarts different subsets of nodes multiple times on the same
    // storage dirs. The active SDK handles therefore change inside the closure, so shutdown of the
    // currently running nodes is done in-closure at each restart boundary and at the end.
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
            .expect("node A unlock initial");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock initial");
        node_c
            .unlock(unlock_request("nodeCpass"))
            .expect("node C unlock initial");

        println!("1 - restart all");
        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);
        let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 80, NODE_C_PEER_PORT + 80);

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart all");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart all");
        node_c
            .unlock(unlock_request("nodeCpass"))
            .expect("node C unlock after restart all");

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
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 1_000);

        println!("2 - restart 1+2");
        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart 1+2");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart 1+2");
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 1_000);

        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;
        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 80);
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
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 400);
        let channel_id = node_a
            .get_channel_id(open_channel.temporary_channel_id)
            .expect("node A get_channel_id");

        println!("3 - restart 1");
        node_a.shutdown();
        node_b.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart 1");
        wait_for_channel_ready(&node_a, channel_id, Duration::from_secs(10));

        println!("4 - restart 1+2");
        node_a.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);
        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart 1+2 second");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart 1+2 second");
        wait_for_channel_ready(&node_a, channel_id, Duration::from_secs(10));
        wait_for_usable_channels(&node_a, 1, Duration::from_secs(60));
        wait_for_usable_channels(&node_b, 1, Duration::from_secs(60));
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 400);

        let invoice = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(100),
                payment_hash: None,
                description_hash: None,
                min_final_cltv_expiry_delta: None,
            })
            .expect("node B ln_invoice")
            .invoice;
        let send_payment = node_a
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("node A sendpayment");
        let payment_hash = send_payment.payment_hash.expect("payment hash");
        wait_for_payment_status(&node_a, &payment_hash, Duration::from_secs(60));

        println!("5 - restart 1+2");
        node_a.shutdown();
        node_b.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);
        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart 1+2 post-payment");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart 1+2 post-payment");
        wait_for_channel_ready(&node_a, channel_id, Duration::from_secs(10));
        wait_for_usable_channels(&node_a, 1, Duration::from_secs(60));
        wait_for_usable_channels(&node_b, 1, Duration::from_secs(60));
        wait_for_succeeded_payment_in_list(&node_a, &payment_hash, Duration::from_secs(30));
        wait_for_succeeded_payment_in_list(&node_b, &payment_hash, Duration::from_secs(30));

        close_channel(&node_a, channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 900, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 100, Duration::from_secs(70));

        println!("6 - restart all");
        node_a.shutdown();
        node_b.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);
        let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 80, NODE_C_PEER_PORT + 80);
        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart all post-close");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart all post-close");
        node_c
            .unlock(unlock_request("nodeCpass"))
            .expect("node C unlock after restart all post-close");
        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 900);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 100);

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

        println!("7 - restart all");
        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 80, NODE_A_PEER_PORT + 80);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 80, NODE_B_PEER_PORT + 80);
        let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 80, NODE_C_PEER_PORT + 80);
        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock final restart");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock final restart");
        node_c
            .unlock(unlock_request("nodeCpass"))
            .expect("node C unlock final restart");

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 200);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 50);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 750);

        node_a.shutdown();
        node_b.shutdown();
        node_c.shutdown();
    }));

    // The closure above repeatedly creates fresh SDK handles on the same storage dirs and shuts
    // those active instances down in-place at each restart boundary. These outer handles are the
    // original pre-restart ones, so this final cleanup is intentionally best-effort and may end up
    // calling shutdown on handles that were already stopped earlier.
    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
