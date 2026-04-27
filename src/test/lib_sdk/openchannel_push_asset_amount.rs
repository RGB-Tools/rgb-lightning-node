use crate::helpers::*;
use serial_test::serial;
use std::{fs, time::Duration};

#[test]
#[serial]
fn openchannel_push_asset_amount() {
    ensure_regtest_available();

    let test_dir = test_dir("openchannel_push_asset_amount");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 40, NODE_A_PEER_PORT + 40);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 40, NODE_B_PEER_PORT + 40);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 40, NODE_C_PEER_PORT + 40);

    // Unlike the other SDK tests, this scenario restarts node A and node B mid-test by shutting
    // them down and recreating them on the same storage dirs. That means the active node handles
    // change inside the closure, so the usual "shutdown everything outside catch_unwind" cleanup
    // pattern is not practical here. The in-closure shutdowns are therefore intentional.
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

        let node_a_pubkey = node_a.node_info().expect("node A node_info").pubkey;
        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;

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

        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 40);
        node_a
            .connectpeer(peer_uri.clone())
            .expect("node A connectpeer");

        let partial_push_channel = node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri.clone(),
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat: 0,
                public: true,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(600),
                push_asset_amount: Some(250),
                virtual_open_mode: None,
            })
            .expect("node A openchannel partial push");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(120));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));

        let partial_channel_id = node_a
            .get_channel_id(partial_push_channel.temporary_channel_id)
            .expect("node A get_channel_id partial");

        let channels_1 = node_a
            .list_channels()
            .expect("node A list_channels partial");
        let channels_2 = node_b
            .list_channels()
            .expect("node B list_channels partial");
        assert_eq!(channels_1.len(), 1);
        assert_eq!(channels_2.len(), 1);

        let node_a_channel = channels_1
            .iter()
            .find(|channel| channel.channel_id == partial_channel_id)
            .expect("node A partial channel");
        assert_eq!(node_a_channel.asset_local_amount, Some(350));
        assert_eq!(node_a_channel.asset_remote_amount, Some(250));

        let node_b_channel = channels_2
            .iter()
            .find(|channel| channel.channel_id == partial_channel_id)
            .expect("node B partial channel");
        assert_eq!(node_b_channel.asset_local_amount, Some(250));
        assert_eq!(node_b_channel.asset_remote_amount, Some(350));

        keysend_with_ln_balance(
            &node_a,
            &node_b,
            node_b_pubkey,
            None,
            &asset_id,
            100,
            350,
            250,
        );
        wait_for_channel_asset_state(
            "node A partial push after first RGB keysend",
            &node_a,
            partial_channel_id,
            Some(250),
            Some(350),
            None,
            Duration::from_secs(30),
        );
        wait_for_channel_asset_state(
            "node B partial push after first RGB keysend",
            &node_b,
            partial_channel_id,
            Some(350),
            Some(250),
            None,
            Duration::from_secs(30),
        );
        keysend(
            &node_a,
            node_b_pubkey,
            Some(LIQUIDITY_KEYSEND_MSAT),
            None,
            None,
        );
        wait_for_channel_asset_state(
            "node B partial push before reverse RGB keysend",
            &node_b,
            partial_channel_id,
            Some(350),
            Some(250),
            Some(PAYMENT_MSAT),
            Duration::from_secs(30),
        );
        keysend_with_ln_balance(
            &node_b,
            &node_a,
            node_a_pubkey,
            None,
            &asset_id,
            50,
            350,
            250,
        );

        let node_a_channel = node_a
            .list_channels()
            .expect("node A list_channels after partial keysend")
            .into_iter()
            .find(|channel| channel.channel_id == partial_channel_id)
            .expect("node A channel after partial keysend");
        assert_eq!(node_a_channel.asset_local_amount, Some(300));
        assert_eq!(node_a_channel.asset_remote_amount, Some(300));

        let node_b_channel = node_b
            .list_channels()
            .expect("node B list_channels after partial keysend")
            .into_iter()
            .find(|channel| channel.channel_id == partial_channel_id)
            .expect("node B channel after partial keysend");
        assert_eq!(node_b_channel.asset_local_amount, Some(300));
        assert_eq!(node_b_channel.asset_remote_amount, Some(300));

        close_channel(&node_a, partial_channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 700, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 300, Duration::from_secs(70));

        let full_push_channel = node_a
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
                push_asset_amount: Some(600),
                virtual_open_mode: None,
            })
            .expect("node A openchannel full push");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(120));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));

        node_a.shutdown();
        node_b.shutdown();

        let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 40, NODE_A_PEER_PORT + 40);
        let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 40, NODE_B_PEER_PORT + 40);

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart");

        wait_for_usable_channels(&node_a, 1, Duration::from_secs(120));
        wait_for_usable_channels(&node_b, 1, Duration::from_secs(120));

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 100);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 300);

        let full_channel_id = node_a
            .get_channel_id(full_push_channel.temporary_channel_id)
            .expect("node A get_channel_id full");

        let node_a_channel = node_a
            .list_channels()
            .expect("node A list_channels full")
            .into_iter()
            .find(|channel| channel.channel_id == full_channel_id)
            .expect("node A full push channel");
        assert_eq!(node_a_channel.asset_local_amount, Some(0));
        assert_eq!(node_a_channel.asset_remote_amount, Some(600));

        let node_b_channel = node_b
            .list_channels()
            .expect("node B list_channels full")
            .into_iter()
            .find(|channel| channel.channel_id == full_channel_id)
            .expect("node B full push channel");
        assert_eq!(node_b_channel.asset_local_amount, Some(600));
        assert_eq!(node_b_channel.asset_remote_amount, Some(0));

        keysend(
            &node_a,
            node_b_pubkey,
            Some(LIQUIDITY_KEYSEND_MSAT),
            None,
            None,
        );
        wait_for_channel_asset_state(
            "node A full push before reverse RGB keysend",
            &node_a,
            full_channel_id,
            Some(0),
            Some(600),
            None,
            Duration::from_secs(30),
        );
        wait_for_channel_asset_state(
            "node B full push before reverse RGB keysend",
            &node_b,
            full_channel_id,
            Some(600),
            Some(0),
            Some(PAYMENT_MSAT),
            Duration::from_secs(30),
        );
        keysend_with_ln_balance(
            &node_b,
            &node_a,
            node_a_pubkey,
            None,
            &asset_id,
            100,
            600,
            0,
        );

        let node_a_channel = node_a
            .list_channels()
            .expect("node A list_channels after full keysend")
            .into_iter()
            .find(|channel| channel.channel_id == full_channel_id)
            .expect("node A full push channel after keysend");
        assert_eq!(node_a_channel.asset_local_amount, Some(100));
        assert_eq!(node_a_channel.asset_remote_amount, Some(500));

        let node_b_channel = node_b
            .list_channels()
            .expect("node B list_channels after full keysend")
            .into_iter()
            .find(|channel| channel.channel_id == full_channel_id)
            .expect("node B full push channel after keysend");
        assert_eq!(node_b_channel.asset_local_amount, Some(500));
        assert_eq!(node_b_channel.asset_remote_amount, Some(100));

        close_channel(&node_a, full_channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 200, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 800, Duration::from_secs(70));

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice final")
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
                        assignment_amount: Some(100),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node B send_rgb final");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_b);

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 200);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 700);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 100);

        node_a.shutdown();
        node_b.shutdown();
    }));

    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
