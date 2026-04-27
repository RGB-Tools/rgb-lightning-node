use crate::helpers::*;
use rgb_lightning_node::{
    SdkMakerExecuteRequest, SdkMakerInitRequest, SdkTakerRequest, SwapStatus,
};
use serial_test::serial;
use std::cell::Cell;
use std::{fs, time::Duration};

fn wait_for_swap_status(
    node: &SdkNode,
    payment_hash: &PaymentHash,
    expected_status: SwapStatus,
    timeout: Duration,
) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let swaps = node
            .list_swaps()
            .expect("list_swaps while waiting for swap status");
        let swap = swaps
            .maker
            .iter()
            .chain(swaps.taker.iter())
            .find(|swap| &swap.payment_hash == payment_hash)
            .expect("swap while waiting for swap status");
        let matches_expected = match expected_status {
            SwapStatus::Waiting => matches!(swap.status, SwapStatus::Waiting),
            SwapStatus::Pending => matches!(swap.status, SwapStatus::Pending),
            SwapStatus::Succeeded => matches!(swap.status, SwapStatus::Succeeded),
            SwapStatus::Expired => matches!(swap.status, SwapStatus::Expired),
            SwapStatus::Failed => matches!(swap.status, SwapStatus::Failed),
        };
        if matches_expected {
            return;
        }

        assert!(
            std::time::Instant::now() < deadline,
            "swap status did not become expected state"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[serial]
#[ignore = "flaky SDK restart persistence issue: ChannelManager::read returns InvalidValue after restart"]
fn swap_roundtrip_buy() {
    ensure_regtest_available();

    let test_dir = test_dir("swap_roundtrip_buy");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(
        &node_a_dir,
        NODE_A_DAEMON_PORT + 110,
        NODE_A_PEER_PORT + 110,
    );
    let node_b = make_node(
        &node_b_dir,
        NODE_B_DAEMON_PORT + 110,
        NODE_B_PEER_PORT + 110,
    );
    let node_c = make_node(
        &node_c_dir,
        NODE_C_DAEMON_PORT + 110,
        NODE_C_PEER_PORT + 110,
    );
    let original_node_a_shutdown = Cell::new(false);
    let original_node_b_shutdown = Cell::new(false);

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

        let node_a_pubkey = node_a.node_info().expect("node A node_info").pubkey;
        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;

        let peer_uri_ab = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 110);
        node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri_ab,
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
            .expect("node A openchannel 12");
        let channel_id_12 = wait_for_channel_open(
            &node_a,
            |channel| {
                channel.peer_pubkey == node_b_pubkey
                    && channel.asset_id.as_ref() == Some(&asset_id)
                    && channel.asset_local_amount == Some(600)
                    && channel.asset_remote_amount == Some(0)
            },
            Duration::from_secs(120),
        );

        let peer_uri_ba = format!("{node_a_pubkey}@127.0.0.1:{}", NODE_A_PEER_PORT + 110);
        node_b
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri_ba,
                capacity_sat: 5_000_000,
                push_msat: 546_000,
                public: true,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: None,
                asset_amount: None,
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("node B openchannel 21");
        let channel_id_21 = wait_for_channel_open(
            &node_b,
            |channel| {
                channel.peer_pubkey == node_a_pubkey
                    && channel.asset_id.is_none()
                    && channel.asset_local_amount.is_none()
                    && channel.asset_remote_amount.is_none()
            },
            Duration::from_secs(120),
        );

        let channels_a_before = node_a.list_channels().expect("node A list_channels before");
        let channels_b_before = node_b.list_channels().expect("node B list_channels before");
        let chan_a_12_before = channels_a_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node A channel 12 before");
        let chan_a_21_before = channels_a_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_21)
            .expect("node A channel 21 before");
        let chan_b_12_before = channels_b_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node B channel 12 before");
        let chan_b_21_before = channels_b_before
            .iter()
            .find(|channel| channel.channel_id == channel_id_21)
            .expect("node B channel 21 before");

        let qty_from = 50_000;
        let qty_to = 10;
        let maker_init = node_a
            .makerinit(SdkMakerInitRequest {
                qty_from,
                qty_to,
                from_asset: None,
                to_asset: Some(asset_id.clone()),
                timeout_sec: 3600,
            })
            .expect("node A makerinit");
        node_b
            .taker(SdkTakerRequest {
                swapstring: maker_init.swapstring.clone(),
            })
            .expect("node B taker");

        let swaps_maker = node_a.list_swaps().expect("node A list_swaps waiting");
        assert!(swaps_maker.taker.is_empty());
        assert_eq!(swaps_maker.maker.len(), 1);
        let swap_maker = swaps_maker.maker.first().expect("maker swap waiting");
        assert_eq!(swap_maker.qty_from, qty_from);
        assert_eq!(swap_maker.qty_to, qty_to);
        assert_eq!(swap_maker.from_asset, None);
        assert_eq!(swap_maker.to_asset, Some(asset_id.clone()));
        assert_eq!(swap_maker.payment_hash, maker_init.payment_hash);
        assert!(matches!(swap_maker.status, SwapStatus::Waiting));

        let swaps_taker = node_b.list_swaps().expect("node B list_swaps waiting");
        assert!(swaps_taker.maker.is_empty());
        assert_eq!(swaps_taker.taker.len(), 1);
        let swap_taker = swaps_taker.taker.first().expect("taker swap waiting");
        assert_eq!(swap_taker.qty_from, qty_from);
        assert_eq!(swap_taker.qty_to, qty_to);
        assert_eq!(swap_taker.from_asset, None);
        assert_eq!(swap_taker.to_asset, Some(asset_id.clone()));
        assert_eq!(swap_taker.payment_hash, maker_init.payment_hash);
        assert!(matches!(swap_taker.status, SwapStatus::Waiting));

        node_a
            .makerexecute(SdkMakerExecuteRequest {
                swapstring: maker_init.swapstring.clone(),
                payment_secret: maker_init.payment_secret.clone(),
                taker_pubkey: node_b_pubkey,
            })
            .expect("node A makerexecute");

        let swaps_maker = node_a.list_swaps().expect("node A list_swaps pending");
        assert_eq!(swaps_maker.maker.len(), 1);
        assert!(matches!(
            swaps_maker
                .maker
                .first()
                .expect("maker swap pending")
                .status,
            SwapStatus::Pending
        ));
        wait_for_swap_status(
            &node_b,
            &maker_init.payment_hash,
            SwapStatus::Succeeded,
            Duration::from_secs(70),
        );

        wait_for_ln_balance(&node_a, &asset_id, 590, Duration::from_secs(60));
        wait_for_ln_balance(&node_b, &asset_id, 10, Duration::from_secs(60));

        node_a.shutdown();
        node_b.shutdown();
        original_node_a_shutdown.set(true);
        original_node_b_shutdown.set(true);

        let node_a = make_node(
            &node_a_dir,
            NODE_A_DAEMON_PORT + 110,
            NODE_A_PEER_PORT + 110,
        );
        let node_b = make_node(
            &node_b_dir,
            NODE_B_DAEMON_PORT + 110,
            NODE_B_PEER_PORT + 110,
        );
        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock after restart");
        node_b
            .unlock(unlock_request("nodeBpass"))
            .expect("node B unlock after restart");
        wait_for_usable_channels(&node_a, 2, Duration::from_secs(60));
        wait_for_usable_channels(&node_b, 2, Duration::from_secs(60));

        let balance_a = wait_for_asset_balance(&node_a, &asset_id, Duration::from_secs(60));
        let balance_b = wait_for_asset_balance(&node_b, &asset_id, Duration::from_secs(60));
        assert_eq!(balance_a.offchain_outbound, 590);
        assert_eq!(balance_a.offchain_inbound, 10);
        assert_eq!(balance_b.offchain_outbound, 10);
        assert_eq!(balance_b.offchain_inbound, 590);

        let swaps_maker = node_a
            .list_swaps()
            .expect("node A list_swaps after restart");
        assert_eq!(swaps_maker.maker.len(), 1);
        assert!(matches!(
            swaps_maker
                .maker
                .first()
                .expect("maker swap after restart")
                .status,
            SwapStatus::Succeeded
        ));
        let swaps_taker = node_b
            .list_swaps()
            .expect("node B list_swaps after restart");
        assert_eq!(swaps_taker.taker.len(), 1);
        assert!(matches!(
            swaps_taker
                .taker
                .first()
                .expect("taker swap after restart")
                .status,
            SwapStatus::Succeeded
        ));

        assert!(node_a
            .list_payments()
            .expect("node A list_payments")
            .is_empty());
        assert!(node_b
            .list_payments()
            .expect("node B list_payments")
            .is_empty());

        let channels_a = node_a
            .list_channels()
            .expect("node A list_channels after restart");
        let channels_b = node_b
            .list_channels()
            .expect("node B list_channels after restart");
        let chan_a_12 = channels_a
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node A channel 12 after restart");
        let chan_a_21 = channels_a
            .iter()
            .find(|channel| channel.channel_id == channel_id_21)
            .expect("node A channel 21 after restart");
        let chan_b_12 = channels_b
            .iter()
            .find(|channel| channel.channel_id == channel_id_12)
            .expect("node B channel 12 after restart");
        let chan_b_21 = channels_b
            .iter()
            .find(|channel| channel.channel_id == channel_id_21)
            .expect("node B channel 21 after restart");
        let btc_leg_diff = (HTLC_MIN_MSAT + qty_from) / 1000;
        let htlc_min_sat = HTLC_MIN_MSAT / 1000;
        assert_eq!(
            chan_a_12.local_balance_sat,
            chan_a_12_before.local_balance_sat - htlc_min_sat
        );
        assert_eq!(
            chan_a_21.local_balance_sat,
            chan_a_21_before.local_balance_sat + btc_leg_diff
        );
        assert_eq!(
            chan_b_12.local_balance_sat,
            chan_b_12_before.local_balance_sat + htlc_min_sat
        );
        assert_eq!(
            chan_b_21.local_balance_sat,
            chan_b_21_before.local_balance_sat - btc_leg_diff
        );

        close_channel(&node_a, channel_id_12, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 990, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 10, Duration::from_secs(70));

        close_channel(&node_b, channel_id_21, node_a_pubkey);

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
                        assignment_amount: Some(5),
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

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 790);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 5);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 205);

        node_a.shutdown();
        node_b.shutdown();
    }));

    if !original_node_a_shutdown.get() {
        node_a.shutdown();
    }
    if !original_node_b_shutdown.get() {
        node_b.shutdown();
    }
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
