use crate::helpers::*;
use serial_test::serial;
use std::{fs, time::Duration};

#[test]
#[serial]
fn vanilla_payment_on_rgb_channel() {
    ensure_regtest_available();

    let test_dir = test_dir("vanilla_payment_on_rgb_channel");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT + 50, NODE_A_PEER_PORT + 50);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT + 50, NODE_B_PEER_PORT + 50);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT + 50, NODE_C_PEER_PORT + 50);

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

        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;
        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{}", NODE_B_PEER_PORT + 50);
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

        let channels_1_before = node_a.list_channels().expect("node A list_channels before");
        let channels_2_before = node_b.list_channels().expect("node B list_channels before");
        assert_eq!(channels_1_before.len(), 1);
        assert_eq!(channels_2_before.len(), 1);
        let chan_1_before = &channels_1_before[0];
        let chan_2_before = &channels_2_before[0];

        let amount = 5_000_000;
        let invoice = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(amount),
                expiry_sec: 900,
                asset_id: None,
                asset_amount: None,
                payment_hash: None,
                description_hash: None,
            })
            .expect("node B vanilla ln_invoice")
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
            .expect("payment hash for vanilla payment");
        wait_for_payment_status(&node_a, &payment_hash, Duration::from_secs(60));
        wait_for_payment_status(&node_b, &payment_hash, Duration::from_secs(60));

        let decoded = node_a
            .decode_ln_invoice(invoice.clone())
            .expect("node A decode_ln_invoice");
        let payments = node_a.list_payments().expect("node A list_payments");
        let payment = payments
            .iter()
            .find(|payment| payment.payment_hash == decoded.payment_hash)
            .expect("node A payment in list_payments");
        assert_eq!(payment.asset_id, None);
        assert_eq!(payment.asset_amount, None);
        let payments = node_b.list_payments().expect("node B list_payments");
        let payment = payments
            .iter()
            .find(|payment| payment.payment_hash == decoded.payment_hash)
            .expect("node B payment in list_payments");
        assert_eq!(payment.asset_id, None);
        assert_eq!(payment.asset_amount, None);

        let channels_1 = node_a.list_channels().expect("node A list_channels after");
        let channels_2 = node_b.list_channels().expect("node B list_channels after");
        assert_eq!(channels_1.len(), 1);
        assert_eq!(channels_2.len(), 1);
        let chan_1 = &channels_1[0];
        let chan_2 = &channels_2[0];
        assert_eq!(
            chan_1.local_balance_sat,
            chan_1_before.local_balance_sat - amount / 1000
        );
        assert_eq!(
            chan_2.local_balance_sat,
            chan_2_before.local_balance_sat + amount / 1000
        );

        close_channel(&node_a, channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 1000, Duration::from_secs(70));

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice")
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
                        assignment_amount: Some(900),
                        transport_endpoints: vec![TransportEndpoint(
                            PROXY_ENDPOINT_LOCAL.to_string(),
                        )],
                    }],
                }],
            })
            .expect("node A send_rgb");
        mine(1);
        refresh_transfers(&node_c);
        refresh_transfers(&node_c);
        refresh_transfers(&node_a);

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 100);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 0);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 900);
    }));

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
