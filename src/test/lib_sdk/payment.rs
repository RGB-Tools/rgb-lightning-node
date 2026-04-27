use crate::helpers::*;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use serial_test::serial;
use std::{
    fs,
    thread::sleep,
    time::{Duration, Instant},
};

fn check_preimage_matches_hash(payment: &Payment, expected_payment_hash: &PaymentHash) {
    let payment_preimage = payment.preimage.as_ref().expect("payment preimage");
    let payment_preimage_hash =
        Sha256::hash(&Vec::from_hex(payment_preimage).expect("preimage hex"))
            .to_byte_array()
            .to_lower_hex_string();
    assert_eq!(
        payment_preimage_hash,
        expected_payment_hash.0.to_lower_hex_string()
    );
}

fn wait_for_channel_state(
    label: &str,
    node: &SdkNode,
    expected_local_balance_sat: u64,
    expected_outbound_balance_msat: u64,
    expected_inbound_balance_msat: u64,
    expected_asset_local: Option<u64>,
    expected_asset_remote: Option<u64>,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        node.sync()
            .unwrap_or_else(|_| panic!("{label}: node sync while waiting for channel state"));
        let channels = node
            .list_channels()
            .unwrap_or_else(|_| panic!("{label}: list_channels while waiting for channel state"));
        assert_eq!(channels.len(), 1, "{label}: expected 1 channel");
        let channel = &channels[0];
        if channel.local_balance_sat == expected_local_balance_sat
            && channel.outbound_balance_msat == expected_outbound_balance_msat
            && channel.inbound_balance_msat == expected_inbound_balance_msat
            && channel.asset_local_amount == expected_asset_local
            && channel.asset_remote_amount == expected_asset_remote
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label} did not reach expected channel state"
        );
        sleep(Duration::from_secs(1));
    }
}

#[test]
#[serial]
fn success() {
    ensure_regtest_available();

    let test_dir = test_dir("sdk_payment_success");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(&node_a_dir, NODE_A_DAEMON_PORT, NODE_A_PEER_PORT);
    let node_b = make_node(&node_b_dir, NODE_B_DAEMON_PORT, NODE_B_PEER_PORT);
    let node_c = make_node(&node_c_dir, NODE_C_DAEMON_PORT, NODE_C_PEER_PORT);

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

        ensure_funded(&node_a, 200_000, "node A");
        ensure_funded(&node_b, 200_000, "node B");
        ensure_funded(&node_c, 200_000, "node C");

        for node in [&node_a, &node_b, &node_c] {
            node.createutxos(SdkCreateUtxosRequest {
                up_to: false,
                num: Some(CREATE_UTXOS_NUM),
                size: None,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .expect("createutxos");
        }
        mine(1);
        node_a.sync().expect("node A sync after createutxos");
        node_b.sync().expect("node B sync after createutxos");
        node_c.sync().expect("node C sync after createutxos");

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
        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{NODE_B_PEER_PORT}");
        node_a
            .connectpeer(peer_uri.clone())
            .expect("node A connectpeer");

        let open_channel = node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat: OPEN_CHANNEL_PUSH_MSAT,
                public: true,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(OPEN_CHANNEL_ASSET_AMOUNT),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("node A openchannel");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(120));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));
        wait_for_balance(&node_a, &asset_id, 400, Duration::from_secs(70));

        let channels_1_before = node_a.list_channels().expect("node A list_channels before");
        let channels_2_before = node_b.list_channels().expect("node B list_channels before");
        assert_eq!(channels_1_before.len(), 1);
        assert_eq!(channels_2_before.len(), 1);
        let chan_1_before = &channels_1_before[0];
        let chan_2_before = &channels_2_before[0];
        let channel_id = node_a
            .get_channel_id(open_channel.temporary_channel_id)
            .expect("node A get_channel_id from temporary_channel_id");
        assert_eq!(channel_id, chan_1_before.channel_id);

        let asset_amount = 100;
        let invoice = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(asset_amount),
                payment_hash: None,
                description_hash: None,
            })
            .expect("node B ln_invoice")
            .invoice;

        send_payment_with_ln_balance(
            &node_a,
            &node_b,
            invoice.clone(),
            &asset_id,
            asset_amount,
            600,
            0,
        );

        let decoded = node_a
            .decode_ln_invoice(invoice.clone())
            .expect("node A decode_ln_invoice");
        assert_eq!(decoded.asset_id, Some(asset_id));
        assert_eq!(decoded.asset_amount, Some(asset_amount));
        assert_eq!(decoded.amt_msat, Some(PAYMENT_MSAT));
        assert_eq!(decoded.expiry_sec, 900);
        assert_eq!(decoded.payee_pubkey, Some(node_b_pubkey));
        assert_eq!(decoded.network, "Regtest");
        let status = node_b
            .invoice_status(invoice.clone())
            .expect("node B invoice_status");
        assert!(matches!(status, InvoiceStatus::Succeeded));

        let sender_payment =
            wait_for_payment_status(&node_a, &decoded.payment_hash, Duration::from_secs(60));
        assert!(matches!(sender_payment.status, HtlcStatus::Succeeded));
        assert_eq!(sender_payment.asset_id, Some(asset_id.clone()));
        assert_eq!(sender_payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&sender_payment, &decoded.payment_hash);

        let receiver_payment =
            wait_for_payment_status(&node_b, &decoded.payment_hash, Duration::from_secs(60));
        assert!(matches!(receiver_payment.status, HtlcStatus::Succeeded));
        assert_eq!(receiver_payment.asset_id, Some(asset_id.clone()));
        assert_eq!(receiver_payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&receiver_payment, &decoded.payment_hash);

        let payment = wait_for_payment_present_in_list(
            &node_a,
            &decoded.payment_hash,
            Duration::from_secs(60),
        );
        assert_eq!(payment.payment_hash, decoded.payment_hash);
        check_preimage_matches_hash(&payment, &decoded.payment_hash);
        let payment = wait_for_payment_present_in_list(
            &node_b,
            &decoded.payment_hash,
            Duration::from_secs(60),
        );
        assert_eq!(payment.payment_hash, decoded.payment_hash);
        check_preimage_matches_hash(&payment, &decoded.payment_hash);

        let asset_amount = 50;
        let invoice = node_a
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(asset_amount),
                payment_hash: None,
                description_hash: None,
            })
            .expect("node A ln_invoice second")
            .invoice;
        send_payment_with_ln_balance(
            &node_b,
            &node_a,
            invoice.clone(),
            &asset_id,
            asset_amount,
            100,
            500,
        );

        let decoded = node_a
            .decode_ln_invoice(invoice.clone())
            .expect("node A decode_ln_invoice second");
        let payment =
            wait_for_payment_status(&node_a, &decoded.payment_hash, Duration::from_secs(60));
        assert_eq!(payment.asset_id, Some(asset_id.clone()));
        assert_eq!(payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&payment, &decoded.payment_hash);
        let payment =
            wait_for_payment_status(&node_b, &decoded.payment_hash, Duration::from_secs(60));
        assert_eq!(payment.asset_id, Some(asset_id.clone()));
        assert_eq!(payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&payment, &decoded.payment_hash);

        let invoice = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(asset_amount),
                payment_hash: None,
                description_hash: None,
            })
            .expect("node B ln_invoice third")
            .invoice;
        node_a
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("node A sendpayment third");
        let decoded = node_a
            .decode_ln_invoice(invoice.clone())
            .expect("node A decode_ln_invoice third");
        let payment =
            wait_for_payment_status(&node_a, &decoded.payment_hash, Duration::from_secs(60));
        assert_eq!(payment.asset_id, Some(asset_id.clone()));
        assert_eq!(payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&payment, &decoded.payment_hash);
        let payment =
            wait_for_payment_status(&node_b, &decoded.payment_hash, Duration::from_secs(60));
        assert_eq!(payment.asset_id, Some(asset_id.clone()));
        assert_eq!(payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&payment, &decoded.payment_hash);

        let invoice = node_a
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(asset_amount),
                payment_hash: None,
                description_hash: None,
            })
            .expect("node A ln_invoice fourth")
            .invoice;
        node_b
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("node B sendpayment fourth");
        let decoded = node_a
            .decode_ln_invoice(invoice.clone())
            .expect("node A decode_ln_invoice fourth");
        let payment =
            wait_for_payment_status(&node_a, &decoded.payment_hash, Duration::from_secs(60));
        assert_eq!(payment.asset_id, Some(asset_id.clone()));
        assert_eq!(payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&payment, &decoded.payment_hash);
        let payment =
            wait_for_payment_status(&node_b, &decoded.payment_hash, Duration::from_secs(60));
        assert_eq!(payment.asset_id, Some(asset_id.clone()));
        assert_eq!(payment.asset_amount, Some(asset_amount));
        check_preimage_matches_hash(&payment, &decoded.payment_hash);

        wait_for_channel_state(
            "node_a after payments",
            &node_a,
            chan_1_before.local_balance_sat,
            chan_1_before.outbound_balance_msat,
            chan_1_before.inbound_balance_msat,
            Some(550),
            Some(50),
            Duration::from_secs(30),
        );
        wait_for_channel_state(
            "node_b after payments",
            &node_b,
            chan_2_before.local_balance_sat,
            chan_2_before.outbound_balance_msat,
            chan_2_before.inbound_balance_msat,
            Some(50),
            Some(550),
            Duration::from_secs(30),
        );
        let channels_1 = node_a
            .list_channels()
            .expect("node A list_channels after channel state convergence");
        let channels_2 = node_b
            .list_channels()
            .expect("node B list_channels after channel state convergence");
        assert_eq!(channels_1.len(), 1);
        assert_eq!(channels_2.len(), 1);
        let chan_1 = &channels_1[0];
        let chan_2 = &channels_2[0];
        assert_eq!(chan_1.local_balance_sat, chan_1_before.local_balance_sat);
        assert_eq!(chan_2.local_balance_sat, chan_2_before.local_balance_sat);

        close_channel(&node_a, channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 950, Duration::from_secs(70));
        wait_for_balance(&node_b, &asset_id, 50, Duration::from_secs(70));

        let recipient_id = node_c
            .rgbinvoice(SdkRgbInvoiceRequest {
                asset_id: None,
                assignment_kind: None,
                assignment_amount: None,
                duration_seconds: None,
                min_confirmations: 1,
                witness: false,
            })
            .expect("node C rgbinvoice for first send")
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
                        assignment_amount: Some(925),
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
            .expect("node C rgbinvoice for second send")
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
                        assignment_amount: Some(25),
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

        assert_eq!(asset_balance_spendable(&node_a, &asset_id), 25);
        assert_eq!(asset_balance_spendable(&node_b, &asset_id), 25);
        assert_eq!(asset_balance_spendable(&node_c, &asset_id), 950);

        let transactions = node_a
            .list_transactions(false)
            .expect("node A list_transactions");
        let tx_user = transactions
            .iter()
            .find(|tx| tx.received == 100_000_000)
            .expect("user transaction");
        let tx_utxos = transactions
            .iter()
            .find(|tx| tx.sent == 100_000_000)
            .expect("create_utxos transaction");
        let tx_send = transactions
            .iter()
            .find(|tx| tx.sent == 128_000)
            .expect("rgb send transaction");
        assert!(matches!(tx_user.transaction_type, TransactionType::User));
        assert!(matches!(
            tx_utxos.transaction_type,
            TransactionType::CreateUtxos
        ));
        assert!(matches!(tx_send.transaction_type, TransactionType::RgbSend));
        assert!(tx_utxos.confirmation_time.is_some());

        let transfers = node_a
            .list_transfers(asset_id.clone())
            .expect("node A list_transfers");
        let xfer_1 = transfers
            .iter()
            .find(|transfer| transfer.idx == 1)
            .expect("transfer 1");
        assert_eq!(xfer_1.status, "Settled");
        assert_eq!(xfer_1.kind, "Issuance");
        assert_eq!(xfer_1.assignments, vec!["Fungible(1000)".to_string()]);
        assert!(xfer_1.txid.is_none());
        assert!(xfer_1.recipient_id.is_none());
        assert!(xfer_1.receive_utxo.is_none());
        assert!(xfer_1.change_utxo.is_none());
        assert!(xfer_1.expiration.is_none());
        assert!(xfer_1.transport_endpoints.is_empty());

        let xfer_2 = transfers
            .iter()
            .find(|transfer| transfer.idx == 2)
            .expect("transfer 2");
        assert_eq!(xfer_2.status, "Settled");
        assert_eq!(xfer_2.kind, "Send");
        assert_eq!(
            xfer_2.requested_assignment,
            Some("Fungible(600)".to_string())
        );
        assert_eq!(xfer_2.assignments, vec!["Fungible(400)".to_string()]);
        assert!(xfer_2.txid.is_some());
        assert!(xfer_2.recipient_id.is_some());
        assert!(xfer_2.receive_utxo.is_none());
        assert!(xfer_2.change_utxo.is_some());
        assert!(xfer_2.expiration.is_none());
        assert!(!xfer_2.transport_endpoints.is_empty());

        let xfer_3 = transfers
            .iter()
            .find(|transfer| transfer.idx == 3)
            .expect("transfer 3");
        assert_eq!(xfer_3.status, "Settled");
        assert_eq!(xfer_3.kind, "ReceiveWitness");
        assert_eq!(xfer_3.assignments, vec!["Fungible(550)".to_string()]);
        assert!(xfer_3.txid.is_some());
        assert!(xfer_3.recipient_id.is_some());
        assert!(xfer_3.receive_utxo.is_some());
        assert!(xfer_3.change_utxo.is_none());
        assert!(xfer_3.expiration.is_none());
        assert!(!xfer_3.transport_endpoints.is_empty());
    }));

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
