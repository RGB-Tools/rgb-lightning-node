use crate::helpers::*;
use serial_test::serial;
use std::{fs, time::Duration};

fn wait_for_vanilla_channel(
    node_a: &SdkNode,
    node_b: &SdkNode,
    temporary_channel_id: lightning::ln::types::ChannelId,
    timeout: Duration,
) -> lightning::ln::types::ChannelId {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        node_a
            .sync()
            .expect("node A sync while waiting for vanilla channel");
        node_b
            .sync()
            .expect("node B sync while waiting for vanilla channel");

        if let Ok(channel_id) = node_a.get_channel_id(temporary_channel_id) {
            let funded = node_a
                .list_channels()
                .expect("node A list_channels while waiting for vanilla channel")
                .into_iter()
                .any(|channel| channel.channel_id == channel_id && channel.funding_txid.is_some());
            if funded {
                mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
                loop {
                    node_a
                        .sync()
                        .expect("node A sync while waiting for vanilla channel usable");
                    node_b
                        .sync()
                        .expect("node B sync while waiting for vanilla channel usable");
                    let usable = node_a
                        .list_channels()
                        .expect("node A list_channels while waiting for vanilla usable channel")
                        .into_iter()
                        .any(|channel| channel.channel_id == channel_id && channel.is_usable);
                    if usable {
                        return channel_id;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "timeout waiting for usable vanilla channel"
                    );
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }

        assert!(
            std::time::Instant::now() < deadline,
            "timeout waiting for funded vanilla channel"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn run_close_coop_vanilla(name: &str, port_offset: u16, with_anchors: bool) {
    ensure_regtest_available();

    let test_dir = test_dir(name);
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let node_c_dir = test_dir.join("node_c");

    let node_a = make_node(
        &node_a_dir,
        NODE_A_DAEMON_PORT + port_offset,
        NODE_A_PEER_PORT + port_offset,
    );
    let node_b = make_node(
        &node_b_dir,
        NODE_B_DAEMON_PORT + port_offset,
        NODE_B_PEER_PORT + port_offset,
    );
    let node_c = make_node(
        &node_c_dir,
        NODE_C_DAEMON_PORT + port_offset,
        NODE_C_PEER_PORT + port_offset,
    );

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

        let unspents = node_a.list_unspents(false).expect("node A list_unspents");
        assert_eq!(unspents.len(), 0);

        fund_and_create_utxos(&node_a, "node A");
        fund_and_create_utxos(&node_b, "node B");
        fund_and_create_utxos(&node_c, "node C");

        let initial_balance = 99_676_210;
        assert_eq!(
            node_a
                .btc_balance(false)
                .expect("node A btc_balance")
                .vanilla
                .spendable,
            initial_balance
        );
        assert_eq!(
            node_b
                .btc_balance(false)
                .expect("node B btc_balance")
                .vanilla
                .spendable,
            initial_balance
        );
        assert_eq!(
            node_c
                .btc_balance(false)
                .expect("node C btc_balance")
                .vanilla
                .spendable,
            initial_balance
        );

        let node_a_pubkey = node_a.node_info().expect("node A node_info").pubkey;
        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;

        let peers = node_a.list_peers().expect("node A list_peers before");
        assert!(!peers.iter().any(|peer| peer.pubkey == node_b_pubkey));
        let peer_uri = format!(
            "{node_b_pubkey}@127.0.0.1:{}",
            NODE_B_PEER_PORT + port_offset
        );
        node_a
            .connectpeer(peer_uri.clone())
            .expect("node A connectpeer");
        let peers = node_a.list_peers().expect("node A list_peers after");
        assert!(peers.iter().any(|peer| peer.pubkey == node_b_pubkey));

        let open_channel = node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri,
                capacity_sat: 600_000,
                push_msat: 300_000_000,
                public: true,
                with_anchors,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: None,
                asset_amount: None,
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("node A openchannel vanilla");
        let channel_id = wait_for_vanilla_channel(
            &node_a,
            &node_b,
            open_channel.temporary_channel_id,
            Duration::from_secs(120),
        );

        keysend(&node_a, node_b_pubkey, Some(10_000_000), None, None);
        keysend(&node_b, node_a_pubkey, Some(10_000_000), None, None);
        assert_eq!(
            node_a.list_payments().expect("node A list_payments").len(),
            2
        );
        assert_eq!(
            node_b.list_payments().expect("node B list_payments").len(),
            2
        );

        let invoice = node_a
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(50_000_000),
                expiry_sec: 900,
                asset_id: None,
                asset_amount: None,
                payment_hash: None,
                description_hash: None,
            })
            .expect("node A vanilla ln_invoice")
            .invoice;
        let send_payment = node_b
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("node B sendpayment");
        let payment_hash = send_payment.payment_hash.expect("vanilla payment hash");
        wait_for_payment_status(&node_b, &payment_hash, Duration::from_secs(60));
        wait_for_payment_present_in_list(&node_a, &payment_hash, Duration::from_secs(60));
        assert_eq!(
            node_a.list_payments().expect("node A list_payments").len(),
            3
        );
        assert_eq!(
            node_b.list_payments().expect("node B list_payments").len(),
            3
        );

        close_channel(&node_a, channel_id, node_b_pubkey);
        wait_for_usable_channels(&node_a, 0, Duration::from_secs(70));
        wait_for_usable_channels(&node_b, 0, Duration::from_secs(70));
    }));

    node_a.shutdown();
    node_b.shutdown();
    node_c.shutdown();

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn with_anchors() {
    run_close_coop_vanilla("close_coop_vanilla_with_anchors", 90, true);
}

#[test]
#[serial]
fn without_anchors() {
    run_close_coop_vanilla("close_coop_vanilla_without_anchors", 100, false);
}
