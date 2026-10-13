use lightning::ln::channelmanager::{
    FORCE_FIRST_HOP_RGB_PAYMENT_ON_NODE, FORCE_SECOND_HOP_RGB_PAYMENT_ON_NODE,
    FORCE_UPDATE_ADD_HTLC_RGB_CONTRACT_TO_PEER,
};
use rgb_lib::ContractId;

use super::*;

const TEST_DIR_BASE: &str = "tmp/forward_rgb_amount_mismatch/";
const ISSUED_ASSET_AMOUNT: u64 = 1000;
const INCOMING_ASSET_AMOUNT: u64 = 100;
const OUTGOING_ASSET_AMOUNT: u64 = 200;

struct ForceFirstHopRgbPaymentGuard;

impl ForceFirstHopRgbPaymentGuard {
    fn set(node_pubkey: &str, payment: Option<(&str, u64)>) -> Self {
        let pubkey = PublicKey::from_str(node_pubkey).unwrap();
        let payment =
            payment.map(|(asset_id, amount)| (ContractId::from_str(asset_id).unwrap(), amount));
        *FORCE_FIRST_HOP_RGB_PAYMENT_ON_NODE.lock().unwrap() = Some((pubkey, payment));
        Self
    }
}

impl Drop for ForceFirstHopRgbPaymentGuard {
    fn drop(&mut self) {
        *FORCE_FIRST_HOP_RGB_PAYMENT_ON_NODE.lock().unwrap() = None;
    }
}

struct ForceUpdateAddHtlcContractGuard;

impl ForceUpdateAddHtlcContractGuard {
    fn set(peer_pubkey: &str, asset_id: &str) -> Self {
        let pubkey = PublicKey::from_str(peer_pubkey).unwrap();
        let contract_id = ContractId::from_str(asset_id).unwrap();
        *FORCE_UPDATE_ADD_HTLC_RGB_CONTRACT_TO_PEER.lock().unwrap() = Some((pubkey, contract_id));
        Self
    }
}

impl Drop for ForceUpdateAddHtlcContractGuard {
    fn drop(&mut self) {
        *FORCE_UPDATE_ADD_HTLC_RGB_CONTRACT_TO_PEER.lock().unwrap() = None;
    }
}

struct ForceSecondHopRgbPaymentGuard;

impl ForceSecondHopRgbPaymentGuard {
    fn set(node_pubkey: &str, asset_id: &str, amount: u64) -> Self {
        let pubkey = PublicKey::from_str(node_pubkey).unwrap();
        let contract_id = ContractId::from_str(asset_id).unwrap();
        *FORCE_SECOND_HOP_RGB_PAYMENT_ON_NODE.lock().unwrap() = Some((pubkey, contract_id, amount));
        Self
    }
}

impl Drop for ForceSecondHopRgbPaymentGuard {
    fn drop(&mut self) {
        *FORCE_SECOND_HOP_RGB_PAYMENT_ON_NODE.lock().unwrap() = None;
    }
}

async fn send_payment_and_assert_failed(node_address: SocketAddr, invoice: String) -> Payment {
    let send_payment = send_payment_raw(node_address, invoice).await;
    let payment_hash = send_payment.payment_hash.unwrap();
    println!(
        "waiting for malicious forwarded RGB payment {payment_hash} to fail on node {node_address}"
    );
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Some(payment) =
            check_payment_status(node_address, &payment_hash, HTLCStatus::Failed).await
        {
            return payment;
        }
        if check_payment_status(node_address, &payment_hash, HTLCStatus::Succeeded)
            .await
            .is_some()
        {
            panic!("malicious forwarded RGB payment {payment_hash} unexpectedly succeeded");
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 180.0 {
            panic!("cannot find payment {payment_hash} in status Failed");
        }
    }
}

struct Setup {
    node1_addr: SocketAddr,
    node2_addr: SocketAddr,
    node3_addr: SocketAddr,
    node2_dir: String,
    node1_pubkey: String,
    asset_a: String,
    channel_12: Channel,
    channel_23: Channel,
    chan_2_12_before: Channel,
    chan_2_23_before: Channel,
}

// node1 (attacker) -> node2 (victim router) -> node3 (attacker), where both channels are colored
// with asset A and node2 holds OUTGOING_ASSET_AMOUNT of it on its side of the 2-3 channel
async fn setup(test_dir_base: &str) -> Setup {
    let test_dir_node1 = format!("{test_dir_base}node1");
    let test_dir_node2 = format!("{test_dir_base}node2");
    let test_dir_node3 = format!("{test_dir_base}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_a = issue_asset_nia(node1_addr).await.asset_id;

    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;
    let node3_pubkey = node_info(node3_addr).await.pubkey;

    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(OUTGOING_ASSET_AMOUNT),
        Some(&asset_a),
    )
    .await;

    assert_eq!(
        asset_balance_spendable(node1_addr, &asset_a).await,
        ISSUED_ASSET_AMOUNT - OUTGOING_ASSET_AMOUNT
    );

    // give node2 the asset it will route over the 2-3 channel
    let recipient_id = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_a,
        Assignment::Fungible(OUTGOING_ASSET_AMOUNT),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(
        asset_balance_spendable(node2_addr, &asset_a).await,
        OUTGOING_ASSET_AMOUNT
    );

    let channel_23 = open_channel(
        node2_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        Some(OUTGOING_ASSET_AMOUNT),
        Some(&asset_a),
    )
    .await;
    assert_eq!(asset_balance_spendable(node2_addr, &asset_a).await, 0);
    wait_for_usable_channels(node1_addr, 1).await;
    wait_for_usable_channels(node2_addr, 2).await;
    wait_for_usable_channels(node3_addr, 1).await;

    let channels_2 = list_channels(node2_addr).await;
    let find = |id: &str| {
        channels_2
            .iter()
            .find(|c| c.channel_id == id)
            .unwrap()
            .clone()
    };
    let chan_2_12_before = find(&channel_12.channel_id);
    let chan_2_23_before = find(&channel_23.channel_id);
    assert_eq!(chan_2_12_before.asset_local_amount, Some(0));
    assert_eq!(
        chan_2_12_before.asset_remote_amount,
        Some(OUTGOING_ASSET_AMOUNT)
    );
    assert_eq!(
        chan_2_23_before.asset_local_amount,
        Some(OUTGOING_ASSET_AMOUNT)
    );
    assert_eq!(chan_2_23_before.asset_remote_amount, Some(0));

    Setup {
        node1_addr,
        node2_addr,
        node3_addr,
        node2_dir: test_dir_node2,
        node1_pubkey,
        asset_a,
        channel_12,
        channel_23,
        chan_2_12_before,
        chan_2_23_before,
    }
}

// node2's channels and node3's inbound balance must be untouched by the attempted drain
async fn assert_victim_unchanged(s: &Setup, drained_asset: &str, check_inbound_channel: bool) {
    let channels_2_after = list_channels(s.node2_addr).await;
    let mut channels = vec![(&s.channel_23.channel_id, &s.chan_2_23_before)];
    if check_inbound_channel {
        channels.push((&s.channel_12.channel_id, &s.chan_2_12_before));
    }
    for (id, before) in channels {
        let after = channels_2_after
            .iter()
            .find(|c| &c.channel_id == id)
            .unwrap();
        assert_eq!(after.asset_local_amount, before.asset_local_amount);
        assert_eq!(after.asset_remote_amount, before.asset_remote_amount);
    }
    assert_eq!(
        asset_balance(s.node3_addr, drained_asset)
            .await
            .offchain_outbound,
        0
    );
}

fn assert_node2_logged(s: &Setup, msg: &str) {
    assert!(
        ldk_log_lines(&s.node2_dir).iter().any(|l| l.contains(msg)),
        "node2 log doesn't contain \"{msg}\""
    );
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn forward_rgb_amount_mismatch_is_rejected() {
    initialize();
    let s = setup(TEST_DIR_BASE).await;

    let LNInvoiceResponse { invoice } = ln_invoice(
        s.node3_addr,
        None,
        Some(&s.asset_a),
        Some(OUTGOING_ASSET_AMOUNT),
        900,
    )
    .await;

    // Simulate a malicious sender: node1 pays an invoice for OUTGOING_ASSET_AMOUNT,
    // so the onion asks node2 to forward 200, but the HTLC node1 hands to node2
    // only carries INCOMING_ASSET_AMOUNT (100). Node2 must reject the HTLC rather
    // than pay the 100 difference out of its own 2-3 channel balance, so the
    // payment fails, node2's channel balances stay the same and node3 receives
    // nothing.
    let _force = ForceFirstHopRgbPaymentGuard::set(
        &s.node1_pubkey,
        Some((&s.asset_a, INCOMING_ASSET_AMOUNT)),
    );
    send_payment_and_assert_failed(s.node1_addr, invoice).await;

    assert_node2_logged(
        &s,
        "The forwarded RGB amount exceeds the incoming RGB amount",
    );
    assert_victim_unchanged(&s, &s.asset_a, true).await;
}

// the attacker sends no RGB at all while the onion asks node2 to forward some
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn forward_rgb_missing_incoming_is_rejected() {
    initialize();
    let s = setup("tmp/forward_rgb_missing_incoming/").await;

    let LNInvoiceResponse { invoice } = ln_invoice(
        s.node3_addr,
        None,
        Some(&s.asset_a),
        Some(OUTGOING_ASSET_AMOUNT),
        900,
    )
    .await;

    let _force = ForceFirstHopRgbPaymentGuard::set(&s.node1_pubkey, None);
    send_payment_and_assert_failed(s.node1_addr, invoice).await;

    assert_node2_logged(&s, "The forwarded RGB asset doesn't match the incoming one");
    assert_victim_unchanged(&s, &s.asset_a, true).await;
}

// the attacker's channel to node2 is colored with asset A, but the update_add_htlc names another
// contract: node2 must reject it based on its channel's asset, not trust the wire contract
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn forward_rgb_wire_contract_not_matching_channel_is_rejected() {
    initialize();
    let s = setup("tmp/forward_rgb_wire_contract/").await;
    let other_asset = issue_asset_nia(s.node1_addr).await.asset_id;
    let node2_pubkey = node_info(s.node2_addr).await.pubkey;

    let LNInvoiceResponse { invoice } = ln_invoice(
        s.node3_addr,
        None,
        Some(&s.asset_a),
        Some(OUTGOING_ASSET_AMOUNT),
        900,
    )
    .await;

    let _force = ForceUpdateAddHtlcContractGuard::set(&node2_pubkey, &other_asset);
    // node2 closes the attacker's channel, so the payment stays pending instead of failing
    let payment_hash = send_payment_raw(s.node1_addr, invoice)
        .await
        .payment_hash
        .unwrap();
    let msg = "an RGB asset that doesn't match this channel";
    let t_0 = OffsetDateTime::now_utc();
    while !ldk_log_lines(&s.node2_dir).iter().any(|l| l.contains(msg)) {
        assert!(
            (OffsetDateTime::now_utc() - t_0).as_seconds_f32() < 120.0,
            "node2 never rejected the HTLC"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(
        check_payment_status(s.node1_addr, &payment_hash, HTLCStatus::Succeeded)
            .await
            .is_none()
    );
    assert_victim_unchanged(&s, &s.asset_a, false).await;
}

// node2 has a second channel to node3, colored with asset B. The honest part of the payment is for
// asset A, but the onion node1 builds asks node2 to forward OUTGOING_ASSET_AMOUNT of B, and node2
// picks any usable channel to the next peer that matches the onion's contract. Node2 must notice
// that it received A, not B, and reject the HTLC instead of paying B out of that channel.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn forward_rgb_different_outgoing_contract_is_rejected() {
    initialize();
    let s = setup("tmp/forward_rgb_different_contract/").await;
    let asset_b = issue_asset_nia(s.node1_addr).await.asset_id;
    let node3_pubkey = node_info(s.node3_addr).await.pubkey;

    // node2 holds asset B and has a second channel with node3 colored with it
    let recipient_id = rgb_invoice(s.node2_addr, None, false).await.recipient_id;
    send_asset(
        s.node1_addr,
        &asset_b,
        Assignment::Fungible(OUTGOING_ASSET_AMOUNT),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(s.node2_addr).await;
    refresh_transfers(s.node2_addr).await;
    refresh_transfers(s.node1_addr).await;
    let channel_23_b = open_channel(
        s.node2_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        Some(100000),
        None,
        Some(OUTGOING_ASSET_AMOUNT),
        Some(&asset_b),
    )
    .await;
    wait_for_usable_channels(s.node2_addr, 3).await;
    let chan_23_b_before = list_channels(s.node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == channel_23_b.channel_id)
        .unwrap();
    assert_eq!(
        chan_23_b_before.asset_local_amount,
        Some(OUTGOING_ASSET_AMOUNT)
    );

    let LNInvoiceResponse { invoice } = ln_invoice(
        s.node3_addr,
        None,
        Some(&s.asset_a),
        Some(OUTGOING_ASSET_AMOUNT),
        900,
    )
    .await;

    let _force =
        ForceSecondHopRgbPaymentGuard::set(&s.node1_pubkey, &asset_b, OUTGOING_ASSET_AMOUNT);
    send_payment_and_assert_failed(s.node1_addr, invoice).await;

    assert_node2_logged(&s, "The forwarded RGB asset doesn't match the incoming one");
    assert_victim_unchanged(&s, &s.asset_a, true).await;
    let chan_23_b_after = list_channels(s.node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == channel_23_b.channel_id)
        .unwrap();
    assert_eq!(
        chan_23_b_after.asset_local_amount,
        chan_23_b_before.asset_local_amount
    );
    assert_eq!(
        chan_23_b_after.asset_remote_amount,
        chan_23_b_before.asset_remote_amount
    );
}

// Swap HTLCs skip the forward check because the swap handler is supposed to vet them against the
// swap the taker whitelisted. In a BTC -> asset swap the handler used to look only at what the
// taker receives, so the maker, who builds the onion, could also ask the taker to forward
// OUTGOING_ASSET_AMOUNT of the asset its outbound channel is colored with. Simulate that: node1
// (maker) swaps BTC for asset A with node2 (taker), whose channel to node1 is colored with asset X,
// and puts an extra 100 X in the payload for node2. Node2 must fail the swap and keep its X.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn forward_rgb_swap_outbound_rgb_is_rejected() {
    initialize();

    let test_dir_base = "tmp/forward_rgb_swap_outbound_rgb/";
    let test_dir_node2 = format!("{test_dir_base}node2");
    let (node1_addr, _) =
        start_node(&format!("{test_dir_base}node1"), NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_a = issue_asset_nia(node1_addr).await.asset_id;
    let asset_x = issue_asset_nia(node1_addr).await.asset_id;
    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // node1 -> node2 carries the asset being bought
    open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_a),
    )
    .await;

    // node2 -> node1 is colored with asset X, which node2 holds on its side
    let recipient_id = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_x,
        Assignment::Fungible(OUTGOING_ASSET_AMOUNT),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    let channel_21 = open_channel(
        node2_addr,
        &node1_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100000),
        Some(546000),
        Some(OUTGOING_ASSET_AMOUNT),
        Some(&asset_x),
    )
    .await;
    wait_for_usable_channels(node1_addr, 2).await;
    wait_for_usable_channels(node2_addr, 2).await;

    let chan_21_before = list_channels(node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == channel_21.channel_id)
        .unwrap();
    assert_eq!(
        chan_21_before.asset_local_amount,
        Some(OUTGOING_ASSET_AMOUNT)
    );
    assert_eq!(chan_21_before.asset_remote_amount, Some(0));

    let maker_init_response = maker_init(node1_addr, 50000, None, 10, Some(&asset_a), 3600).await;
    taker(node2_addr, maker_init_response.swapstring.clone()).await;

    let _force = ForceSecondHopRgbPaymentGuard::set(&node1_pubkey, &asset_x, INCOMING_ASSET_AMOUNT);
    maker_execute(
        node1_addr,
        maker_init_response.swapstring,
        maker_init_response.payment_secret,
        node2_pubkey,
    )
    .await;

    wait_for_swap_status(
        node2_addr,
        &maker_init_response.payment_hash,
        SwapStatus::Failed,
    )
    .await;
    // the swap handler fails the intercepted HTLC instead of forwarding it
    let payment_hash = &maker_init_response.payment_hash;
    assert!(
        ldk_log_lines(&test_dir_node2).iter().any(|l| l
            .contains(&format!("Failing HTLC with payment_hash {payment_hash}"))
            && l.contains("UnknownNextPeer")),
        "node2 log doesn't show the swap HTLC being failed"
    );

    let chan_21_after = list_channels(node2_addr)
        .await
        .into_iter()
        .find(|c| c.channel_id == channel_21.channel_id)
        .unwrap();
    assert_eq!(
        chan_21_after.asset_local_amount,
        chan_21_before.asset_local_amount
    );
    assert_eq!(
        chan_21_after.asset_remote_amount,
        chan_21_before.asset_remote_amount
    );
}
