use lightning::ln::channelmanager::FORCE_PATH_RGB_PAYMENT_ON_NODE;
use rgb_lib::ContractId;

use super::*;

const TEST_DIR_BASE: &str = "tmp/rgb_htlc_balance_checks/";
const CHANNEL_ASSET_AMOUNT: u64 = 100;
const HTLC_ASSET_AMOUNT: u64 = 60;

struct ForcePathRgbPaymentGuard;

impl ForcePathRgbPaymentGuard {
    fn set(node_pubkey: &str, asset_id: &str, amount: u64) -> Self {
        let pubkey = PublicKey::from_str(node_pubkey).unwrap();
        let contract_id = ContractId::from_str(asset_id).unwrap();
        *FORCE_PATH_RGB_PAYMENT_ON_NODE.lock().unwrap() = Some((pubkey, contract_id, amount));
        Self
    }
}

impl Drop for ForcePathRgbPaymentGuard {
    fn drop(&mut self) {
        *FORCE_PATH_RGB_PAYMENT_ON_NODE
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}

async fn node_alive(node_address: SocketAddr) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    match client
        .get(format!("http://{node_address}/nodeinfo"))
        .send()
        .await
    {
        Ok(res) => res.status() == reqwest::StatusCode::OK,
        Err(_) => false,
    }
}

// Sends a payment without requiring the request to succeed
async fn try_send_payment(node_address: SocketAddr, invoice: String) -> Option<String> {
    let payload = SendPaymentRequest {
        invoice,
        amt_msat: None,
        asset_id: None,
        asset_amount: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/sendpayment"))
        .json(&payload)
        .send()
        .await
        .ok()?;
    if res.status() != reqwest::StatusCode::OK {
        println!("sendpayment rejected: {:?}", res.text().await);
        return None;
    }
    res.json::<SendPaymentResponse>().await.ok()?.payment_hash
}

async fn wait_for_held_payments(count: usize) {
    let t_0 = OffsetDateTime::now_utc();
    while HELD_PAYMENT_CLAIMABLE_COUNT.load(Ordering::SeqCst) < count {
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 40.0 {
            panic!("receiver did not receive payment #{count} to hold");
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

// Like wait_for_ln_payment, but fails right away if the node goes down while waiting
async fn wait_for_ln_payment_failed_while_alive(node_address: SocketAddr, payment_hash: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        assert!(
            node_alive(node_address).await,
            "node {node_address} went down while waiting for payment {payment_hash} to fail"
        );
        if check_payment_status(node_address, payment_hash, HTLCStatus::Failed)
            .await
            .is_some()
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 40.0 {
            panic!("payment {payment_hash} did not fail");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// Waits for the channel to be closed or no longer usable, failing right away if the node goes down
async fn wait_for_channel_unusable_while_alive(node_address: SocketAddr, channel_id: &str) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        assert!(
            node_alive(node_address).await,
            "node {node_address} went down while waiting for channel {channel_id} to close"
        );
        let channels = list_channels(node_address).await;
        if channels
            .iter()
            .all(|c| c.channel_id != channel_id || !c.is_usable)
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 40.0 {
            panic!("channel {channel_id} is still usable");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

// A node must not have more RGB in flight than its balance: with 100 units in the channel, a
// second 60-unit payment must not be sent while the first 60 units are still in flight.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_outbound_htlcs_cannot_exceed_balance() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}outbound_node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}outbound_node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(CHANNEL_ASSET_AMOUNT),
        Some(&asset_id),
    )
    .await;
    wait_for_usable_channels(node1_addr, 1).await;

    // node2 holds incoming payments so their HTLCs stay in flight
    let _hold = HoldPaymentsGuard::set(&node2_pubkey);

    let LNInvoiceResponse { invoice: invoice_1 } = ln_invoice(
        node2_addr,
        None,
        Some(&asset_id),
        Some(HTLC_ASSET_AMOUNT),
        900,
    )
    .await;
    let LNInvoiceResponse { invoice: invoice_2 } = ln_invoice(
        node2_addr,
        None,
        Some(&asset_id),
        Some(HTLC_ASSET_AMOUNT),
        900,
    )
    .await;

    assert!(try_send_payment(node1_addr, invoice_1).await.is_some());
    wait_for_held_payments(1).await;
    assert!(
        node_alive(node1_addr).await,
        "node1 down after the first in-flight HTLC"
    );

    // 60 + 60 > 100: the second payment has to be refused
    // sendpayment accepts the request; the send itself must fail without node1 going down
    let second = try_send_payment(node1_addr, invoice_2).await;
    assert!(
        node_alive(node1_addr).await,
        "node1 went down with more RGB in flight than it owns"
    );
    let second_hash = second
        .as_ref()
        .expect("sendpayment rejected the second payment");
    wait_for_ln_payment_failed_while_alive(node1_addr, second_hash).await;
    assert_eq!(
        HELD_PAYMENT_CLAIMABLE_COUNT.load(Ordering::SeqCst),
        1,
        "node2 received a second HTLC that node1 cannot cover (accepted: {second:?})"
    );

    let channels = list_channels(node1_addr).await;
    let chan = channels
        .iter()
        .find(|c| c.channel_id == channel.channel_id)
        .unwrap();
    assert_eq!(chan.asset_local_amount, Some(CHANNEL_ASSET_AMOUNT));
}

// An incoming HTLC must carry the channel's asset: the amount is checked against the channel's
// balance, so an HTLC of another asset must not be accepted.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn rgb_inbound_htlc_of_other_asset_is_rejected() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}asset_node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}asset_node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let other_asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let node1_pubkey = node_info(node1_addr).await.pubkey;
    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(CHANNEL_ASSET_AMOUNT),
        Some(&asset_id),
    )
    .await;
    wait_for_usable_channels(node1_addr, 1).await;

    let _hold = HoldPaymentsGuard::set(&node2_pubkey);
    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        None,
        Some(&asset_id),
        Some(HTLC_ASSET_AMOUNT),
        900,
    )
    .await;

    // the payer puts HTLC_ASSET_AMOUNT of another asset on the HTLC
    let _force_path_rgb =
        ForcePathRgbPaymentGuard::set(&node1_pubkey, &other_asset_id, HTLC_ASSET_AMOUNT);
    let payment_hash = try_send_payment(node1_addr, invoice).await;

    // the offending peer's channel is closed, without node2 going down
    wait_for_channel_unusable_while_alive(node2_addr, &channel.channel_id).await;
    assert_eq!(
        HELD_PAYMENT_CLAIMABLE_COUNT.load(Ordering::SeqCst),
        0,
        "node2 accepted an HTLC of another asset (payment {payment_hash:?})"
    );
}
