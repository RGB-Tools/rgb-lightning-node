use lightning::ln::channelmanager::FORCE_FIRST_HOP_RGB_PAYMENT_ON_NODE;
use rgb_lib::ContractId;

use super::*;

const TEST_DIR_BASE: &str = "tmp/forward_rgb_amount_mismatch/";
const ISSUED_ASSET_AMOUNT: u64 = 1000;
const INCOMING_ASSET_AMOUNT: u64 = 100;
const OUTGOING_ASSET_AMOUNT: u64 = 200;

struct ForceFirstHopRgbPaymentGuard;

impl ForceFirstHopRgbPaymentGuard {
    fn set(node_pubkey: &str, asset_id: &str, amount: u64) -> Self {
        let pubkey = PublicKey::from_str(node_pubkey).unwrap();
        let contract_id = ContractId::from_str(asset_id).unwrap();
        *FORCE_FIRST_HOP_RGB_PAYMENT_ON_NODE.lock().unwrap() = Some((pubkey, contract_id, amount));
        Self
    }
}

impl Drop for ForceFirstHopRgbPaymentGuard {
    fn drop(&mut self) {
        *FORCE_FIRST_HOP_RGB_PAYMENT_ON_NODE.lock().unwrap() = None;
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

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn forward_rgb_amount_mismatch_is_rejected() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_info = node_info(node1_addr).await;
    let node2_info = node_info(node2_addr).await;
    let node3_info = node_info(node3_addr).await;
    let node1_pubkey = node1_info.pubkey;
    let node2_pubkey = node2_info.pubkey;
    let node3_pubkey = node3_info.pubkey;

    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(OUTGOING_ASSET_AMOUNT),
        Some(&asset_id),
    )
    .await;
    assert_eq!(
        asset_balance_spendable(node1_addr, &asset_id).await,
        ISSUED_ASSET_AMOUNT - OUTGOING_ASSET_AMOUNT
    );

    let recipient_id = rgb_invoice(node2_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
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
        asset_balance_spendable(node2_addr, &asset_id).await,
        OUTGOING_ASSET_AMOUNT
    );

    let channel_23 = open_channel(
        node2_addr,
        &node3_pubkey,
        Some(NODE3_PEER_PORT),
        None,
        None,
        Some(OUTGOING_ASSET_AMOUNT),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 0);
    wait_for_usable_channels(node1_addr, 1).await;
    wait_for_usable_channels(node2_addr, 2).await;
    wait_for_usable_channels(node3_addr, 1).await;

    let channels_2_before = list_channels(node2_addr).await;
    let chan_2_12_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_23_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_23.channel_id)
        .unwrap();
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

    let LNInvoiceResponse { invoice } = ln_invoice(
        node3_addr,
        None,
        Some(&asset_id),
        Some(OUTGOING_ASSET_AMOUNT),
        900,
    )
    .await;

    let _force_first_hop_rgb =
        ForceFirstHopRgbPaymentGuard::set(&node1_pubkey, &asset_id, INCOMING_ASSET_AMOUNT);
    send_payment_and_assert_failed(node1_addr, invoice).await;

    let channels_2_after = list_channels(node2_addr).await;
    let chan_2_12_after = channels_2_after
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_23_after = channels_2_after
        .iter()
        .find(|c| c.channel_id == channel_23.channel_id)
        .unwrap();
    assert_eq!(
        chan_2_12_after.asset_local_amount,
        chan_2_12_before.asset_local_amount
    );
    assert_eq!(
        chan_2_12_after.asset_remote_amount,
        chan_2_12_before.asset_remote_amount
    );
    assert_eq!(
        chan_2_23_after.asset_local_amount,
        chan_2_23_before.asset_local_amount
    );
    assert_eq!(
        chan_2_23_after.asset_remote_amount,
        chan_2_23_before.asset_remote_amount
    );
    assert_eq!(
        asset_balance(node3_addr, &asset_id).await.offchain_outbound,
        0
    );
}
