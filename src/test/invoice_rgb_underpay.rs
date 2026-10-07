use lightning::ln::channelmanager::FORCE_PATH_RGB_PAYMENT_ON_NODE;
use rgb_lib::ContractId;

use super::*;

const TEST_DIR_BASE: &str = "tmp/invoice_rgb_underpay/";
const CHANNEL_ASSET_AMOUNT: u64 = 100;
const INVOICE_ASSET_AMOUNT: u64 = 50;
const PAID_ASSET_AMOUNT: u64 = 1;

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
        *FORCE_PATH_RGB_PAYMENT_ON_NODE.lock().unwrap() = None;
    }
}

// Wait for the payment to leave Pending and return its final status
async fn wait_for_outbound_payment_final_status(
    node_address: SocketAddr,
    payment_hash: &str,
) -> HTLCStatus {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        for status in [HTLCStatus::Succeeded, HTLCStatus::Failed] {
            if check_payment_status(node_address, payment_hash, status)
                .await
                .is_some()
            {
                return status;
            }
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 120.0 {
            panic!("payment {payment_hash} still pending after 120s");
        }
    }
}

// A receiver must not settle an RGB invoice with less RGB than the invoice asks for.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn invoice_rgb_underpay_is_rejected() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

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
    wait_for_usable_channels(node2_addr, 1).await;

    let LNInvoiceResponse { invoice } = ln_invoice(
        node2_addr,
        None,
        Some(&asset_id),
        Some(INVOICE_ASSET_AMOUNT),
        900,
    )
    .await;

    let _force_path_rgb =
        ForcePathRgbPaymentGuard::set(&node1_pubkey, &asset_id, PAID_ASSET_AMOUNT);
    let send_payment = send_payment_raw(node1_addr, invoice).await;
    let payment_hash = send_payment.payment_hash.unwrap();
    let status = wait_for_outbound_payment_final_status(node1_addr, &payment_hash).await;

    // the payer must not get a settled payment for 1 unit of an invoice asking for 50
    assert_eq!(
        status,
        HTLCStatus::Failed,
        "RGB invoice for {INVOICE_ASSET_AMOUNT} units was settled by a payment of {PAID_ASSET_AMOUNT}"
    );
    assert!(
        check_payment_status(node2_addr, &payment_hash, HTLCStatus::Succeeded)
            .await
            .is_none(),
        "receiver recorded the underpaid RGB invoice as paid"
    );

    // no RGB moved
    let channels_1 = list_channels(node1_addr).await;
    let chan_1 = channels_1
        .iter()
        .find(|c| c.channel_id == channel.channel_id)
        .unwrap();
    assert_eq!(chan_1.asset_local_amount, Some(CHANNEL_ASSET_AMOUNT));
    assert_eq!(chan_1.asset_remote_amount, Some(0));
    let channels_2 = list_channels(node2_addr).await;
    let chan_2 = channels_2
        .iter()
        .find(|c| c.channel_id == channel.channel_id)
        .unwrap();
    assert_eq!(chan_2.asset_local_amount, Some(0));
    assert_eq!(chan_2.asset_remote_amount, Some(CHANNEL_ASSET_AMOUNT));
}
