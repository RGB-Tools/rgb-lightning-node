use self::routes::HTLC_MIN_MSAT;

use super::*;

const TEST_DIR_BASE: &str = "tmp/multi_hop/";
const NODE1_PEER_PORT: u16 = 9901;
const NODE2_PEER_PORT: u16 = 9902;
const NODE3_PEER_PORT: u16 = 9903;

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn multi_hop() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;
    fund_and_create_utxos(node3_addr).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node1_info = node_info(node1_addr).await;
    let node1_pubkey = node1_info.pubkey;
    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;
    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 400, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node1_addr).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 600);

    let channel_12 = open_channel(
        node1_addr,
        &node2_pubkey,
        NODE2_PEER_PORT,
        None,
        None,
        Some(500),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 100);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 400);

    let channel_23 = open_channel(
        node2_addr,
        &node3_pubkey,
        NODE3_PEER_PORT,
        None,
        None,
        Some(300),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 100);

    println!("check balances and channels before payment");
    // check off-chain balances
    let balance_1 = asset_balance(node1_addr, &asset_id).await;
    let balance_2 = asset_balance(node2_addr, &asset_id).await;
    let balance_3 = asset_balance(node3_addr, &asset_id).await;
    assert_eq!(balance_1.offchain_outbound, 500);
    assert_eq!(balance_1.offchain_inbound, 0);
    assert_eq!(balance_2.offchain_outbound, 300);
    assert_eq!(balance_2.offchain_inbound, 500);
    assert_eq!(balance_3.offchain_outbound, 0);
    assert_eq!(balance_3.offchain_inbound, 300);
    // check channel RGB amounts
    let channels_1_before = list_channels(node1_addr).await;
    let channels_2_before = list_channels(node2_addr).await;
    let channels_3_before = list_channels(node3_addr).await;
    dbg!(&channels_1_before);
    dbg!(&channels_2_before);
    dbg!(&channels_3_before);
    assert_eq!(channels_1_before.len(), 1);
    assert_eq!(channels_3_before.len(), 1);
    let chan_1_12_before = channels_1_before.first().unwrap();
    let chan_2_12_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_23_before = channels_2_before
        .iter()
        .find(|c| c.channel_id == channel_23.channel_id)
        .unwrap();
    let chan_3_23_before = channels_3_before.first().unwrap();
    assert_eq!(chan_1_12_before.asset_local_amount, Some(500));
    assert_eq!(chan_1_12_before.asset_remote_amount, Some(0));
    assert_eq!(chan_2_12_before.asset_local_amount, Some(0));
    assert_eq!(chan_2_12_before.asset_remote_amount, Some(500));
    assert_eq!(chan_2_23_before.asset_local_amount, Some(300));
    assert_eq!(chan_2_23_before.asset_remote_amount, Some(0));
    assert_eq!(chan_3_23_before.asset_local_amount, Some(0));
    assert_eq!(chan_3_23_before.asset_remote_amount, Some(300));

    let LNInvoiceResponse { invoice } =
        ln_invoice(node3_addr, None, Some(&asset_id), Some(50), 900).await;
    let _ = send_payment(node1_addr, invoice).await;

    println!("check balances and channels after payment");
    // check off-chain balances
    let balance_1 = asset_balance(node1_addr, &asset_id).await;
    let balance_2 = asset_balance(node2_addr, &asset_id).await;
    let balance_3 = asset_balance(node3_addr, &asset_id).await;
    assert_eq!(balance_1.offchain_outbound, 450);
    assert_eq!(balance_1.offchain_inbound, 50);
    assert_eq!(balance_2.offchain_outbound, 300);
    assert_eq!(balance_2.offchain_inbound, 500);
    assert_eq!(balance_3.offchain_outbound, 50);
    assert_eq!(balance_3.offchain_inbound, 250);
    // check channel RGB amounts
    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    let channels_3 = list_channels(node3_addr).await;
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_3.len(), 1);
    let chan_1_12 = channels_1.first().unwrap();
    let chan_2_12 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_23 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_23.channel_id)
        .unwrap();
    let chan_3_23 = channels_3.first().unwrap();
    assert_eq!(chan_1_12.asset_local_amount, Some(450));
    assert_eq!(chan_1_12.asset_remote_amount, Some(50));
    assert_eq!(chan_2_12.asset_local_amount, Some(50));
    assert_eq!(chan_2_12.asset_remote_amount, Some(450));
    assert_eq!(chan_2_23.asset_local_amount, Some(250));
    assert_eq!(chan_2_23.asset_remote_amount, Some(50));
    assert_eq!(chan_3_23.asset_local_amount, Some(50));
    assert_eq!(chan_3_23.asset_remote_amount, Some(250));

    println!("restart all nodes");
    shutdown(&[node1_addr, node2_addr, node3_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, true).await;

    println!("check balances and channels after nodes have restarted");
    // check off-chain balances
    let balance_1 = asset_balance(node1_addr, &asset_id).await;
    let balance_2 = asset_balance(node2_addr, &asset_id).await;
    let balance_3 = asset_balance(node3_addr, &asset_id).await;
    assert_eq!(balance_1.offchain_outbound, 450);
    assert_eq!(balance_1.offchain_inbound, 50);
    assert_eq!(balance_2.offchain_outbound, 300);
    assert_eq!(balance_2.offchain_inbound, 500);
    assert_eq!(balance_3.offchain_outbound, 50);
    assert_eq!(balance_3.offchain_inbound, 250);
    // check channel RGB amounts
    let channels_1 = list_channels(node1_addr).await;
    let channels_2 = list_channels(node2_addr).await;
    let channels_3 = list_channels(node3_addr).await;
    dbg!(&channels_1);
    dbg!(&channels_2);
    dbg!(&channels_3);
    assert_eq!(channels_1.len(), 1);
    assert_eq!(channels_3.len(), 1);
    let chan_1_12 = channels_1.first().unwrap();
    let chan_2_12 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_12.channel_id)
        .unwrap();
    let chan_2_23 = channels_2
        .iter()
        .find(|c| c.channel_id == channel_23.channel_id)
        .unwrap();
    let chan_3_23 = channels_3.first().unwrap();
    assert_eq!(chan_1_12.asset_local_amount, Some(450));
    assert_eq!(chan_1_12.asset_remote_amount, Some(50));
    assert_eq!(chan_2_12.asset_local_amount, Some(50));
    assert_eq!(chan_2_12.asset_remote_amount, Some(450));
    assert_eq!(chan_2_23.asset_local_amount, Some(250));
    assert_eq!(chan_2_23.asset_remote_amount, Some(50));
    assert_eq!(chan_3_23.asset_local_amount, Some(50));
    assert_eq!(chan_3_23.asset_remote_amount, Some(250));
    let fees = 1000;
    assert_eq!(
        chan_1_12.local_balance_msat,
        chan_1_12_before.local_balance_msat - HTLC_MIN_MSAT - fees
    );
    assert_eq!(
        chan_2_12.local_balance_msat,
        chan_2_12_before.local_balance_msat + HTLC_MIN_MSAT + fees
    );
    assert_eq!(
        chan_2_23.local_balance_msat,
        chan_2_23_before.local_balance_msat - HTLC_MIN_MSAT
    );
    assert_eq!(
        chan_3_23.local_balance_msat,
        chan_3_23_before.local_balance_msat + HTLC_MIN_MSAT
    );

    close_channel(node2_addr, &channel_12.channel_id, &node1_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 550).await;
    wait_for_balance(node2_addr, &asset_id, 150).await;

    close_channel(node3_addr, &channel_23.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node2_addr, &asset_id, 400).await;
    wait_for_balance(node3_addr, &asset_id, 50).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node1_addr, &asset_id, 200, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None).await.recipient_id;
    send_asset(node2_addr, &asset_id, 150, recipient_id).await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    let recipient_id = rgb_invoice(node2_addr, None).await.recipient_id;
    send_asset(node3_addr, &asset_id, 375, recipient_id).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    refresh_transfers(node2_addr).await;
    refresh_transfers(node3_addr).await;

    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 350);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 625);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 25);
}
