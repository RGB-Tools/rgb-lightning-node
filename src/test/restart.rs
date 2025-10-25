use super::*;

const TEST_DIR_BASE: &str = "tmp/restart/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn restart() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");

    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;

    println!("1 - restart all");
    shutdown(&[node1_addr, node2_addr, node3_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, true).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;
    fund_and_create_utxos(node3_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);

    println!("2 - restart 1+2");
    shutdown(&[node1_addr, node2_addr, node3_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    let channel = open_channel(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        None,
        None,
        Some(600),
        Some(&asset_id),
    )
    .await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    println!("3 - restart 1");
    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node1_addr).await;
        let channel = channels
            .iter()
            .find(|c| c.channel_id == channel.channel_id)
            .unwrap();
        if channel.ready {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find re-established channel")
        }
    }
    println!("4 - restart 1+2");
    shutdown(&[node1_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node1_addr).await;
        let channel = channels
            .iter()
            .find(|c| c.channel_id == channel.channel_id)
            .unwrap();
        if channel.ready {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find re-established channel")
        }
    }
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 400);

    let LNInvoiceResponse { invoice } =
        ln_invoice(node2_addr, None, Some(&asset_id), Some(100), 900).await;
    let send_payment = send_payment(node1_addr, invoice).await;

    println!("5 - restart 1+2");
    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let channels = list_channels(node1_addr).await;
        let channel = channels
            .iter()
            .find(|c| c.channel_id == channel.channel_id)
            .unwrap();
        if channel.ready {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find re-established channel")
        }
    }
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let payments = list_payments(node1_addr).await;
        let payment = payments
            .iter()
            .find(|p| p.payment_hash == send_payment.payment_hash)
            .unwrap();
        if matches!(payment.status, HTLCStatus::Succeeded) {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find payment on node 1")
        }
    }
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let payments = list_payments(node2_addr).await;
        let payment = payments
            .iter()
            .find(|p| p.payment_hash == send_payment.payment_hash)
            .unwrap();
        if matches!(payment.status, HTLCStatus::Succeeded) {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("cannot find payment on node 2")
        }
    }
    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    wait_for_balance(node1_addr, &asset_id, 900).await;
    wait_for_balance(node2_addr, &asset_id, 100).await;

    println!("6 - restart all");
    shutdown(&[node1_addr, node2_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, true).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 900);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 100);

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node1_addr,
        &asset_id,
        Assignment::Fungible(700),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node1_addr).await;

    let recipient_id = rgb_invoice(node3_addr, None, false).await.recipient_id;
    send_asset(
        node2_addr,
        &asset_id,
        Assignment::Fungible(50),
        recipient_id,
        None,
    )
    .await;
    mine(false);
    refresh_transfers(node3_addr).await;
    refresh_transfers(node3_addr).await;
    refresh_transfers(node2_addr).await;

    println!("7 - restart all");
    shutdown(&[node1_addr, node2_addr, node3_addr]).await;
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, true).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, true).await;
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, true).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 200);
    assert_eq!(asset_balance_spendable(node2_addr, &asset_id).await, 50);
    assert_eq!(asset_balance_spendable(node3_addr, &asset_id).await, 750);
}
