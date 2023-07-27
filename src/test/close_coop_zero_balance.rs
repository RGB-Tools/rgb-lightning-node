use super::*;

const TEST_DIR_BASE: &str = "tmp/close_coop_zero_balance/";
const NODE1_PEER_PORT: u16 = 9851;
const NODE2_PEER_PORT: u16 = 9852;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[serial_test::serial]
async fn close_coop_zero_balance() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let node1_addr = start_node(test_dir_node1, NODE1_PEER_PORT);
    let node2_addr = start_node(test_dir_node2, NODE2_PEER_PORT);

    fund_and_create_utxos(node1_addr).await;
    fund_and_create_utxos(node2_addr).await;

    let asset_id = issue_asset(node1_addr).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    stop_mining();
    let channel = open_channel(node1_addr, &node2_pubkey, NODE2_PEER_PORT, 1000, &asset_id).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 0);

    stop_mining();
    close_channel(node1_addr, &channel.channel_id, &node2_pubkey, false).await;
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if asset_balance(node1_addr, &asset_id).await == 1000
            && asset_balance(node2_addr, &asset_id).await == 0
        {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
            panic!("closing TX is not becoming spendable")
        }
    }

    let blinded_utxo = rgb_invoice(node2_addr).await;
    send_asset(node1_addr, &asset_id, 700, blinded_utxo).await;
    mine(false);
    refresh_transfers(node2_addr).await;
    assert_eq!(asset_balance(node1_addr, &asset_id).await, 300);
    assert_eq!(asset_balance(node2_addr, &asset_id).await, 700);
}
