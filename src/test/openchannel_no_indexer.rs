use super::*;

const TEST_DIR_BASE: &str = "tmp/openchannel_no_indexer/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn openchannel_no_indexer() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let node2_pubkey = node_info(node2_addr).await.pubkey;

    // open channel while indexer connectivity is broken
    let guard = ElectrsRestartGuard;
    guard.stop_electrs();
    let _ = open_channel_raw(
        node1_addr,
        &node2_pubkey,
        Some(NODE2_PEER_PORT),
        Some(100_000),
        Some(20_000),
        Some(100),
        Some(&asset_id),
        None,
        None,
        None,
        None,
        true,
        true,
    )
    .await;

    // check the channel opening failed for the correct reason
    let check_err_in_logs = async |node_dir| {
        let t_0 = OffsetDateTime::now_utc();
        'outer: loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let file = File::open(
                PathBuf::from(node_dir)
                    .join(LDK_DIR)
                    .join(LOGS_DIR)
                    .join(LDK_LOGS_FILE),
            )
            .unwrap();
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if line.unwrap().contains("Failed to connect to indexer") {
                    break 'outer;
                }
            }
            if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
                panic!("expected log line not found");
            }
        }
    };
    check_err_in_logs(&test_dir_node1).await;
    check_err_in_logs(&test_dir_node2).await;

    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let chans_1 = list_channels(node1_addr).await;
        let chans_2 = list_channels(node2_addr).await;
        if chans_1.is_empty() && chans_2.is_empty() {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("channel is not being closed");
        }
    }
}
