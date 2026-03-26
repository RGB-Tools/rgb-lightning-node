use super::*;

const TEST_DIR_BASE: &str = "tmp/channel_closed_lock_release/";

/// Test that verifies the rgb_send_lock is released after a channel's peer
/// disconnects before funding is generated.
///
/// Scenario: node1 opens a channel to node2, then immediately disconnects
/// the peer. If the disconnect happens before FundingGenerationReady, LDK
/// emits ChannelClosed with channel_funding_txo = None. Without the fix,
/// the lock is never released and node1 cannot open new channels.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn channel_closed_no_funding_releases_openchannel_lock() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}node2");
    let test_dir_node3 = format!("{TEST_DIR_BASE}node3");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let node2_info = node_info(node2_addr).await;
    let node2_pubkey = node2_info.pubkey;

    // Open a vanilla channel from node1 to node2 (just the API call, don't wait for funding)
    let open_channel_payload = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!(
            "{}@127.0.0.1:{}",
            node2_pubkey, NODE2_PEER_PORT
        ),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: None,
        asset_id: None,
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/openchannel"))
        .json(&open_channel_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Shut down node2 so LDK on node1 detects the peer going offline.
    // This triggers ChannelClosed (and possibly DiscardFunding).
    // The lock should be released regardless of which events fire.
    shutdown(&[node2_addr]).await;

    // Give LDK time to detect the disconnect and process events
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // Start node3 and try to open a new channel from node1
    let (node3_addr, _) = start_node(&test_dir_node3, NODE3_PEER_PORT, false).await;
    fund_and_create_utxos(node3_addr, None).await;
    let node3_info = node_info(node3_addr).await;
    let node3_pubkey = node3_info.pubkey;

    // Poll until the rgb_send_lock is released and we can open a new channel.
    // Without the fix, the lock stays stuck indefinitely and every attempt returns 403.
    let t_0 = OffsetDateTime::now_utc();
    loop {
        let open_channel_payload_2 = OpenChannelRequest {
            peer_pubkey_and_opt_addr: format!(
                "{}@127.0.0.1:{}",
                node3_pubkey, NODE3_PEER_PORT
            ),
            capacity_sat: 50_000,
            push_msat: 0,
            asset_amount: None,
            asset_id: None,
            push_asset_amount: None,
            public: true,
            with_anchors: true,
            fee_base_msat: None,
            fee_proportional_millionths: None,
            temporary_channel_id: None,
        };
        let res = reqwest::Client::new()
            .post(format!("http://{node1_addr}/openchannel"))
            .json(&open_channel_payload_2)
            .send()
            .await
            .unwrap();

        if res.status() == reqwest::StatusCode::OK {
            break;
        }
        assert_eq!(
            res.status(),
            reqwest::StatusCode::FORBIDDEN,
            "unexpected status code"
        );

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            panic!(
                "rgb_send_lock remained stuck for 60s after peer disconnect — \
                 node cannot open new channels"
            );
        }
    }

    shutdown(&[node1_addr, node3_addr]).await;
}
