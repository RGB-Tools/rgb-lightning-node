use crate::routes::NodeState;

use super::*;

const TEST_DIR_BASE: &str = "tmp/node_state_test/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn success() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");

    if std::path::Path::new(&test_dir_node1).exists() {
        std::fs::remove_dir_all(&test_dir_node1).unwrap();
    }

    let node1_addr = start_daemon(&test_dir_node1, NODE1_PEER_PORT).await;
    let state_response = node_state(node1_addr).await;
    assert!(matches!(state_response.state, NodeState::None));

    let password = format!("{test_dir_node1}.{NODE1_PEER_PORT}");
    let payload = InitRequest {
        password: password.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{}/init", node1_addr))
        .json(&payload)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<InitResponse>()
        .await
        .unwrap();

    let state_response = node_state(node1_addr).await;
    assert!(matches!(state_response.state, NodeState::Locked));

    unlock(node1_addr, &password).await;

    let state_response = node_state(node1_addr).await;
    assert!(matches!(state_response.state, NodeState::Running));

    lock(node1_addr).await;

    let state_response = node_state(node1_addr).await;
    assert!(matches!(state_response.state, NodeState::Locked));

    unlock(node1_addr, &password).await;
    let state_response = node_state(node1_addr).await;
    assert!(matches!(state_response.state, NodeState::Running));

    let node_info_response = node_info(node1_addr).await;
    assert!(!node_info_response.pubkey.is_empty());
    assert_eq!(node_info_response.num_channels, 0);
    assert_eq!(node_info_response.num_peers, 0);

    println!("Node state test completed successfully");
}
