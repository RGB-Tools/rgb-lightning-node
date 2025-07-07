use super::*;

const TEST_DIR_BASE: &str = "tmp/lock_unlock_changepassword/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn lock_unlock_changepassword() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");

    let (node1_addr, node1_password) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;

    println!("1 - lock+unlock");
    lock(node1_addr).await;
    unlock(node1_addr, &node1_password).await;

    fund_and_create_utxos(node1_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);

    println!("2 - change password");
    // an unlocked node should refuse a password change
    let new_password = "while_locked";
    let payload = ChangePasswordRequest {
        old_password: node1_password.to_string(),
        new_password: new_password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/changepassword"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(res.text().await.unwrap().contains("Node is unlocked"));

    lock(node1_addr).await;

    // new password needs to be strong enough
    let new_password = "short";
    let payload = ChangePasswordRequest {
        old_password: node1_password.to_string(),
        new_password: new_password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/changepassword"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(res.text().await.unwrap().contains("Invalid password"));

    // wrong password
    let new_password = format!("{node1_password}_changed");
    let wrong_password = "!nc0rr3ct";
    let payload = ChangePasswordRequest {
        old_password: wrong_password.to_string(),
        new_password: new_password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node1_addr}/changepassword"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(res
        .text()
        .await
        .unwrap()
        .contains("The provided password is incorrect"));

    // successful password change
    change_password(node1_addr, &node1_password, &new_password).await;

    unlock(node1_addr, &new_password).await;
    assert_eq!(asset_balance_spendable(node1_addr, &asset_id).await, 1000);

    // unlock an already unlocked node
    let res = unlock_res(node1_addr, &new_password).await;
    check_response_is_nok(
        res,
        reqwest::StatusCode::FORBIDDEN,
        "Node has already been unlocked",
        "AlreadyUnlocked",
    )
    .await;
}
