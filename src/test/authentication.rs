use super::*;

const TEST_DIR_BASE: &str = "tmp/authentication/";

fn create_token(
    root: &KeyPair,
    user_role: Option<&str>,
    operations: Vec<&str>,
    expiration_date: Option<DateTime<Utc>>,
) -> String {
    let mut authority = biscuit!("");
    if let Some(user_role) = user_role {
        authority = biscuit_merge!(authority, r#"role({user_role});"#);
    }
    for op in operations {
        authority = biscuit_merge!(authority, r#"right("api", {op});"#);
    }
    if let Some(expiration_date) = expiration_date {
        let exp = date(&expiration_date.into());
        authority = biscuit_merge!(authority, r#"check if time($t), $t < {exp};"#);
    }
    authority.build(root).unwrap().to_base64().unwrap()
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn authentication() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");

    let root_keypair = KeyPair::new();
    let root_public_key = root_keypair.public();

    let _ = std::fs::remove_dir_all(&test_dir_node1);
    let node_address = start_daemon(&test_dir_node1, NODE1_PEER_PORT, Some(root_public_key)).await;

    // admin can do everything
    let admin_token = create_token(&root_keypair, Some("admin"), vec![], None);
    let password = "a_password";
    let payload = InitRequest {
        password: password.to_string(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/init"))
        .json(&payload)
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<InitResponse>()
        .await
        .unwrap();
    let payload = unlock_req(password);
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/unlock"))
        .json(&payload)
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();

    // user with custom role can call only allowed operations and none after token expiration
    let now = Local::now().to_utc();
    let ten_seconds_later = now + chrono::Duration::seconds(10);
    let user_token = create_token(
        &root_keypair,
        Some("custom"),
        vec!["/nodeinfo", "/networkinfo"],
        Some(ten_seconds_later),
    );
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<NodeInfoResponse>()
        .await
        .unwrap();
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/networkinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<NetworkInfoResponse>()
        .await
        .unwrap();
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/address"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    while Utc::now() < ten_seconds_later {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/networkinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);

    // user with no role cannot do any operation
    let user_token = create_token(&root_keypair, None, vec!["/nodeinfo"], None);
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);

    // user with unknown role cannot do any operation
    let user_token = create_token(&root_keypair, Some("unknown"), vec!["/nodeinfo"], None);
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);

    // user with read-only role can only call read-only APIs
    let user_token = create_token(&root_keypair, Some("read-only"), vec![], None);
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<NodeInfoResponse>()
        .await
        .unwrap();
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/address"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);

    // user cannot call any API after token revocation
    let user_token = create_token(&root_keypair, Some("custom"), vec!["/nodeinfo"], None);
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<NodeInfoResponse>()
        .await
        .unwrap();
    let payload = RevokeTokenRequest {
        token: user_token.clone(),
    };
    let res = reqwest::Client::new()
        .post(format!("http://{node_address}/revoketoken"))
        .json(&payload)
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    _check_response_is_ok(res)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);

    // with no token no API can be called
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);

    // with an invalid token no API can be called
    let res = reqwest::Client::new()
        .get(format!("http://{node_address}/nodeinfo"))
        .bearer_auth("invalid_token")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}
