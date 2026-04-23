use super::*;

const TEST_DIR_BASE: &str = "tmp/openchannel_virtual/";
const VIRTUAL_TIMEOUT_BOUNDARY_CHUNK_SIZE: u16 = 144;
const VIRTUAL_TIMEOUT_BOUNDARY_SYNC_TIMEOUT_SECS: f32 = 30.0;

async fn close_channel_response(
    node_address: SocketAddr,
    channel_id: &str,
    peer_pubkey: &str,
    force: bool,
) -> reqwest::Response {
    let payload = CloseChannelRequest {
        channel_id: channel_id.to_string(),
        peer_pubkey: peer_pubkey.to_string(),
        force,
    };
    reqwest::Client::new()
        .post(format!("http://{node_address}/closechannel"))
        .json(&payload)
        .send()
        .await
        .unwrap()
}

async fn mine_blocks_and_wait_for_sync(
    host_node_address: SocketAddr,
    client_node_address: SocketAddr,
    blocks_to_mine: u16,
) {
    mine_n_blocks(false, blocks_to_mine);

    let expected_block_height = get_block_count();
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut host_node_last_height = 0;
    let mut client_node_last_height = 0;

    tokio::time::timeout(
        std::time::Duration::from_secs_f32(VIRTUAL_TIMEOUT_BOUNDARY_SYNC_TIMEOUT_SECS),
        async {
            loop {
                poll_interval.tick().await;
                host_node_last_height = network_info(host_node_address).await.height;
                client_node_last_height = network_info(client_node_address).await.height;
                if host_node_last_height == expected_block_height
                    && client_node_last_height == expected_block_height
                {
                    break;
                }
            }
        },
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "nodes did not sync to block height {expected_block_height} after mining \
             {blocks_to_mine} blocks (host={host_node_last_height}, \
             client={client_node_last_height})"
        )
    });
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_open_rejects_duplicate_peer_pair_concurrently_and_sequentially() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}duplicate/");
    let host_node_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    let (client_node_address, _client_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    fund_and_create_utxos(host_node_address, None).await;
    let issued_asset_id = issue_asset_nia(host_node_address).await.asset_id;
    let client_node_info = node_info(client_node_address).await;
    let client_node_pubkey_with_addr = format!(
        "{}@127.0.0.1:{}",
        client_node_info.pubkey, client_node_peer_port
    );

    let request_a = OpenChannelRequest {
        peer_pubkey_and_opt_addr: client_node_pubkey_with_addr.clone(),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(200),
        asset_id: Some(issued_asset_id.clone()),
        push_asset_amount: None,
        public: false,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
        virtual_open_mode: Some("trusted_no_broadcast".to_string()),
    };
    let request_b = OpenChannelRequest {
        peer_pubkey_and_opt_addr: client_node_pubkey_with_addr,
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(200),
        asset_id: Some(issued_asset_id.clone()),
        push_asset_amount: None,
        public: false,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
        virtual_open_mode: Some("trusted_no_broadcast".to_string()),
    };

    let (response_a, response_b) = tokio::join!(
        reqwest::Client::new()
            .post(format!("http://{host_node_address}/openchannel"))
            .json(&request_a)
            .send(),
        reqwest::Client::new()
            .post(format!("http://{host_node_address}/openchannel"))
            .json(&request_b)
            .send()
    );
    let response_a = response_a.unwrap();
    let response_b = response_b.unwrap();

    assert_ne!(
        response_a.status().is_success(),
        response_b.status().is_success()
    );
    let failed_response = if response_a.status().is_success() {
        response_b
    } else {
        response_a
    };
    let failed_status = failed_response.status();
    assert!(matches!(
        failed_status,
        reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::FORBIDDEN
    ));
    let failed_error = failed_response.json::<APIErrorResponse>().await.unwrap();
    assert!(
        failed_error
            .error
            .contains("already exists for this peer pair")
            || failed_error
                .error
                .contains("open channel operation is in progress")
    );

    let t_0 = time::OffsetDateTime::now_utc();
    loop {
        let host_node_channels = list_channels(host_node_address).await;
        let matching_virtual_channels: Vec<_> = host_node_channels
            .iter()
            .filter(|channel| {
                channel.peer_pubkey == client_node_info.pubkey
                    && channel.virtual_open_mode.as_deref() == Some("trusted_no_broadcast")
                    && channel.ready
                    && channel.is_usable
            })
            .collect();
        if matching_virtual_channels.len() == 1 {
            break;
        }
        if (time::OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 20.0 {
            panic!("expected exactly one trusted_no_broadcast channel for the peer");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let duplicate_virtual_open_request = OpenChannelRequest {
        peer_pubkey_and_opt_addr: format!(
            "{}@127.0.0.1:{}",
            client_node_info.pubkey, client_node_peer_port
        ),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(200),
        asset_id: Some(issued_asset_id),
        push_asset_amount: None,
        public: false,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
        virtual_open_mode: Some("trusted_no_broadcast".to_string()),
    };

    let response = reqwest::Client::new()
        .post(format!("http://{host_node_address}/openchannel"))
        .json(&duplicate_virtual_open_request)
        .send()
        .await
        .unwrap();
    let response_status = response.status();
    assert_eq!(response_status, reqwest::StatusCode::BAD_REQUEST);
    let error = response.json::<APIErrorResponse>().await.unwrap();
    assert!(error.error.contains("already exists for this peer pair"));

    let host_node_channels = list_channels(host_node_address).await;
    let matching_virtual_channel_count = host_node_channels
        .iter()
        .filter(|channel| {
            channel.peer_pubkey == client_node_info.pubkey
                && channel.virtual_open_mode.as_deref() == Some("trusted_no_broadcast")
        })
        .count();
    assert_eq!(matching_virtual_channel_count, 1);
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_open_rejects_invalid_requests() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}negative/");
    let host_node_virtual_disabled_peer_port = next_peer_port();
    let host_node_virtual_enabled_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_virtual_disabled_address, _host_node_virtual_disabled_password) = start_node(
        &format!("{test_storage_root}host_node_virtual_disabled"),
        host_node_virtual_disabled_peer_port,
        false,
    )
    .await;
    let (host_node_virtual_enabled_address, _host_node_virtual_enabled_password) =
        start_node_with_virtual_options(
            &format!("{test_storage_root}host_node_virtual_enabled"),
            host_node_virtual_enabled_peer_port,
            false,
            true,
            vec![],
        )
        .await;
    let (client_node_address, _client_node_password) = start_node(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
    )
    .await;

    fund_and_create_utxos(host_node_virtual_enabled_address, None).await;
    let issued_asset_id = issue_asset_nia(host_node_virtual_enabled_address)
        .await
        .asset_id;
    let client_node_info = node_info(client_node_address).await;
    let client_node_pubkey_with_addr = format!(
        "{}@127.0.0.1:{}",
        client_node_info.pubkey, client_node_peer_port
    );

    let request_when_virtual_feature_disabled = OpenChannelRequest {
        peer_pubkey_and_opt_addr: client_node_pubkey_with_addr.clone(),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(100),
        asset_id: Some(issued_asset_id.clone()),
        push_asset_amount: None,
        public: false,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
        virtual_open_mode: Some("trusted_no_broadcast".to_string()),
    };

    let response = reqwest::Client::new()
        .post(format!(
            "http://{host_node_virtual_disabled_address}/openchannel"
        ))
        .json(&request_when_virtual_feature_disabled)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        response,
        reqwest::StatusCode::BAD_REQUEST,
        "trusted virtual channels v0 are disabled",
        "InvalidRequest",
    )
    .await;

    let request_with_unknown_virtual_mode = OpenChannelRequest {
        peer_pubkey_and_opt_addr: client_node_pubkey_with_addr.clone(),
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(100),
        asset_id: Some(issued_asset_id.clone()),
        push_asset_amount: None,
        public: false,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
        virtual_open_mode: Some("wrong_mode".to_string()),
    };

    let response = reqwest::Client::new()
        .post(format!(
            "http://{host_node_virtual_enabled_address}/openchannel"
        ))
        .json(&request_with_unknown_virtual_mode)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        response,
        reqwest::StatusCode::BAD_REQUEST,
        "unknown virtual_open_mode: wrong_mode",
        "InvalidRequest",
    )
    .await;

    let request_with_public_channel_true = OpenChannelRequest {
        peer_pubkey_and_opt_addr: client_node_pubkey_with_addr,
        capacity_sat: 100_000,
        push_msat: 0,
        asset_amount: Some(100),
        asset_id: Some(issued_asset_id),
        push_asset_amount: None,
        public: true,
        with_anchors: true,
        fee_base_msat: None,
        fee_proportional_millionths: None,
        temporary_channel_id: None,
        virtual_open_mode: Some("trusted_no_broadcast".to_string()),
    };

    let response = reqwest::Client::new()
        .post(format!(
            "http://{host_node_virtual_enabled_address}/openchannel"
        ))
        .json(&request_with_public_channel_true)
        .send()
        .await
        .unwrap();
    check_response_is_nok(
        response,
        reqwest::StatusCode::BAD_REQUEST,
        "virtual channels requires public=false",
        "InvalidRequest",
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_trusted_no_broadcast_survives_funding_timeout_and_routes_btc_and_rgb_payments() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}positive/");
    let host_node_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    fund_and_create_utxos(host_node_address, None).await;
    let issued_asset_id = issue_asset_nia_with_amounts(host_node_address, vec![500, 500])
        .await
        .asset_id;
    let funded_rgb_amount = 200;
    let channel_b_funded_rgb_amount = 300;
    let client_a_push_msat = 10_000_000;

    let (client_a_node_address, _client_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    let client_node_info = node_info(client_a_node_address).await;
    let opened_virtual_channel = open_virtual_channel(
        host_node_address,
        &client_node_info.pubkey,
        Some(client_node_peer_port),
        Some(100_000),
        Some(client_a_push_msat),
        Some(funded_rgb_amount),
        Some(&issued_asset_id),
        None,
    )
    .await;
    assert_eq!(
        opened_virtual_channel.virtual_open_mode.as_deref(),
        Some("trusted_no_broadcast")
    );
    assert!(!opened_virtual_channel.public);
    assert!(opened_virtual_channel.ready);
    assert!(opened_virtual_channel.is_usable);
    assert!(matches!(
        opened_virtual_channel.status,
        ChannelStatus::Opened
    ));

    let host_node_onchain_spendable_after_open =
        asset_balance_spendable(host_node_address, &issued_asset_id).await;
    assert!(
        host_node_onchain_spendable_after_open >= channel_b_funded_rgb_amount,
        "first virtual open must leave enough spendable balance for the second virtual channel"
    );

    for _ in 0..14 {
        mine_blocks_and_wait_for_sync(
            host_node_address,
            client_a_node_address,
            VIRTUAL_TIMEOUT_BOUNDARY_CHUNK_SIZE,
        )
        .await;
    }
    mine_blocks_and_wait_for_sync(host_node_address, client_a_node_address, 1).await;

    let host_node_channels = list_channels(host_node_address).await;
    let virtual_channel_after_timeout = host_node_channels
        .iter()
        .find(|channel| channel.channel_id == opened_virtual_channel.channel_id)
        .expect("virtual channel should still exist after 2017 blocks");
    assert!(virtual_channel_after_timeout.ready);
    assert!(virtual_channel_after_timeout.is_usable);
    assert!(matches!(
        virtual_channel_after_timeout.status,
        ChannelStatus::Opened
    ));
    assert_eq!(
        virtual_channel_after_timeout.virtual_open_mode.as_deref(),
        Some("trusted_no_broadcast")
    );
    assert_eq!(
        virtual_channel_after_timeout.asset_id.as_deref(),
        Some(issued_asset_id.as_str())
    );
    assert_eq!(
        virtual_channel_after_timeout.asset_local_amount,
        Some(funded_rgb_amount)
    );

    let expected_virtual_marker_path = PathBuf::from(format!(
        "{test_storage_root}host_node/.ldk/virtual_channel_{}",
        virtual_channel_after_timeout.channel_id
    ));
    assert!(expected_virtual_marker_path.exists());

    let btc_ln_invoice = ln_invoice(client_a_node_address, Some(3_000_000), None, None, 3600)
        .await
        .invoice;
    send_payment_with_status(host_node_address, btc_ln_invoice, HTLCStatus::Succeeded).await;

    let host_to_client_a_rgb_payment_amount = 50;
    let rgb_ln_invoice_a = ln_invoice(
        client_a_node_address,
        Some(3_000_000),
        Some(&issued_asset_id),
        Some(host_to_client_a_rgb_payment_amount),
        3600,
    )
    .await
    .invoice;
    send_payment_with_status(host_node_address, rgb_ln_invoice_a, HTLCStatus::Succeeded).await;

    wait_for_ln_balance(
        host_node_address,
        &issued_asset_id,
        funded_rgb_amount - host_to_client_a_rgb_payment_amount,
    )
    .await;
    wait_for_ln_balance(
        client_a_node_address,
        &issued_asset_id,
        host_to_client_a_rgb_payment_amount,
    )
    .await;

    let client_a_to_host_rgb_payment_amount = 5;
    let client_a_to_host_invoice = ln_invoice(
        host_node_address,
        Some(3_000_000),
        Some(&issued_asset_id),
        Some(client_a_to_host_rgb_payment_amount),
        3600,
    )
    .await
    .invoice;

    send_payment_with_status(
        client_a_node_address,
        client_a_to_host_invoice,
        HTLCStatus::Succeeded,
    )
    .await;
    wait_for_ln_balance(
        host_node_address,
        &issued_asset_id,
        funded_rgb_amount - host_to_client_a_rgb_payment_amount
            + client_a_to_host_rgb_payment_amount,
    )
    .await;
    wait_for_ln_balance(
        client_a_node_address,
        &issued_asset_id,
        host_to_client_a_rgb_payment_amount - client_a_to_host_rgb_payment_amount,
    )
    .await;

    let host_node_onchain_spendable_after_payments =
        asset_balance_spendable(host_node_address, &issued_asset_id).await;
    assert_eq!(
        host_node_onchain_spendable_after_payments,
        host_node_onchain_spendable_after_open
    );

    let client_b_node_peer_port = next_peer_port();
    let (client_b_node_address, _client_b_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_b_node"),
        client_b_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    let client_b_node_info = node_info(client_b_node_address).await;
    let opened_virtual_channel_b = open_virtual_channel(
        host_node_address,
        &client_b_node_info.pubkey,
        Some(client_b_node_peer_port),
        Some(100_000),
        Some(0),
        Some(channel_b_funded_rgb_amount),
        Some(&issued_asset_id),
        None,
    )
    .await;
    assert_eq!(
        opened_virtual_channel_b.virtual_open_mode.as_deref(),
        Some("trusted_no_broadcast")
    );
    assert!(!opened_virtual_channel_b.public);
    assert!(opened_virtual_channel_b.ready);
    assert!(opened_virtual_channel_b.is_usable);
    assert!(matches!(
        opened_virtual_channel_b.status,
        ChannelStatus::Opened
    ));

    let expected_virtual_marker_path_b = PathBuf::from(format!(
        "{test_storage_root}host_node/.ldk/virtual_channel_{}",
        opened_virtual_channel_b.channel_id
    ));
    assert!(expected_virtual_marker_path_b.exists());

    let client_a_to_b_btc_payment_msat = 4_000_000;
    let btc_ln_invoice_b = ln_invoice(
        client_b_node_address,
        Some(client_a_to_b_btc_payment_msat),
        None,
        None,
        3600,
    )
    .await
    .invoice;
    let decoded_btc_invoice_b = Bolt11Invoice::from_str(&btc_ln_invoice_b).unwrap();
    assert_eq!(decoded_btc_invoice_b.route_hints().len(), 1);
    assert_eq!(decoded_btc_invoice_b.route_hints()[0].0.len(), 1);
    assert_eq!(
        decoded_btc_invoice_b.route_hints()[0].0[0]
            .src_node_id
            .to_string(),
        host_node_info.pubkey
    );

    send_payment_with_status(
        client_a_node_address,
        btc_ln_invoice_b,
        HTLCStatus::Succeeded,
    )
    .await;

    let client_a_to_b_rgb_payment_amount = 10;
    let rgb_ln_invoice_b = ln_invoice(
        client_b_node_address,
        Some(3_000_000),
        Some(&issued_asset_id),
        Some(client_a_to_b_rgb_payment_amount),
        3600,
    )
    .await
    .invoice;
    let decoded_rgb_invoice_b = Bolt11Invoice::from_str(&rgb_ln_invoice_b).unwrap();
    assert_eq!(decoded_rgb_invoice_b.route_hints().len(), 1);
    assert_eq!(decoded_rgb_invoice_b.route_hints()[0].0.len(), 1);
    assert_eq!(
        decoded_rgb_invoice_b.route_hints()[0].0[0]
            .src_node_id
            .to_string(),
        host_node_info.pubkey
    );

    send_payment_with_status(
        client_a_node_address,
        rgb_ln_invoice_b,
        HTLCStatus::Succeeded,
    )
    .await;
    wait_for_ln_balance(
        client_a_node_address,
        &issued_asset_id,
        host_to_client_a_rgb_payment_amount
            - client_a_to_host_rgb_payment_amount
            - client_a_to_b_rgb_payment_amount,
    )
    .await;
    wait_for_ln_balance(
        client_b_node_address,
        &issued_asset_id,
        client_a_to_b_rgb_payment_amount,
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_close_rejects_client_side_without_host_session() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}close_client_side/");
    let host_node_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    let (client_node_address, _client_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    fund_and_create_utxos(host_node_address, None).await;
    let client_node_info = node_info(client_node_address).await;
    let opened_virtual_channel = open_virtual_channel(
        host_node_address,
        &client_node_info.pubkey,
        Some(client_node_peer_port),
        Some(100_000),
        Some(0),
        None,
        None,
        None,
    )
    .await;

    let response = close_channel_response(
        client_node_address,
        &opened_virtual_channel.channel_id,
        &host_node_info.pubkey,
        false,
    )
    .await;
    check_response_is_nok(
        response,
        reqwest::StatusCode::FORBIDDEN,
        "host-side session",
        "CannotCloseChannel",
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_close_rejects_force_true_on_host() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}close_force/");
    let host_node_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    let (client_node_address, _client_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    fund_and_create_utxos(host_node_address, None).await;
    let client_node_info = node_info(client_node_address).await;
    let opened_virtual_channel = open_virtual_channel(
        host_node_address,
        &client_node_info.pubkey,
        Some(client_node_peer_port),
        Some(100_000),
        Some(0),
        None,
        None,
        None,
    )
    .await;

    let response = close_channel_response(
        host_node_address,
        &opened_virtual_channel.channel_id,
        &client_node_info.pubkey,
        true,
    )
    .await;
    check_response_is_nok(
        response,
        reqwest::StatusCode::FORBIDDEN,
        "force=true is not supported",
        "CannotCloseChannel",
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_close_succeeds_without_remote_value_and_is_idempotent() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}close_success/");
    let host_node_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    let (client_node_address, _client_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    fund_and_create_utxos(host_node_address, None).await;
    let issued_asset_id = issue_asset_nia(host_node_address).await.asset_id;
    let client_node_info = node_info(client_node_address).await;
    let opened_virtual_channel = open_virtual_channel(
        host_node_address,
        &client_node_info.pubkey,
        Some(client_node_peer_port),
        Some(100_000),
        Some(0),
        Some(200),
        Some(&issued_asset_id),
        None,
    )
    .await;

    close_channel(
        host_node_address,
        &opened_virtual_channel.channel_id,
        &client_node_info.pubkey,
        false,
    )
    .await;

    let response = close_channel_response(
        host_node_address,
        &opened_virtual_channel.channel_id,
        &client_node_info.pubkey,
        false,
    )
    .await;
    _check_response_is_ok(response)
        .await
        .json::<EmptyResponse>()
        .await
        .unwrap();
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_close_rejects_after_rgb_round_trip_when_remote_btc_remains() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}close_remote_rgb/");
    let host_node_peer_port = next_peer_port();
    let client_a_node_peer_port = next_peer_port();
    let client_b_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    let (client_a_node_address, _client_a_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_a_node"),
        client_a_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    let (client_b_node_address, _client_b_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_b_node"),
        client_b_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    fund_and_create_utxos(host_node_address, None).await;

    let client_a_node_info = node_info(client_a_node_address).await;
    let opened_virtual_channel = open_virtual_channel(
        host_node_address,
        &client_a_node_info.pubkey,
        Some(client_a_node_peer_port),
        Some(100_000),
        Some(0),
        None,
        None,
        None,
    )
    .await;

    let btc_ln_invoice = ln_invoice(client_a_node_address, Some(3_000_000), None, None, 3600)
        .await
        .invoice;
    send_payment_with_status(host_node_address, btc_ln_invoice, HTLCStatus::Succeeded).await;

    let response = close_channel_response(
        host_node_address,
        &opened_virtual_channel.channel_id,
        &client_a_node_info.pubkey,
        false,
    )
    .await;
    check_response_is_nok(
        response,
        reqwest::StatusCode::FORBIDDEN,
        "counterparty BTC balance floor is",
        "CannotCloseChannel",
    )
    .await;

    let issued_asset_id = issue_asset_nia(host_node_address).await.asset_id;
    let funded_rgb_amount = 200;
    let client_b_node_info = node_info(client_b_node_address).await;
    let opened_virtual_channel_b = open_virtual_channel(
        host_node_address,
        &client_b_node_info.pubkey,
        Some(client_b_node_peer_port),
        Some(100_000),
        Some(0),
        Some(funded_rgb_amount),
        Some(&issued_asset_id),
        None,
    )
    .await;

    let btc_ln_invoice = ln_invoice(client_b_node_address, Some(3_000_000), None, None, 3600)
        .await
        .invoice;
    send_payment_with_status(host_node_address, btc_ln_invoice, HTLCStatus::Succeeded).await;

    let host_to_client_b_rgb_amount = 50;
    let rgb_ln_invoice = ln_invoice(
        client_b_node_address,
        Some(3_000_000),
        Some(&issued_asset_id),
        Some(host_to_client_b_rgb_amount),
        3600,
    )
    .await
    .invoice;
    send_payment_with_status(host_node_address, rgb_ln_invoice, HTLCStatus::Succeeded).await;
    wait_for_ln_balance(
        host_node_address,
        &issued_asset_id,
        funded_rgb_amount - host_to_client_b_rgb_amount,
    )
    .await;
    wait_for_ln_balance(
        client_b_node_address,
        &issued_asset_id,
        host_to_client_b_rgb_amount,
    )
    .await;

    let response = close_channel_response(
        host_node_address,
        &opened_virtual_channel_b.channel_id,
        &client_b_node_info.pubkey,
        false,
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let api_error_response = response.json::<APIErrorResponse>().await.unwrap();
    assert_eq!(
        api_error_response.code,
        reqwest::StatusCode::FORBIDDEN.as_u16()
    );
    assert_eq!(api_error_response.name, "CannotCloseChannel");
    assert!(
        api_error_response
            .error
            .contains("counterparty BTC balance floor is")
            || api_error_response
                .error
                .contains("counterparty RGB balance is 50")
    );

    let client_b_to_host_rgb_invoice = ln_invoice(
        host_node_address,
        Some(3_000_000),
        Some(&issued_asset_id),
        Some(host_to_client_b_rgb_amount),
        3600,
    )
    .await
    .invoice;
    send_payment_with_status(
        client_b_node_address,
        client_b_to_host_rgb_invoice,
        HTLCStatus::Succeeded,
    )
    .await;
    wait_for_ln_balance(host_node_address, &issued_asset_id, funded_rgb_amount).await;
    wait_for_ln_balance(client_b_node_address, &issued_asset_id, 0).await;

    let response = close_channel_response(
        host_node_address,
        &opened_virtual_channel_b.channel_id,
        &client_b_node_info.pubkey,
        false,
    )
    .await;
    check_response_is_nok(
        response,
        reqwest::StatusCode::FORBIDDEN,
        "counterparty BTC balance floor is",
        "CannotCloseChannel",
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[serial_test::serial]
async fn virtual_close_succeeds_after_client_returns_full_btc_and_rgb() {
    initialize();

    let test_storage_root = format!("{TEST_DIR_BASE}close_success_after_return/");
    let host_node_peer_port = next_peer_port();
    let client_node_peer_port = next_peer_port();

    let (host_node_address, _host_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}host_node"),
        host_node_peer_port,
        false,
        true,
        vec![],
    )
    .await;
    let host_node_info = node_info(host_node_address).await;

    let (client_node_address, _client_node_password) = start_node_with_virtual_options(
        &format!("{test_storage_root}client_node"),
        client_node_peer_port,
        false,
        true,
        vec![bitcoin::secp256k1::PublicKey::from_str(&host_node_info.pubkey).unwrap()],
    )
    .await;

    fund_and_create_utxos(host_node_address, None).await;
    let issued_asset_id = issue_asset_nia(host_node_address).await.asset_id;
    let funded_rgb_amount = 200;
    let client_node_info = node_info(client_node_address).await;
    let opened_virtual_channel = open_virtual_channel(
        host_node_address,
        &client_node_info.pubkey,
        Some(client_node_peer_port),
        Some(100_000),
        Some(0),
        Some(funded_rgb_amount),
        Some(&issued_asset_id),
        None,
    )
    .await;

    let btc_ln_invoice = ln_invoice(client_node_address, Some(3_000_000), None, None, 3600)
        .await
        .invoice;
    send_payment_with_status(host_node_address, btc_ln_invoice, HTLCStatus::Succeeded).await;

    let host_to_client_rgb_amount = 50;
    let rgb_ln_invoice = ln_invoice(
        client_node_address,
        Some(3_000_000),
        Some(&issued_asset_id),
        Some(host_to_client_rgb_amount),
        3600,
    )
    .await
    .invoice;
    send_payment_with_status(host_node_address, rgb_ln_invoice, HTLCStatus::Succeeded).await;
    wait_for_ln_balance(
        host_node_address,
        &issued_asset_id,
        funded_rgb_amount - host_to_client_rgb_amount,
    )
    .await;
    wait_for_ln_balance(
        client_node_address,
        &issued_asset_id,
        host_to_client_rgb_amount,
    )
    .await;

    let response = close_channel_response(
        host_node_address,
        &opened_virtual_channel.channel_id,
        &client_node_info.pubkey,
        false,
    )
    .await;
    check_response_is_nok(
        response,
        reqwest::StatusCode::FORBIDDEN,
        "counterparty",
        "CannotCloseChannel",
    )
    .await;

    let client_to_host_full_invoice = ln_invoice(
        host_node_address,
        Some(6_000_000),
        Some(&issued_asset_id),
        Some(host_to_client_rgb_amount),
        3600,
    )
    .await
    .invoice;
    send_payment_with_status(
        client_node_address,
        client_to_host_full_invoice,
        HTLCStatus::Succeeded,
    )
    .await;
    wait_for_ln_balance(host_node_address, &issued_asset_id, funded_rgb_amount).await;
    wait_for_ln_balance(client_node_address, &issued_asset_id, 0).await;

    close_channel(
        host_node_address,
        &opened_virtual_channel.channel_id,
        &client_node_info.pubkey,
        false,
    )
    .await;
}
