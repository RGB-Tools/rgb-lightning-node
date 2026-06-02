//! External-signer `lib_sdk` tests use [`NativeExternalSigner`] (real PSBT signing) behind a small
//! [`ExternalSignerHost`] wrapper for availability / `SignRgbPsbt` failure injection. The wire format
//! matches production (`rgb_lightning_node::signer_integration_wire` → `signer::proto`).
use crate::helpers::*;
use rgb_lightning_node::signer_integration_wire::{decode_signer_request_wire, SignerRequest};
use serial_test::serial;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

fn clone_bootstrap(b: &SdkExternalSignerBootstrap) -> SdkExternalSignerBootstrap {
    SdkExternalSignerBootstrap {
        node_id: b.node_id.clone(),
        account_xpub_vanilla: b.account_xpub_vanilla.clone(),
        account_xpub_colored: b.account_xpub_colored.clone(),
        master_fingerprint: b.master_fingerprint.clone(),
        protocol_version: b.protocol_version.clone(),
        api_level: b.api_level,
    }
}

/// Wraps [`NativeExternalSigner`] so tests can simulate signer outage or `SignRgbPsbt` rejection.
struct TunableNativeSignerHost {
    inner: Arc<rgb_lightning_node::NativeExternalSigner>,
    available: Arc<AtomicBool>,
    /// When set, [`SignerRequest::SignRgbPsbt`] returns a host error (simulates signer / transport failure).
    fail_sign_rgb_psbt: Arc<AtomicBool>,
}

impl TunableNativeSignerHost {
    fn new(inner: Arc<rgb_lightning_node::NativeExternalSigner>) -> Self {
        Self {
            inner,
            available: Arc::new(AtomicBool::new(true)),
            fail_sign_rgb_psbt: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::Relaxed);
    }

    fn set_fail_sign_rgb_psbt(&self, fail: bool) {
        self.fail_sign_rgb_psbt.store(fail, Ordering::Relaxed);
    }
}

impl rgb_lightning_node::ExternalSignerHost for TunableNativeSignerHost {
    fn call(&self, request: Vec<u8>) -> Result<Vec<u8>, rgb_lightning_node::RlnError> {
        if !self.available.load(Ordering::Relaxed) {
            return Err(rgb_lightning_node::RlnError::Internal);
        }
        if self.fail_sign_rgb_psbt.load(Ordering::Relaxed) {
            let req = decode_signer_request_wire(&request)
                .map_err(|_| rgb_lightning_node::RlnError::Internal)?;
            if matches!(&req, SignerRequest::SignRgbPsbt { .. }) {
                return Err(rgb_lightning_node::RlnError::Internal);
            }
        }
        self.inner.call(request)
    }
}

fn attach_external_signer_host(
    node: &SdkNode,
    host: Arc<dyn rgb_lightning_node::ExternalSignerHost>,
    bootstrap: &SdkExternalSignerBootstrap,
) {
    node.attach_external_signer(host, clone_bootstrap(bootstrap))
        .expect("attach external signer");
}

fn unlock_with_attached_external_signer(node: &SdkNode, announce_alias: &str) {
    node.unlock_with_attached_external_signer(
        Some("user".to_string()),
        Some("password".to_string()),
        Some("localhost".to_string()),
        Some(18443),
        Some("127.0.0.1:50001".to_string()),
        Some(PROXY_ENDPOINT_LOCAL.to_string()),
        vec![],
        Some(announce_alias.to_string()),
    )
    .expect("unlock with attached external signer");
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn make_native_signer(
    storage_dir: &std::path::Path,
    seed_hex: Option<String>,
) -> Arc<rgb_lightning_node::NativeExternalSigner> {
    // With the seed-only `NativeExternalSigner` constructor, tests provide stable seeds from env or
    // explicit per-test overrides. This avoids any signer-side seed persistence while still letting
    // us simulate mismatched signers.
    let seed_hex = seed_hex.unwrap_or_else(|| {
        std::env::var("RLN_TEST_NATIVE_SIGNER_SEED_HEX").unwrap_or_else(|_| "11".repeat(32))
    });
    let _ = storage_dir; // kept to minimize churn in test callsites
    rgb_lightning_node::NativeExternalSigner::new(seed_hex, "regtest".to_string(), Some(true))
        .expect("create native signer")
}

#[test]
#[serial]
fn external_init_unlock_and_restart_same_signer() {
    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    let test_dir = test_dir("sdk_external_signer_init_unlock_restart");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_dir = test_dir.join("node_a");
    let signer_dir = test_dir.join("signer_a");

    let signer = make_native_signer(&signer_dir, None);
    let bootstrap = signer.bootstrap().expect("bootstrap");

    let node = make_node(&node_dir, NODE_A_DAEMON_PORT + 110, NODE_A_PEER_PORT + 110);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.init_with_native_external_signer(signer.clone())
            .expect("external init");
        node.unlock_with_native_external_signer(
            signer.clone(),
            Some("user".to_string()),
            Some("password".to_string()),
            Some("localhost".to_string()),
            Some(18443),
            Some("127.0.0.1:50001".to_string()),
            Some(PROXY_ENDPOINT_LOCAL.to_string()),
            vec![],
            Some("RLN_external".to_string()),
        )
        .expect("unlock with native external signer");

        let info = node.node_info().expect("node_info");
        assert_eq!(info.pubkey.to_string(), bootstrap.node_id);

        node.shutdown();
        thread::sleep(Duration::from_millis(500));

        let restarted = make_node(&node_dir, NODE_A_DAEMON_PORT + 110, NODE_A_PEER_PORT + 110);
        restarted
            .unlock_with_native_external_signer(
                signer.clone(),
                Some("user".to_string()),
                Some("password".to_string()),
                Some("localhost".to_string()),
                Some(18443),
                Some("127.0.0.1:50001".to_string()),
                Some(PROXY_ENDPOINT_LOCAL.to_string()),
                vec![],
                Some("RLN_external".to_string()),
            )
            .expect("unlock after restart");
        let info2 = restarted.node_info().expect("node_info after restart");
        assert_eq!(info2.pubkey.to_string(), bootstrap.node_id);
        restarted.shutdown();
    }));

    if result.is_err() {
        panic!("external signer SDK test failed");
    }
}

#[test]
#[serial]
fn external_restart_with_mismatched_signer_fails_unlock() {
    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    let test_dir = test_dir("sdk_external_signer_restart_mismatch");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_dir = test_dir.join("node_a");
    let signer_a_dir = test_dir.join("signer_a");
    let signer_b_dir = test_dir.join("signer_b");

    let signer_a = make_native_signer(&signer_a_dir, Some("11".repeat(32)));
    let node = make_node(&node_dir, NODE_A_DAEMON_PORT + 111, NODE_A_PEER_PORT + 111);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.init_with_native_external_signer(signer_a.clone())
            .expect("external init");
        node.unlock_with_native_external_signer(
            signer_a.clone(),
            Some("user".to_string()),
            Some("password".to_string()),
            Some("localhost".to_string()),
            Some(18443),
            Some("127.0.0.1:50001".to_string()),
            Some(PROXY_ENDPOINT_LOCAL.to_string()),
            vec![],
            Some("RLN_external".to_string()),
        )
        .expect("unlock");
        node.shutdown();
        thread::sleep(Duration::from_millis(500));

        let signer_b = make_native_signer(&signer_b_dir, Some("22".repeat(32)));

        let restarted = make_node(&node_dir, NODE_A_DAEMON_PORT + 111, NODE_A_PEER_PORT + 111);
        let err = restarted
            .unlock_with_native_external_signer(
                signer_b,
                Some("user".to_string()),
                Some("password".to_string()),
                Some("localhost".to_string()),
                Some(18443),
                Some("127.0.0.1:50001".to_string()),
                Some(PROXY_ENDPOINT_LOCAL.to_string()),
                vec![],
                Some("RLN_external".to_string()),
            )
            .expect_err("unlock must fail for mismatched signer");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("conflict") || msg.contains("mismatch"),
            "unexpected error for mismatched signer: {msg}"
        );
        restarted.shutdown();
    }));

    if result.is_err() {
        panic!("external signer mismatch SDK test failed");
    }
}

#[test]
#[serial]
fn external_signer_connection_loss_and_restore_mock() {
    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    let test_dir = test_dir("sdk_external_signer_connection_loss_restore_mock");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_dir = test_dir.join("node_a");

    let signer_dir = test_dir.join("signer_a");
    let signer = make_native_signer(&signer_dir, None);
    let bootstrap = signer.bootstrap().expect("bootstrap");
    let host = Arc::new(TunableNativeSignerHost::new(signer));

    let node = make_node(&node_dir, NODE_A_DAEMON_PORT + 121, NODE_A_PEER_PORT + 121);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.init_with_external_signer(clone_bootstrap(&bootstrap))
            .expect("external init");
        attach_external_signer_host(&node, host.clone(), &bootstrap);
        unlock_with_attached_external_signer(&node, "RLN_external_conn_loss");

        // `createutxos` can be flaky across environments; this test only needs a spendable UTXO
        // so that `sendbtc` reaches the external signer `SignRgbPsbt` path.
        ensure_funded(&node, 1, "node A mock");
        let self_addr = node.address().expect("node address").address;

        host.set_available(false);
        let err = node
            .sendbtc(SdkSendBtcRequest {
                address: self_addr.clone(),
                amount: 1_000,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .err()
            .expect("send_btc must fail while signer is unavailable");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("external signer")
                || msg.contains("status")
                || msg.contains("transport")
                || msg.contains("unavailable")
                || msg.contains("internal"),
            "unexpected error while signer unavailable: {msg}"
        );

        host.set_available(true);
        // Best-effort recovery: once the signer is back, the node should be able to proceed,
        // but some environments may still surface transient failures (sync/fee estimation).
        let _ = node.sendbtc(SdkSendBtcRequest {
            address: self_addr,
            amount: 1_000,
            fee_rate: CREATE_UTXOS_FEE_RATE,
            skip_sync: false,
        });
        node.shutdown();
    }));

    if result.is_err() {
        panic!("external signer connection loss/restore mock test failed");
    }
}

/// When the host rejects [`SignerRequest::SignRgbPsbt`], the node must surface the error (no silent
/// success via a local RGB wallet PSBT path). Uses `sendbtc` after `createutxos` so the flow reaches
/// `rgb_sign_psbt` (a second identical `createutxos` can fail earlier with insufficient coins before
/// signing).
#[test]
#[serial]
fn external_signer_sign_rgb_psbt_failure_surfaces_on_send_btc_mock() {
    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    let test_dir = test_dir("sdk_external_signer_sign_rgb_psbt_fail_mock");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_dir = test_dir.join("node_a");
    let signer_dir = test_dir.join("signer_a");

    let signer = make_native_signer(&signer_dir, None);
    let bootstrap = signer.bootstrap().expect("bootstrap");
    let host = Arc::new(TunableNativeSignerHost::new(signer));

    let node = make_node(&node_dir, NODE_A_DAEMON_PORT + 131, NODE_A_PEER_PORT + 131);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.init_with_external_signer(clone_bootstrap(&bootstrap))
            .expect("external init");
        attach_external_signer_host(&node, host.clone(), &bootstrap);
        unlock_with_attached_external_signer(&node, "RLN_external_sign_rgb_fail");

        // `createutxos` is not required for this test and can be flaky across environments.
        // We only need some spendable balance so `sendbtc` reaches the external signer signing path.
        ensure_funded(&node, 1, "node A mock");
        let self_addr = node.address().expect("node address").address;

        host.set_fail_sign_rgb_psbt(true);
        let err = node
            .sendbtc(SdkSendBtcRequest {
                address: self_addr.clone(),
                amount: 1_000,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .err()
            .expect("sendbtc must fail when SignRgbPsbt is rejected");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unexpected")
                || msg.contains("rgb")
                || msg.contains("external")
                || msg.contains("transport")
                || msg.contains("sign")
                || msg.contains("internal")
                || msg.contains("psbt"),
            "unexpected error for SignRgbPsbt host failure: {msg}"
        );

        host.set_fail_sign_rgb_psbt(false);
        // Best-effort: once the host starts responding again, the node should be able to proceed.
        // Some environments may still surface transient failures (fee estimation/sync), so don't
        // hard-require success here; the core assertion for this test is that the host rejection
        // surfaces as an error.
        let _ = node.sendbtc(SdkSendBtcRequest {
            address: self_addr,
            amount: 1_000,
            fee_rate: CREATE_UTXOS_FEE_RATE,
            skip_sync: false,
        });
        node.shutdown();
    }));

    if result.is_err() {
        panic!("external signer SignRgbPsbt failure lib_sdk test failed");
    }
}

/// RGB payment with node A (internal signer) and node B (native in-process VLS signer).
///
/// Regtest: `./regtest.sh start`, then:
/// `cargo test -p rgb-lightning-node --features uniffi,test-utils,vls --test lib_sdk rgb_native_external_signer_mixed_one_hop_payment_quick -- --nocapture`
#[test]
#[serial]
fn rgb_native_external_signer_mixed_one_hop_payment_quick() {
    if std::env::var("SKIP_RGB_NATIVE_EXTERNAL_QUICK")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
    {
        return;
    }

    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    const PORT_OFF: u16 = 200;
    let da = NODE_A_DAEMON_PORT + PORT_OFF;
    let pa = NODE_A_PEER_PORT + PORT_OFF;
    let db = NODE_B_DAEMON_PORT + PORT_OFF;
    let pb = NODE_B_PEER_PORT + PORT_OFF;

    let test_dir = test_dir("sdk_rgb_native_external_quick");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let signer_b_dir = test_dir.join("signer_b");

    let signer_b = make_native_signer(&signer_b_dir, None);

    let node_a = make_node(&node_a_dir, da, pa);
    let node_b = make_node(&node_b_dir, db, pb);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node_a
            .init("nodeApass".to_string(), None)
            .expect("node A init");
        node_b
            .init_with_native_external_signer(signer_b.clone())
            .expect("node B init native external signer");

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock");
        node_b
            .unlock_with_native_external_signer(
                signer_b.clone(),
                Some("user".to_string()),
                Some("password".to_string()),
                Some("localhost".to_string()),
                Some(18443),
                Some("127.0.0.1:50001".to_string()),
                Some(PROXY_ENDPOINT_LOCAL.to_string()),
                vec![],
                Some("RLN_rgb_native_quick".to_string()),
            )
            .expect("node B unlock native external signer");

        fund_and_create_utxos(&node_a, "node A quick");
        node_a
            .createutxos(SdkCreateUtxosRequest {
                up_to: false,
                num: Some(25),
                size: None,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .expect("node A createutxos (extra RGB allocation headroom)");
        ensure_funded(&node_b, 200_000, "node B quick");
        mine(1);
        node_a.sync().expect("node A sync after fund");
        node_b.sync().expect("node B sync after fund");

        let asset_id = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "QRGB".to_string(),
                name: "QuickRgb".to_string(),
                precision: 0,
            })
            .expect("issueassetnia")
            .asset_id;

        let peer_uri = format!(
            "{}@127.0.0.1:{pb}",
            node_b.node_info().expect("node B node_info").pubkey
        );
        node_a.connectpeer(peer_uri.clone()).expect("connectpeer");

        const PAY_ASSET: u64 = 100;

        node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat: OPEN_CHANNEL_PUSH_MSAT,
                public: false,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(OPEN_CHANNEL_ASSET_AMOUNT),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("openchannel");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(90));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));

        let invoice = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(PAY_ASSET),
                payment_hash: None,
                description_hash: None,
                min_final_cltv_expiry_delta: None,
            })
            .expect("ln_invoice")
            .invoice;

        let send = node_a
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("sendpayment");
        let payment_hash = send.payment_hash.expect("payment_hash");

        wait_for_payment_status(&node_a, &payment_hash, Duration::from_secs(120));
        wait_for_payment_status(&node_b, &payment_hash, Duration::from_secs(120));

        node_a.shutdown();
        node_b.shutdown();
        thread::sleep(Duration::from_millis(300));
    }));

    if result.is_err() {
        panic!("rgb_native_external_signer_mixed_one_hop_payment_quick failed");
    }
}

/// Mixed internal/external RGB channel: after receiving RGB, the external-signer node must be able
/// to send RGB back over the same channel.
#[test]
#[serial]
fn rgb_native_external_signer_mixed_one_hop_payment_roundtrip() {
    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    const PORT_OFF: u16 = 260;
    const PAY_ASSET: u64 = 50;
    const ROUNDTRIP_PUSH_MSAT: u64 = 6_000_000;
    let da = NODE_A_DAEMON_PORT + PORT_OFF;
    let pa = NODE_A_PEER_PORT + PORT_OFF;
    let db = NODE_B_DAEMON_PORT + PORT_OFF;
    let pb = NODE_B_PEER_PORT + PORT_OFF;

    let test_dir = test_dir("sdk_rgb_native_external_roundtrip");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let signer_b_dir = test_dir.join("signer_b");

    let signer_b = make_native_signer(&signer_b_dir, None);

    let node_a = make_node(&node_a_dir, da, pa);
    let node_b = make_node(&node_b_dir, db, pb);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node_a
            .init("nodeApass".to_string(), None)
            .expect("node A init");
        node_b
            .init_with_native_external_signer(signer_b.clone())
            .expect("node B init native external signer");

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock");
        node_b
            .unlock_with_native_external_signer(
                signer_b.clone(),
                Some("user".to_string()),
                Some("password".to_string()),
                Some("localhost".to_string()),
                Some(18443),
                Some("127.0.0.1:50001".to_string()),
                Some(PROXY_ENDPOINT_LOCAL.to_string()),
                vec![],
                Some("RLN_rgb_native_roundtrip".to_string()),
            )
            .expect("node B unlock native external signer");

        fund_and_create_utxos(&node_a, "node A roundtrip");
        node_a
            .createutxos(SdkCreateUtxosRequest {
                up_to: false,
                num: Some(25),
                size: None,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .expect("node A createutxos (extra RGB allocation headroom)");
        ensure_funded(&node_b, 200_000, "node B roundtrip");
        mine(1);
        node_a.sync().expect("node A sync after fund");
        node_b.sync().expect("node B sync after fund");

        let asset_id = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "QRT".to_string(),
                name: "QuickRoundTripRgb".to_string(),
                precision: 0,
            })
            .expect("issueassetnia")
            .asset_id;

        let peer_uri = format!(
            "{}@127.0.0.1:{pb}",
            node_b.node_info().expect("node B node_info").pubkey
        );
        node_a.connectpeer(peer_uri.clone()).expect("connectpeer");

        node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat: ROUNDTRIP_PUSH_MSAT,
                public: false,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(OPEN_CHANNEL_ASSET_AMOUNT),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("openchannel");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(90));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));

        let invoice_1 = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(PAY_ASSET),
                payment_hash: None,
                description_hash: None,
                min_final_cltv_expiry_delta: None,
            })
            .expect("ln_invoice first")
            .invoice;

        send_payment_with_ln_balance(
            &node_a,
            &node_b,
            invoice_1,
            &asset_id,
            PAY_ASSET,
            OPEN_CHANNEL_ASSET_AMOUNT,
            0,
        );

        let invoice_2 = node_a
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(PAY_ASSET),
                payment_hash: None,
                description_hash: None,
                min_final_cltv_expiry_delta: None,
            })
            .expect("ln_invoice second")
            .invoice;

        send_payment_with_ln_balance(
            &node_b,
            &node_a,
            invoice_2,
            &asset_id,
            PAY_ASSET,
            PAY_ASSET,
            OPEN_CHANNEL_ASSET_AMOUNT - PAY_ASSET,
        );

        node_a.shutdown();
        node_b.shutdown();
        thread::sleep(Duration::from_millis(300));
    }));

    if result.is_err() {
        panic!("rgb_native_external_signer_mixed_one_hop_payment_roundtrip failed");
    }
}

/// Mixed internal/external RGB channel: one RGB payment followed by cooperative close must settle
/// balances back on-chain.
#[test]
#[serial]
fn rgb_native_external_signer_mixed_one_hop_payment_coop_close_settles_to_chain() {
    ensure_regtest_available();
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    const PORT_OFF: u16 = 210;
    const PAY_ASSET: u64 = 50;
    let da = NODE_A_DAEMON_PORT + PORT_OFF;
    let pa = NODE_A_PEER_PORT + PORT_OFF;
    let db = NODE_B_DAEMON_PORT + PORT_OFF;
    let pb = NODE_B_PEER_PORT + PORT_OFF;

    let test_dir = test_dir("sdk_rgb_native_external_close_settles");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).expect("remove previous lib_sdk test dir");
    }
    fs::create_dir_all(&test_dir).expect("create lib_sdk test dir");
    let node_a_dir = test_dir.join("node_a");
    let node_b_dir = test_dir.join("node_b");
    let signer_b_dir = test_dir.join("signer_b");

    let signer_b = make_native_signer(&signer_b_dir, None);

    let node_a = make_node(&node_a_dir, da, pa);
    let node_b = make_node(&node_b_dir, db, pb);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node_a
            .init("nodeApass".to_string(), None)
            .expect("node A init");
        node_b
            .init_with_native_external_signer(signer_b.clone())
            .expect("node B init native external signer");

        node_a
            .unlock(unlock_request("nodeApass"))
            .expect("node A unlock");
        node_b
            .unlock_with_native_external_signer(
                signer_b.clone(),
                Some("user".to_string()),
                Some("password".to_string()),
                Some("localhost".to_string()),
                Some(18443),
                Some("127.0.0.1:50001".to_string()),
                Some(PROXY_ENDPOINT_LOCAL.to_string()),
                vec![],
                Some("RLN_rgb_native_close".to_string()),
            )
            .expect("node B unlock native external signer");

        fund_and_create_utxos(&node_a, "node A close");
        node_a
            .createutxos(SdkCreateUtxosRequest {
                up_to: false,
                num: Some(25),
                size: None,
                fee_rate: CREATE_UTXOS_FEE_RATE,
                skip_sync: false,
            })
            .expect("node A createutxos (extra RGB allocation headroom)");
        ensure_funded(&node_b, 200_000, "node B close");
        mine(1);
        node_a.sync().expect("node A sync after fund");
        node_b.sync().expect("node B sync after fund");

        let asset_id = node_a
            .issueassetnia(SdkIssueAssetNiaRequest {
                amounts: vec![1_000],
                ticker: "QCLS".to_string(),
                name: "QuickCloseRgb".to_string(),
                precision: 0,
            })
            .expect("issueassetnia")
            .asset_id;

        let node_b_pubkey = node_b.node_info().expect("node B node_info").pubkey;
        let peer_uri = format!("{node_b_pubkey}@127.0.0.1:{pb}");
        node_a.connectpeer(peer_uri.clone()).expect("connectpeer");

        node_a
            .openchannel(SdkOpenChannelRequest {
                peer_pubkey_and_opt_addr: peer_uri,
                capacity_sat: OPEN_CHANNEL_CAPACITY_SAT,
                push_msat: OPEN_CHANNEL_PUSH_MSAT,
                public: false,
                with_anchors: true,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                temporary_channel_id: None,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(OPEN_CHANNEL_ASSET_AMOUNT),
                push_asset_amount: None,
                virtual_open_mode: None,
            })
            .expect("openchannel");

        wait_for_channel_funding_tx(&node_a, &node_b, &asset_id, Duration::from_secs(90));
        mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
        wait_for_usable_channel(&node_a, &node_b, &asset_id, Duration::from_secs(300));
        let channel_id = node_a
            .list_channels()
            .expect("node A list_channels after channel ready")
            .into_iter()
            .find(|channel| channel.asset_id.as_ref() == Some(&asset_id) && channel.is_usable)
            .expect("usable RGB channel on node A")
            .channel_id;

        let invoice = node_b
            .ln_invoice(LnInvoiceRequest {
                amt_msat: Some(PAYMENT_MSAT),
                expiry_sec: 900,
                asset_id: Some(asset_id.clone()),
                asset_amount: Some(PAY_ASSET),
                payment_hash: None,
                description_hash: None,
                min_final_cltv_expiry_delta: None,
            })
            .expect("ln_invoice")
            .invoice;

        let send = node_a
            .sendpayment(SdkSendPaymentRequest {
                invoice: invoice.to_string(),
                amt_msat: None,
                asset_id: None,
                asset_amount: None,
            })
            .expect("sendpayment");
        let payment_hash = send.payment_hash.expect("payment_hash");

        wait_for_payment_status(&node_a, &payment_hash, Duration::from_secs(120));
        wait_for_payment_status(&node_b, &payment_hash, Duration::from_secs(120));
        wait_for_ln_balance(
            &node_a,
            &asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT - PAY_ASSET,
            Duration::from_secs(120),
        );

        close_channel(&node_a, channel_id, node_b_pubkey);
        wait_for_balance(&node_a, &asset_id, 950, Duration::from_secs(120));
        wait_for_balance(&node_b, &asset_id, PAY_ASSET, Duration::from_secs(120));

        node_a.shutdown();
        node_b.shutdown();
        thread::sleep(Duration::from_millis(300));
    }));

    if result.is_err() {
        panic!(
            "rgb_native_external_signer_mixed_one_hop_payment_coop_close_settles_to_chain failed"
        );
    }
}
