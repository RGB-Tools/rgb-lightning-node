use electrum_client::ElectrumApi;
use once_cell::sync::Lazy;
pub(crate) use rgb_lightning_node::{
    AssetBalanceInfo, AssetRecipients, AssignmentKind, Channel, ContractId, HtlcStatus,
    InvoiceStatus, LnInvoiceRequest, Payment, PaymentHash, RecipientId, RgbRecipient,
    SdkCloseChannelRequest, SdkCreateUtxosRequest, SdkInitRequest, SdkIssueAssetCfaRequest,
    SdkIssueAssetNiaRequest, SdkKeysendRequest, SdkNode, SdkOpenChannelRequest,
    SdkRefreshTransfersRequest, SdkRgbInvoiceRequest, SdkSendBtcRequest, SdkSendPaymentRequest,
    SdkUnlockRequest, SendRgbRequest, TransactionType, TransportEndpoint, WitnessData,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::RwLock;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub(crate) const NODE_A_DAEMON_PORT: u16 = 3211;
pub(crate) const NODE_B_DAEMON_PORT: u16 = 3212;
pub(crate) const NODE_C_DAEMON_PORT: u16 = 3213;
pub(crate) const NODE_A_PEER_PORT: u16 = 9911;
pub(crate) const NODE_B_PEER_PORT: u16 = 9912;
pub(crate) const NODE_C_PEER_PORT: u16 = 9913;

pub(crate) const OPEN_CHANNEL_CAPACITY_SAT: u64 = 100_000;
pub(crate) const OPEN_CHANNEL_CONFIRM_BLOCKS: u32 = 6;
pub(crate) const OPEN_CHANNEL_ASSET_AMOUNT: u64 = 600;
pub(crate) const OPEN_CHANNEL_PUSH_MSAT: u64 = 3_500_000;
pub(crate) const HTLC_MIN_MSAT: u64 = 3_000_000;
pub(crate) const PAYMENT_MSAT: u64 = HTLC_MIN_MSAT;
pub(crate) const LIQUIDITY_KEYSEND_MSAT: u64 = 10_000_000;
pub(crate) const CREATE_UTXOS_NUM: u8 = 10;
pub(crate) const CREATE_UTXOS_FEE_RATE: u64 = 7;
pub(crate) const PROXY_ENDPOINT_LOCAL: &str = "rpc://127.0.0.1:3000/json-rpc";
const ELECTRUM_URL: &str = "127.0.0.1:50001";

static MINER: Lazy<RwLock<Miner>> = Lazy::new(|| RwLock::new(Miner { no_mine_count: 0 }));

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

pub(crate) fn test_dir(name: &str) -> PathBuf {
    repo_root().join(format!("tmp/lib_sdk/{name}"))
}

pub(crate) fn ensure_regtest_available() {
    let output = Command::new("docker")
        .args(["compose", "ps", "--services", "--status", "running"])
        .current_dir(repo_root())
        .output()
        .expect("failed to run `docker compose ps`; ensure Docker is available");
    assert!(
        output.status.success(),
        "`docker compose ps` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let services = String::from_utf8_lossy(&output.stdout);
    for service in ["bitcoind", "electrs", "proxy"] {
        assert!(
            services.lines().any(|line| line.trim() == service),
            "regtest service `{service}` is not running; start it with `./regtest.sh start`"
        );
    }
}

fn run_regtest(args: &[&str]) -> String {
    let output = Command::new("./regtest.sh")
        .args(args)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|err| panic!("failed to run `./regtest.sh {}`: {err}", args.join(" ")));

    assert!(
        output.status.success(),
        "`./regtest.sh {}` failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn get_txout(txid: &str) -> String {
    let output = Command::new("docker")
        .args([
            "compose",
            "exec",
            "-u",
            "blits",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcwallet=miner",
            "gettxout",
            txid,
            "0",
        ])
        .current_dir(repo_root())
        .output()
        .expect("failed to run gettxout");

    assert!(
        output.status.success(),
        "`docker compose exec ... gettxout` failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).to_string()
}

pub(crate) fn mine(blocks: u32) {
    mine_blocks(false, blocks);
}

fn mine_blocks(resume: bool, blocks: u32) {
    let start = Instant::now();
    if resume {
        resume_mining();
    }
    let mut mined = false;
    while !mined {
        let miner = MINER.read().expect("MINER lock");
        mined = miner.mine(blocks);
        drop(miner);

        if start.elapsed() > Duration::from_secs(120) {
            resume_mining();
        }
        if !mined {
            sleep(Duration::from_millis(500));
        }
    }
    wait_electrs_sync();
}

fn stop_mining() {
    MINER.write().expect("MINER lock").stop_mining();
}

fn resume_mining() {
    MINER.write().expect("MINER lock").resume_mining();
}

fn get_block_count() -> u32 {
    let output = Command::new("docker")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .arg("compose")
        .args([
            "exec",
            "-T",
            "-u",
            "blits",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
        ])
        .arg("getblockcount")
        .current_dir(repo_root())
        .output()
        .expect("failed to call getblockcount");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .expect("could not parse blockcount")
}

fn wait_electrs_sync() {
    let start = Instant::now();
    let blockcount = get_block_count();
    loop {
        sleep(Duration::from_millis(100));
        let electrum =
            electrum_client::Client::new(ELECTRUM_URL).expect("cannot get electrum client");
        if electrum.block_header(blockcount as usize).is_ok() {
            return;
        }
        assert!(
            start.elapsed() <= Duration::from_secs(10),
            "electrs not syncing with bitcoind"
        );
    }
}

#[derive(Clone, Debug)]
struct Miner {
    no_mine_count: u32,
}

impl Miner {
    fn mine(&self, blocks: u32) -> bool {
        if self.no_mine_count > 0 {
            return false;
        }
        let blocks = blocks.to_string();
        run_regtest(&["mine", &blocks]);
        true
    }

    fn stop_mining(&mut self) {
        self.no_mine_count += 1;
    }

    fn resume_mining(&mut self) {
        if self.no_mine_count > 0 {
            self.no_mine_count -= 1;
        }
    }
}

pub(crate) fn sendtoaddress(address: &str, amount_btc: &str) {
    run_regtest(&["sendtoaddress", address, amount_btc]);
}

pub(crate) fn make_node(
    storage_dir_path: &Path,
    daemon_listening_port: u16,
    ldk_peer_listening_port: u16,
) -> SdkNode {
    fs::create_dir_all(storage_dir_path).expect("create storage dir");
    SdkNode::create(SdkInitRequest {
        storage_dir_path: storage_dir_path.display().to_string(),
        daemon_listening_port,
        ldk_peer_listening_port,
        network: "regtest".to_string(),
        max_media_upload_size_mb: 20,
        enable_virtual_channels_v0: Some(false),
        virtual_peer_pubkeys: None,
        lsp_base_url: None,
        lsp_bearer_token: None,
        vss_url: None,
        vss_allow_http: false,
        vss_allow_empty_restore: false,
    })
    .expect("create SDK node")
}

pub(crate) fn unlock_request(password: &str) -> SdkUnlockRequest {
    SdkUnlockRequest {
        password: password.to_string(),
        bitcoind_rpc_username: "user".to_string(),
        bitcoind_rpc_password: "password".to_string(),
        bitcoind_rpc_host: "localhost".to_string(),
        bitcoind_rpc_port: 18443,
        indexer_url: Some("127.0.0.1:50001".to_string()),
        proxy_endpoint: Some(PROXY_ENDPOINT_LOCAL.to_string()),
        announce_addresses: vec![],
        announce_alias: Some("RLN_alias".to_string()),
    }
}

pub(crate) fn ensure_funded(node: &SdkNode, min_spendable_sat: u64, node_name: &str) {
    let spendable = node
        .btc_balance(false)
        .unwrap_or_else(|_| panic!("{node_name}: btc_balance before funding"))
        .vanilla
        .spendable;
    if spendable >= min_spendable_sat {
        return;
    }

    let address = node
        .address()
        .unwrap_or_else(|_| panic!("{node_name}: address"))
        .address;
    sendtoaddress(&address, "1");
    mine(1);
    node.sync()
        .unwrap_or_else(|_| panic!("{node_name}: sync after funding"));

    let spendable_after = node
        .btc_balance(false)
        .unwrap_or_else(|_| panic!("{node_name}: btc_balance after funding"))
        .vanilla
        .spendable;
    assert!(
        spendable_after >= min_spendable_sat,
        "{node_name}: spendable balance too low after funding: {spendable_after} < {min_spendable_sat}"
    );
}

pub(crate) fn fund_and_create_utxos(node: &SdkNode, node_name: &str) {
    ensure_funded(node, 1, node_name);
    node.createutxos(SdkCreateUtxosRequest {
        up_to: false,
        num: Some(CREATE_UTXOS_NUM),
        size: None,
        fee_rate: CREATE_UTXOS_FEE_RATE,
        skip_sync: false,
    })
    .unwrap_or_else(|_| panic!("{node_name}: createutxos"));
    mine(1);
    node.sync()
        .unwrap_or_else(|_| panic!("{node_name}: sync after createutxos"));
}

pub(crate) fn asset_balance_spendable(node: &SdkNode, asset_id: &ContractId) -> u64 {
    node.asset_balance(asset_id.clone())
        .expect("asset_balance spendable")
        .spendable
}

pub(crate) fn asset_balance_offchain_outbound(node: &SdkNode, asset_id: &ContractId) -> u64 {
    node.asset_balance(asset_id.clone())
        .expect("asset_balance offchain_outbound")
        .offchain_outbound
}

pub(crate) fn wait_for_asset_balance(
    node: &SdkNode,
    asset_id: &ContractId,
    timeout: Duration,
) -> AssetBalanceInfo {
    let deadline = Instant::now() + timeout;
    loop {
        node.sync()
            .expect("node sync while waiting for asset_balance");
        if let Ok(balance) = node.asset_balance(asset_id.clone()) {
            return balance;
        }
        assert!(
            Instant::now() < deadline,
            "asset_balance did not become available in time"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_channel_funding_tx(
    node_a: &SdkNode,
    node_b: &SdkNode,
    asset_id: &ContractId,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        node_a
            .sync()
            .expect("node A sync while waiting for funding tx");
        node_b
            .sync()
            .expect("node B sync while waiting for funding tx");

        let funding_seen = node_a
            .list_channels()
            .expect("node A list_channels while waiting for funding tx")
            .into_iter()
            .any(|channel| {
                channel.asset_id.as_ref() == Some(asset_id) && channel.funding_txid.is_some()
            });

        if funding_seen {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "timeout waiting for channel funding tx broadcast"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_channel_open<F>(
    node: &SdkNode,
    matcher: F,
    timeout: Duration,
) -> lightning::ln::types::ChannelId
where
    F: Fn(&Channel) -> bool,
{
    let deadline = Instant::now() + timeout;
    let channel_id = loop {
        node.sync()
            .expect("node sync while waiting for channel open");
        let channels = node
            .list_channels()
            .expect("list_channels while waiting for channel open");

        if let Some(channel) = channels
            .iter()
            .find(|channel| matcher(channel) && !channel.ready)
        {
            if let Some(txid) = &channel.funding_txid {
                if !get_txout(&txid.to_string()).trim().is_empty() {
                    mine(OPEN_CHANNEL_CONFIRM_BLOCKS);
                    break channel.channel_id;
                }
            }
        }

        assert!(Instant::now() < deadline, "cannot find funding TX");
        sleep(Duration::from_secs(1));
    };

    wait_for_channel_ready(node, channel_id, timeout);
    channel_id
}

pub(crate) fn wait_for_usable_channel(
    node_a: &SdkNode,
    node_b: &SdkNode,
    asset_id: &ContractId,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let mut polls = 0u32;

    loop {
        polls += 1;
        node_a
            .sync()
            .expect("node A sync while waiting for usable channel");
        node_b
            .sync()
            .expect("node B sync while waiting for usable channel");

        let ready = node_a
            .list_channels()
            .expect("node A list_channels while waiting for usable channel")
            .into_iter()
            .any(|channel| channel.asset_id.as_ref() == Some(asset_id) && channel.is_usable);

        if ready {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "timeout waiting for usable channel"
        );
        if polls % 5 == 0 {
            mine(1);
        }
        sleep(Duration::from_secs(2));
    }
}

pub(crate) fn wait_for_channel_asset_state(
    label: &str,
    node: &SdkNode,
    channel_id: lightning::ln::types::ChannelId,
    expected_asset_local: Option<u64>,
    expected_asset_remote: Option<u64>,
    min_outbound_msat: Option<u64>,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        node.sync()
            .unwrap_or_else(|_| panic!("{label}: node sync while waiting for channel state"));
        let channel = node
            .list_channels()
            .unwrap_or_else(|_| panic!("{label}: list_channels while waiting for channel state"))
            .into_iter()
            .find(|channel| channel.channel_id == channel_id)
            .unwrap_or_else(|| panic!("{label}: expected channel {channel_id}"));
        if channel.ready
            && channel.is_usable
            && channel.asset_local_amount == expected_asset_local
            && channel.asset_remote_amount == expected_asset_remote
            && min_outbound_msat
                .map(|min_outbound_msat| channel.outbound_balance_msat >= min_outbound_msat)
                .unwrap_or(true)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label} did not reach expected channel state"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_channel_ready(
    node: &SdkNode,
    channel_id: lightning::ln::types::ChannelId,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        node.sync()
            .expect("node sync while waiting for re-established channel");
        let channels = node
            .list_channels()
            .expect("list_channels while waiting for re-established channel");
        if let Some(channel) = channels.iter().find(|c| c.channel_id == channel_id) {
            if channel.ready {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "cannot find re-established channel"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_usable_channels(
    node: &SdkNode,
    expected_num_usable_channels: usize,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let usable = node
            .node_info()
            .expect("node_info while waiting for usable channels")
            .num_usable_channels as usize;
        if usable == expected_num_usable_channels {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "usable channel count ({usable}) did not become {expected_num_usable_channels}"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_usable_channel_counts(nodes: &[(&SdkNode, usize)], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut polls = 0u32;
    loop {
        polls += 1;
        let mut all_ready = true;
        for (node, expected) in nodes {
            node.sync()
                .expect("node sync while waiting for usable channel counts");
            let usable = node
                .list_channels()
                .expect("list_channels while waiting for usable channel counts")
                .into_iter()
                .filter(|channel| channel.ready && channel.is_usable)
                .count();
            if usable != *expected {
                all_ready = false;
            }
        }
        if all_ready {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "usable channel counts did not reach expected values in time"
        );
        if polls % 5 == 0 {
            mine(1);
        }
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_num_peers(node: &SdkNode, expected_num_peers: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let node_info = node
            .node_info()
            .expect("node_info while waiting for num_peers");
        if node_info.num_peers == expected_num_peers {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "num_peers ({}) did not become {}",
            node_info.num_peers,
            expected_num_peers
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_payment_status(
    node: &SdkNode,
    payment_hash: &PaymentHash,
    timeout: Duration,
) -> Payment {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(payment) = node
            .list_payments()
            .expect("list_payments while waiting for payment success")
            .into_iter()
            .find(|payment| {
                payment.payment_hash == *payment_hash
                    && matches!(payment.status, HtlcStatus::Succeeded)
            })
        {
            return payment;
        }

        assert!(
            Instant::now() < deadline,
            "timeout waiting for payment success"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_ln_balance(
    node: &SdkNode,
    asset_id: &ContractId,
    expected_balance: u64,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let balance = asset_balance_offchain_outbound(node, asset_id);
        if balance == expected_balance {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "offchain_outbound balance ({balance}) did not become {expected_balance}"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_balance(
    node: &SdkNode,
    asset_id: &ContractId,
    expected_balance: u64,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let balance = asset_balance_spendable(node, asset_id);
        if balance == expected_balance {
            return;
        }
        node.refreshtransfers(SdkRefreshTransfersRequest { skip_sync: false })
            .expect("refreshtransfers while waiting for balance");
        assert!(
            Instant::now() < deadline,
            "spendable balance ({balance}) did not become {expected_balance}"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_payment_present_in_list(
    node: &SdkNode,
    payment_hash: &PaymentHash,
    timeout: Duration,
) -> Payment {
    let deadline = Instant::now() + timeout;
    loop {
        let payments = node.list_payments().expect("list_payments");
        if let Some(payment) = payments
            .into_iter()
            .find(|payment| payment.payment_hash == *payment_hash)
        {
            return payment;
        }
        assert!(
            Instant::now() < deadline,
            "payment not found in list_payments"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_succeeded_payment_in_list(
    node: &SdkNode,
    payment_hash: &PaymentHash,
    timeout: Duration,
) -> Payment {
    let deadline = Instant::now() + timeout;
    loop {
        node.sync()
            .expect("node sync while waiting for succeeded payment in list");
        let payments = node.list_payments().expect("list_payments");
        if let Some(payment) = payments
            .into_iter()
            .find(|payment| payment.payment_hash == *payment_hash)
        {
            if matches!(payment.status, HtlcStatus::Succeeded) {
                return payment;
            }
        }
        assert!(
            Instant::now() < deadline,
            "payment did not become succeeded in list_payments"
        );
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn send_payment_with_ln_balance(
    sender: &SdkNode,
    receiver: &SdkNode,
    invoice: rgb_lightning_node::Bolt11Invoice,
    asset_id: &ContractId,
    asset_amount: u64,
    initial_sender_ln_balance: u64,
    initial_receiver_ln_balance: u64,
) {
    let send_payment = sender
        .sendpayment(SdkSendPaymentRequest {
            invoice: invoice.to_string(),
            amt_msat: None,
            asset_id: None,
            asset_amount: None,
        })
        .expect("sendpayment with ln balance checks");

    assert!(matches!(
        send_payment.status,
        HtlcStatus::Pending | HtlcStatus::Succeeded
    ));

    let payment_hash = send_payment
        .payment_hash
        .expect("payment hash from sendpayment");
    wait_for_ln_balance(
        sender,
        asset_id,
        initial_sender_ln_balance - asset_amount,
        Duration::from_secs(60),
    );
    wait_for_payment_status(sender, &payment_hash, Duration::from_secs(60));
    wait_for_ln_balance(
        receiver,
        asset_id,
        initial_receiver_ln_balance + asset_amount,
        Duration::from_secs(60),
    );
    wait_for_payment_status(receiver, &payment_hash, Duration::from_secs(60));
}

pub(crate) fn keysend_with_ln_balance(
    sender: &SdkNode,
    receiver: &SdkNode,
    dest_pubkey: bitcoin::secp256k1::PublicKey,
    amt_msat: Option<u64>,
    asset_id: &ContractId,
    asset_amount: u64,
    initial_sender_ln_balance: u64,
    initial_receiver_ln_balance: u64,
) {
    let keysend = sender
        .keysend(SdkKeysendRequest {
            dest_pubkey,
            amt_msat: amt_msat.unwrap_or(PAYMENT_MSAT),
            asset_id: Some(asset_id.clone()),
            asset_amount: Some(asset_amount),
        })
        .expect("keysend with ln balance checks");

    assert!(matches!(
        keysend.status,
        HtlcStatus::Pending | HtlcStatus::Succeeded
    ));

    wait_for_ln_balance(
        sender,
        asset_id,
        initial_sender_ln_balance - asset_amount,
        Duration::from_secs(60),
    );
    wait_for_payment_status(sender, &keysend.payment_hash, Duration::from_secs(60));
    wait_for_ln_balance(
        receiver,
        asset_id,
        initial_receiver_ln_balance + asset_amount,
        Duration::from_secs(60),
    );
    wait_for_payment_status(receiver, &keysend.payment_hash, Duration::from_secs(60));
}

pub(crate) fn keysend(
    sender: &SdkNode,
    dest_pubkey: bitcoin::secp256k1::PublicKey,
    amt_msat: Option<u64>,
    asset_id: Option<&ContractId>,
    asset_amount: Option<u64>,
) -> Payment {
    let keysend = sender
        .keysend(SdkKeysendRequest {
            dest_pubkey,
            amt_msat: amt_msat.unwrap_or(PAYMENT_MSAT),
            asset_id: asset_id.cloned(),
            asset_amount,
        })
        .expect("keysend");
    wait_for_succeeded_payment_in_list(sender, &keysend.payment_hash, Duration::from_secs(60))
}

pub(crate) fn close_channel(
    node: &SdkNode,
    channel_id: lightning::ln::types::ChannelId,
    peer_pubkey: bitcoin::secp256k1::PublicKey,
) {
    close_channel_with_force(node, channel_id, peer_pubkey, false);
}

pub(crate) fn close_channel_with_force(
    node: &SdkNode,
    channel_id: lightning::ln::types::ChannelId,
    peer_pubkey: bitcoin::secp256k1::PublicKey,
    force: bool,
) {
    stop_mining();
    node.closechannel(SdkCloseChannelRequest {
        channel_id,
        peer_pubkey,
        force,
    })
    .expect("closechannel");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let channels = node
            .list_channels()
            .expect("list_channels while waiting for close");
        if !channels
            .iter()
            .any(|channel| channel.channel_id == channel_id)
        {
            mine_blocks(true, if force { 144 } else { 6 });
            return;
        }
        assert!(Instant::now() < deadline, "channel did not close in time");
        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn refresh_transfers(node: &SdkNode) {
    node.refreshtransfers(SdkRefreshTransfersRequest { skip_sync: false })
        .expect("refreshtransfers");
}
