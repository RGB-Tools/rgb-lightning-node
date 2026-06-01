#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import List, Optional

import rgb_lightning_node as rln

REPO_ROOT = Path(__file__).resolve().parents[4]

PROXY_ENDPOINT_LOCAL = "rpc://127.0.0.1:3000/json-rpc"

NODE_A_PASSWORD = os.getenv("NODE_A_PASSWORD", "nodeApass")
NODE_B_PASSWORD = os.getenv("NODE_B_PASSWORD", "nodeBpass")

OPEN_CHANNEL_CAPACITY_SAT = int(os.getenv("OPEN_CHANNEL_CAPACITY_SAT", "500000"))
OPEN_CHANNEL_PUSH_MSAT = int(os.getenv("OPEN_CHANNEL_PUSH_MSAT", "0"))
ROUNDTRIP_OPEN_CHANNEL_PUSH_MSAT = int(
    os.getenv("ROUNDTRIP_OPEN_CHANNEL_PUSH_MSAT", "6000000")
)
PAYMENT_MSAT = int(os.getenv("PAYMENT_MSAT", "3000000"))
CREATE_UTXOS_NUM = int(os.getenv("CREATE_UTXOS_NUM", "10"))
CREATE_UTXOS_SIZE_SAT = int(os.getenv("CREATE_UTXOS_SIZE_SAT", "100000"))
CREATE_UTXOS_FEE_RATE = int(os.getenv("CREATE_UTXOS_FEE_RATE", "7"))
OPEN_CHANNEL_CONFIRM_BLOCKS = int(os.getenv("OPEN_CHANNEL_CONFIRM_BLOCKS", "12"))
CHANNEL_READY_TIMEOUT_SEC = int(os.getenv("CHANNEL_READY_TIMEOUT_SEC", "300"))
PAYMENT_SUCCEEDED_TIMEOUT_SEC = int(os.getenv("PAYMENT_SUCCEEDED_TIMEOUT_SEC", "300"))
ISSUE_ASSET_TICKER = os.getenv("ISSUE_ASSET_TICKER", "USDT")
ISSUE_ASSET_NAME = os.getenv("ISSUE_ASSET_NAME", "Tether")
ISSUE_ASSET_PRECISION = int(os.getenv("ISSUE_ASSET_PRECISION", "0"))
ISSUE_ASSET_SUPPLY = int(os.getenv("ISSUE_ASSET_SUPPLY", "1000"))
OPEN_CHANNEL_ASSET_AMOUNT = int(os.getenv("OPEN_CHANNEL_ASSET_AMOUNT", "200"))
PAYMENT_ASSET_AMOUNT = int(os.getenv("PAYMENT_ASSET_AMOUNT", "50"))
RGB_MIN_HTLC_MSAT = 3_000_000
RESET_DATA = os.getenv("RESET_DATA", "1") == "1"
# Set to 1 for stderr progress while waiting on funding / usable channels (mixed RGB debugging).
_PY_EXT_SIGNER_DEBUG = os.getenv("PY_EXT_SIGNER_DEBUG", "").lower() in ("1", "true", "yes")
# When 0, disables the regtest-only heuristic: single mempool tx treated as funding if
# `list_channels` has rows but funding_txid is slow to appear (mixed internal/external RGB).
_PY_EXT_SIGNER_FUNDING_MEMPOOL_FALLBACK = os.getenv(
    "PY_EXT_SIGNER_FUNDING_MEMPOOL_FALLBACK", "1"
) != "0"


def run_command(*args: str) -> str:
    res = subprocess.run(
        list(args),
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return (res.stdout or "").strip()


def run_regtest(*args: str) -> str:
    return run_command("./regtest.sh", *args)


def ensure_regtest_available():
    out = run_command("docker", "compose", "ps", "--services", "--status", "running")
    services = set(line.strip() for line in out.splitlines() if line.strip())
    for required in ("bitcoind", "electrs", "proxy"):
        if required not in services:
            raise RuntimeError(
                f"regtest service `{required}` is not running; start it with ./regtest.sh start"
            )


def ensure_dir(path: Path, *, reset: bool = True):
    if reset and RESET_DATA and path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def make_node(storage_dir: Path, daemon_port: int, peer_port: int) -> rln.SdkNode:
    req = rln.SdkInitRequest(
        storage_dir_path=str(storage_dir),
        daemon_listening_port=daemon_port,
        ldk_peer_listening_port=peer_port,
        network="regtest",
        max_media_upload_size_mb=20,
        enable_virtual_channels_v0=False,
        virtual_peer_pubkeys=None,
        lsp_base_url=None,
        lsp_bearer_token=None,
    )
    last_err = None
    for _ in range(5):
        try:
            return rln.SdkNode.create(req)
        except rln.RlnError.Internal as e:
            last_err = e
            req.daemon_listening_port = find_free_port()
            req.ldk_peer_listening_port = find_free_port()
            time.sleep(0.2)
    assert last_err is not None
    raise last_err


def unlock_request(password: str) -> rln.SdkUnlockRequest:
    return rln.SdkUnlockRequest(
        password=password,
        bitcoind_rpc_username="user",
        bitcoind_rpc_password="password",
        bitcoind_rpc_host="localhost",
        bitcoind_rpc_port=18443,
        indexer_url="127.0.0.1:50001",
        proxy_endpoint=PROXY_ENDPOINT_LOCAL,
        announce_addresses=[],
        announce_alias=None,
    )

def unlock_with_attached_signer(
    node: rln.SdkNode,
):
    node.unlock_with_attached_external_signer(
        "user",
        "password",
        "localhost",
        18443,
        "127.0.0.1:50001",
        PROXY_ENDPOINT_LOCAL,
        [],
        "RLN_external_py",
    )


def make_native_signer(storage_dir: Path, *, reset: bool = True) -> "rln.NativeExternalSigner":
    network = os.getenv("RLN_TEST_NATIVE_SIGNER_NETWORK", "regtest")
    permissive_policy = os.getenv("RLN_TEST_NATIVE_SIGNER_PERMISSIVE_POLICY", "1") == "1"
    seed_hex = os.getenv("RLN_TEST_NATIVE_SIGNER_SEED_HEX", "11" * 32)
    ensure_dir(storage_dir, reset=reset)
    return rln.NativeExternalSigner(seed_hex, network, permissive_policy)


def make_native_signer_with_dir(
    storage_dir: Path, *, reset: bool = True
) -> "rln.NativeExternalSigner":
    network = os.getenv("RLN_TEST_NATIVE_SIGNER_NETWORK", "regtest")
    permissive_policy = os.getenv("RLN_TEST_NATIVE_SIGNER_PERMISSIVE_POLICY", "1") == "1"
    seed_hex = os.getenv("RLN_TEST_NATIVE_SIGNER_SEED_HEX", "11" * 32)
    ensure_dir(storage_dir, reset=reset)
    return rln.NativeExternalSigner(seed_hex, network, permissive_policy)


def ensure_funded(node: rln.SdkNode, min_spendable_sat: int):
    spendable = node.btc_balance(False).vanilla.spendable
    if spendable >= min_spendable_sat:
        return
    address = node.address().address
    run_regtest("sendtoaddress", address, "1")
    run_regtest("mine", "6")
    node.sync()
    spendable_after = node.btc_balance(False).vanilla.spendable
    if spendable_after < min_spendable_sat:
        raise RuntimeError(
            f"node spendable balance too low after funding: {spendable_after} < {min_spendable_sat}"
        )


def create_utxos(node: rln.SdkNode):
    node.createutxos(
        rln.SdkCreateUtxosRequest(
            up_to=False,
            num=CREATE_UTXOS_NUM,
            size=CREATE_UTXOS_SIZE_SAT,
            fee_rate=CREATE_UTXOS_FEE_RATE,
            skip_sync=False,
        )
    )
    run_regtest("mine", "1")
    node.sync()


def create_utxos_if_possible(node: rln.SdkNode):
    try:
        create_utxos(node)
    except (rln.RlnError.Conflict, rln.RlnError.Internal):
        # External real signer backends may not support wallet key-index mapping
        # required by createutxos PSBT signing yet; continue with funded wallet UTXOs.
        pass


def issue_asset_nia(node: rln.SdkNode, name: str) -> str:
    asset = node.issueassetnia(
        rln.SdkIssueAssetNiaRequest(
            amounts=[ISSUE_ASSET_SUPPLY],
            ticker=ISSUE_ASSET_TICKER,
            name=ISSUE_ASSET_NAME,
            precision=ISSUE_ASSET_PRECISION,
        )
    )
    print(f"{name}: issued NIA asset_id={asset.asset_id}")
    run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
    wait_for_asset_balance(node, asset.asset_id, spendable=ISSUE_ASSET_SUPPLY, timeout_sec=60)
    return asset.asset_id


def wait_for_channel_funding_tx(
    node_a: rln.SdkNode,
    timeout_sec: int = 120,
    asset_id: Optional[str] = None,
    node_b: Optional[rln.SdkNode] = None,
) -> str:
    """Wait until we can name a funding txid that bitcoind knows, then return it.

    Primary path: ``list_channels()`` row with ``funding_txid`` + ``getrawtransaction`` succeeds.

    Regtest fallback (``PY_EXT_SIGNER_FUNDING_MEMPOOL_FALLBACK``): mixed internal/external RGB
    opens sometimes broadcast funding before the UniFFI channel row exposes ``funding_txid``.
    If bitcoind's mempool has **exactly one** tx and node A already lists **at least one**
    channel, treat that tx as funding (valid only for isolated single-channel flows).
    """
    deadline = time.time() + timeout_sec
    last_log = 0.0
    while time.time() < deadline:
        node_a.sync()
        if node_b is not None:
            node_b.sync()
        channels = node_a.list_channels()
        if asset_id is None:
            opening = next((c for c in channels if c.funding_txid is not None), None)
        else:
            opening = next(
                (
                    c
                    for c in channels
                    if c.funding_txid is not None and str(c.asset_id) == asset_id
                ),
                None,
            )
        if opening is not None:
            txid = str(opening.funding_txid)
            # `funding_txid` is set from LDK once `funding_outpoint` is known, which can be before
            # the funding tx is actually broadcast. Wait until bitcoind knows the tx (mempool or
            # chain), matching `wait_for_channel_open` in `src/test/lib_sdk/helpers.rs` (gettxout).
            if _regtest_funding_tx_seen_by_bitcoind(txid):
                return txid
        # Regtest-only: mempool has a single tx while we already have a channel row — likely
        # funding broadcast before `funding_txid` appears on the listing (mixed RGB + external).
        if (
            _PY_EXT_SIGNER_FUNDING_MEMPOOL_FALLBACK
            and asset_id is None
            and channels
        ):
            mempool_txids = _regtest_mempool_txids()
            if len(mempool_txids) == 1:
                cand = mempool_txids[0]
                if _regtest_funding_tx_seen_by_bitcoind(cand):
                    if _PY_EXT_SIGNER_DEBUG:
                        print(
                            f"[PY_EXT_SIGNER_DEBUG] funding wait: using sole mempool tx {cand} "
                            f"(channels={len(channels)}, no usable funding_txid+bitcoind match yet)",
                            flush=True,
                        )
                    return cand
        if _PY_EXT_SIGNER_DEBUG and time.time() - last_log >= 10.0:
            last_log = time.time()
            n_mempool = len(_regtest_mempool_txids())
            with_fund = sum(1 for c in channels if c.funding_txid is not None)
            print(
                f"[PY_EXT_SIGNER_DEBUG] funding wait: channels={len(channels)} "
                f"with_funding_txid={with_fund} mempool_txs={n_mempool} "
                f"elapsed={int(time.time() - (deadline - timeout_sec))}s",
                flush=True,
            )
        time.sleep(1)
    raise RuntimeError("timeout waiting for funding tx broadcast")


def _regtest_mempool_txids() -> List[str]:
    """Return txid list from regtest bitcoind mempool (empty list on failure)."""
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=user",
                "-rpcpassword=password",
                "getrawmempool",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout)
        if isinstance(data, list):
            return [str(x) for x in data]
        return []
    except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return []


def _regtest_funding_tx_seen_by_bitcoind(txid: str) -> bool:
    """True if regtest bitcoind has this tx (mempool or block)."""
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=user",
                "-rpcpassword=password",
                "getrawtransaction",
                txid,
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _regtest_rawtx_confirmed(txid: str) -> bool:
    """True if bitcoind reports the tx in a block (wallet list_transactions can lag)."""
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=user",
                "-rpcpassword=password",
                "getrawtransaction",
                txid,
                "true",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return False
        data = json.loads(proc.stdout)
        return data.get("confirmations", 0) >= 1
    except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return False


def mine_until_tx_confirmed(
    node: rln.SdkNode,
    txid: str,
    timeout_sec: int = 180,
    peer_node: Optional[rln.SdkNode] = None,
):
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        node.sync()
        if peer_node is not None:
            peer_node.sync()
        txs = node.list_transactions(False)
        tx = next((t for t in txs if str(t.txid) == txid), None)
        if tx is not None and tx.confirmation_time is not None:
            return
        if _regtest_rawtx_confirmed(txid):
            return
        run_regtest("mine", "1")
        time.sleep(1)
    raise RuntimeError(f"funding tx not confirmed: {txid}")


def wait_for_usable_channels(
    nodes: list[tuple[rln.SdkNode, int]],
    timeout_sec: int = 180,
    asset_id: Optional[str] = None,
) -> None:
    deadline = time.time() + timeout_sec
    last_log = 0.0
    while time.time() < deadline:
        all_ready = True
        for node, expected_usable in nodes:
            node.sync()
            usable = sum(
                1
                for c in node.list_channels()
                if c.ready
                and c.is_usable
                and (asset_id is None or str(c.asset_id) == asset_id)
            )
            if usable != expected_usable:
                all_ready = False
        if all_ready:
            return
        if _PY_EXT_SIGNER_DEBUG and time.time() - last_log >= 10.0:
            last_log = time.time()
            parts = []
            for node, expected_usable in nodes:
                chans = node.list_channels()
                usable = sum(
                    1
                    for c in chans
                    if c.ready
                    and c.is_usable
                    and (asset_id is None or str(c.asset_id) == asset_id)
                )
                parts.append(f"usable={usable}/{expected_usable} chans={len(chans)}")
            print(
                f"[PY_EXT_SIGNER_DEBUG] wait_for_usable_channels: {', '.join(parts)} "
                f"asset_id_filter={asset_id!r}",
                flush=True,
            )
        time.sleep(1)
    raise RuntimeError("timeout waiting for usable channels")


def wait_for_payment_succeeded(
    node: rln.SdkNode,
    payment_hash: rln.PaymentHash,
    timeout_sec: Optional[int] = None,
    peer_node: Optional[rln.SdkNode] = None,
):
    """Wait until ``list_payments`` shows ``SUCCEEDED`` for this hash on ``node``.

    Syncs the optional ``peer_node`` each iteration (so the counterparty advances state) and
    mines a regtest block every 5 polls, matching ``wait_for_usable_channel_counts`` in
    ``src/test/lib_sdk/helpers.rs`` (HTLC / commitment updates often need chain progress).
    """
    if timeout_sec is None:
        timeout_sec = PAYMENT_SUCCEEDED_TIMEOUT_SEC
    deadline = time.time() + timeout_sec
    polls = 0
    last_payment_state: Optional[str] = None
    while time.time() < deadline:
        polls += 1
        node.sync()
        if peer_node is not None:
            peer_node.sync()
        payment = next(
            (p for p in node.list_payments() if p.payment_hash == payment_hash), None
        )
        if payment is not None:
            last_payment_state = repr(payment.status)
            if payment.status == rln.HtlcStatus.SUCCEEDED:
                return
            if payment.status == rln.HtlcStatus.FAILED:
                chans = node.list_channels()
                raise RuntimeError(
                    "payment reached FAILED (see RUST_LOG / node logs). "
                    f"channels={len(chans)} usable="
                    f"{sum(1 for c in chans if c.ready and c.is_usable)} "
                    f"last_status={last_payment_state!r}"
                )
        if _PY_EXT_SIGNER_DEBUG and payment is not None and polls % 10 == 0:
            print(
                f"[PY_EXT_SIGNER_DEBUG] payment wait: status={payment.status!r} "
                f"poll={polls} timeout_sec={timeout_sec}",
                flush=True,
            )
        if polls % 5 == 0:
            run_regtest("mine", "1")
        time.sleep(1)
    raise RuntimeError(
        "payment did not reach SUCCEEDED "
        f"(timeout_sec={timeout_sec}, last_status={last_payment_state!r})"
    )


def wait_for_channels_gone(
    nodes: list[rln.SdkNode],
    *,
    asset_id: Optional[str] = None,
    timeout_sec: int = 120,
) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        all_gone = True
        for node in nodes:
            node.sync()
            channels = node.list_channels()
            if asset_id is None:
                matching = channels
            else:
                matching = [c for c in channels if str(c.asset_id) == asset_id]
            if matching:
                all_gone = False
        if all_gone:
            return
        time.sleep(1)
    raise RuntimeError("timeout waiting for channel removal after close")


def wait_for_asset_balance(
    node: rln.SdkNode,
    asset_id: str,
    *,
    settled: Optional[int] = None,
    future: Optional[int] = None,
    spendable: Optional[int] = None,
    offchain_outbound: Optional[int] = None,
    offchain_inbound: Optional[int] = None,
    timeout_sec: int = 180,
) -> None:
    def _fmt_balance(bal: object) -> str:
        return (
            f"settled={bal.settled} future={bal.future} spendable={bal.spendable} "
            f"offchain_outbound={bal.offchain_outbound} offchain_inbound={bal.offchain_inbound}"
        )

    deadline = time.time() + timeout_sec
    last_balance = None
    while time.time() < deadline:
        node.sync()
        node.refreshtransfers(rln.SdkRefreshTransfersRequest(skip_sync=False))
        bal = node.asset_balance(asset_id)
        last_balance = bal
        if (
            (settled is None or bal.settled == settled)
            and (future is None or bal.future == future)
            and (spendable is None or bal.spendable == spendable)
            and (
                offchain_outbound is None
                or bal.offchain_outbound == offchain_outbound
            )
            and (offchain_inbound is None or bal.offchain_inbound == offchain_inbound)
        ):
            return
        time.sleep(1)
    raise RuntimeError(
        f"asset balance did not reach expected state for {asset_id}: "
        f"last={_fmt_balance(last_balance)}"
    )


def _setup_mixed_asset_channel_with_payment(
    scenario_name: str,
    *,
    open_channel_push_msat: Optional[int] = None,
) -> tuple[
    rln.SdkNode,
    rln.SdkNode,
    object,
    str,
    object,
]:
    ensure_regtest_available()
    data_root = REPO_ROOT / "target" / "uniffi" / "python-e2e" / scenario_name
    node_a_dir = data_root / "node_a_internal"
    node_b_dir = data_root / "node_b_external"
    signer_dir = data_root / "signer_b"
    ensure_dir(node_a_dir)
    ensure_dir(node_b_dir)
    signer = make_native_signer(signer_dir, reset=True)

    node_a_daemon_port = find_free_port()
    node_b_daemon_port = find_free_port()
    node_a_peer_port = find_free_port()
    node_b_peer_port = find_free_port()

    node_a = make_node(node_a_dir, node_a_daemon_port, node_a_peer_port)
    node_b = make_node(node_b_dir, node_b_daemon_port, node_b_peer_port)

    node_a.init(NODE_A_PASSWORD, None)
    node_b.init_with_native_external_signer(signer)
    node_a.unlock(unlock_request(NODE_A_PASSWORD))
    node_b.unlock_with_native_external_signer(
        signer,
        "user",
        "password",
        "localhost",
        18443,
        "127.0.0.1:50001",
        PROXY_ENDPOINT_LOCAL,
        [],
        "RLN_external_py",
    )

    ensure_funded(node_a, OPEN_CHANNEL_CAPACITY_SAT + 250_000)
    ensure_funded(node_b, 100_000)
    create_utxos(node_a)
    create_utxos_if_possible(node_b)

    asset_id = issue_asset_nia(node_a, "node A")
    peer_uri = f"{node_b.node_info().pubkey}@127.0.0.1:{node_b_peer_port}"
    try:
        node_a.connectpeer(peer_uri)
    except rln.RlnError.Conflict:
        pass

    push_msat = OPEN_CHANNEL_PUSH_MSAT if open_channel_push_msat is None else open_channel_push_msat
    open_res = node_a.openchannel(
        rln.SdkOpenChannelRequest(
            peer_pubkey_and_opt_addr=peer_uri,
            capacity_sat=OPEN_CHANNEL_CAPACITY_SAT,
            push_msat=push_msat,
            public=False,
            with_anchors=True,
            fee_base_msat=None,
            fee_proportional_millionths=None,
            temporary_channel_id=None,
            asset_id=asset_id,
            asset_amount=OPEN_CHANNEL_ASSET_AMOUNT,
            push_asset_amount=None,
            virtual_open_mode=None,
        )
    )
    print("opened mixed asset channel temporary id:", open_res.temporary_channel_id)

    txid = wait_for_channel_funding_tx(
        node_a,
        timeout_sec=CHANNEL_READY_TIMEOUT_SEC,
        asset_id=None,
        node_b=node_b,
    )
    mine_until_tx_confirmed(node_a, txid, peer_node=node_b)
    run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
    wait_for_usable_channels(
        [(node_a, 1), (node_b, 1)],
        timeout_sec=CHANNEL_READY_TIMEOUT_SEC,
        asset_id=asset_id,
    )

    channel = next(
        c
        for c in node_a.list_channels()
        if c.funding_txid is not None and str(c.asset_id) == asset_id and c.is_usable
    )
    print("mixed internal/external RGB channel is usable")

    invoice = node_b.ln_invoice(
        rln.LnInvoiceRequest(
            amt_msat=PAYMENT_MSAT,
            expiry_sec=900,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
            payment_hash=None,
            description_hash=None,
                    min_final_cltv_expiry_delta=None,
)
    ).invoice
    send = node_a.sendpayment(
        rln.SdkSendPaymentRequest(
            invoice=str(invoice),
            amt_msat=PAYMENT_MSAT,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
        )
    )
    if send.payment_hash is None:
        raise RuntimeError("sendpayment did not return payment_hash for mixed RGB payment")
    wait_for_payment_succeeded(node_a, send.payment_hash, peer_node=node_b)
    wait_for_payment_succeeded(node_b, send.payment_hash, peer_node=node_a)
    print("mixed internal/external RGB payment succeeded")
    return node_a, node_b, signer, asset_id, channel


def run_regular_channel_flow_external_real():
    data_root = REPO_ROOT / "target" / "uniffi" / "python-e2e" / "external-real-flow"
    node_a_dir = data_root / "node_a"
    node_b_dir = data_root / "node_b"
    signer_dir = data_root / "signer_a"
    ensure_dir(node_a_dir)
    ensure_dir(node_b_dir)
    signer = make_native_signer(signer_dir, reset=True)
    bootstrap = signer.bootstrap()

    node_a_daemon_port = find_free_port()
    node_b_daemon_port = find_free_port()
    node_a_peer_port = find_free_port()
    node_b_peer_port = find_free_port()

    node_a = make_node(node_a_dir, node_a_daemon_port, node_a_peer_port)
    node_b = make_node(node_b_dir, node_b_daemon_port, node_b_peer_port)
    try:
        node_a.init_with_native_external_signer(signer)
        node_b.init(NODE_B_PASSWORD, None)
        node_a.unlock_with_native_external_signer(
            signer,
            "user",
            "password",
            "localhost",
            18443,
            "127.0.0.1:50001",
            PROXY_ENDPOINT_LOCAL,
            [],
            "RLN_external_py",
        )
        node_b.unlock(unlock_request(NODE_B_PASSWORD))

        ensure_funded(node_a, 300_000)
        ensure_funded(node_b, 100_000)
        # External signer backends may not yet support the key-index mapping
        # needed by createutxos; skip for node_a to keep the regular-flow
        # scenario focused on channel operations.
        # create_utxos_if_possible(node_a)
        create_utxos_if_possible(node_b)

        peer_uri = f"{node_b.node_info().pubkey}@127.0.0.1:{node_b_peer_port}"
        try:
            node_a.connectpeer(peer_uri)
        except rln.RlnError.Conflict:
            pass

        open_res = node_a.openchannel(
            rln.SdkOpenChannelRequest(
                peer_pubkey_and_opt_addr=peer_uri,
                capacity_sat=OPEN_CHANNEL_CAPACITY_SAT,
                push_msat=0,
                public=False,
                with_anchors=True,
                fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id=None,
                asset_amount=None,
                push_asset_amount=None,
                virtual_open_mode=None,
            )
        )
        print("opened channel temporary id:", open_res.temporary_channel_id)

        txid = wait_for_channel_funding_tx(node_a)
        mine_until_tx_confirmed(node_a, txid)
        print(f"mining {OPEN_CHANNEL_CONFIRM_BLOCKS} extra blocks for channel confirmations...")
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        wait_for_usable_channels(
            [(node_a, 1), (node_b, 1)], timeout_sec=CHANNEL_READY_TIMEOUT_SEC
        )

        inv_1 = node_b.ln_invoice(
            rln.LnInvoiceRequest(
                amt_msat=PAYMENT_MSAT,
                expiry_sec=900,
                asset_id=None,
                asset_amount=None,
                payment_hash=None,
                description_hash=None,
                            min_final_cltv_expiry_delta=None,
)
        ).invoice
        send_1 = node_a.sendpayment(
            rln.SdkSendPaymentRequest(
                invoice=str(inv_1),
                amt_msat=None,
                asset_id=None,
                asset_amount=None,
            )
        )
        if send_1.payment_hash is None:
            raise RuntimeError("sendpayment did not return payment_hash")
        wait_for_payment_succeeded(node_a, send_1.payment_hash, peer_node=node_b)
        wait_for_payment_succeeded(node_b, send_1.payment_hash, peer_node=node_a)
        print("payment #1 succeeded")

        node_a.shutdown()
        time.sleep(0.5)
        node_a = make_node(node_a_dir, node_a_daemon_port, node_a_peer_port)
        # Keep the same in-process native signer instance across node restart.
        # The VLS in-process transport uses an in-memory persister, so recreating the signer
        # can lose enforcement state needed for subsequent commitment validation.
        node_a.unlock_with_native_external_signer(
            signer,
            "user",
            "password",
            "localhost",
            18443,
            "127.0.0.1:50001",
            PROXY_ENDPOINT_LOCAL,
            [],
            "RLN_external_py",
        )
        wait_for_usable_channels([(node_a, 1), (node_b, 1)])

        inv_2 = node_b.ln_invoice(
            rln.LnInvoiceRequest(
                amt_msat=PAYMENT_MSAT,
                expiry_sec=900,
                asset_id=None,
                asset_amount=None,
                payment_hash=None,
                description_hash=None,
                            min_final_cltv_expiry_delta=None,
)
        ).invoice
        send_2 = node_a.sendpayment(
            rln.SdkSendPaymentRequest(
                invoice=str(inv_2),
                amt_msat=None,
                asset_id=None,
                asset_amount=None,
            )
        )
        if send_2.payment_hash is None:
            raise RuntimeError("sendpayment did not return payment_hash")
        wait_for_payment_succeeded(node_a, send_2.payment_hash, peer_node=node_b)
        wait_for_payment_succeeded(node_b, send_2.payment_hash, peer_node=node_a)
        print("payment #2 succeeded after restart")
    finally:
        try:
            node_a.shutdown()
        except Exception:
            pass
        try:
            node_b.shutdown()
        except Exception:
            pass


def run_mixed_asset_channel_internal_external_real():
    """RGB asset channel: internal opener (issues NIA) + NativeExternalSigner (VLS) acceptor.

    Uses in-process VLS, not the attached protobuf signer. Opt-in via ``RUN_MIXED_ASSET_EXTERNAL_E2E``
    because it needs regtest and a VLS-enabled build (``uniffi,vls``).
    """
    if os.getenv("RUN_MIXED_ASSET_EXTERNAL_E2E", "").lower() not in ("1", "true", "yes"):
        print(
            "SKIP mixed-asset-channel-real: set RUN_MIXED_ASSET_EXTERNAL_E2E=1 to run "
            "(requires regtest + ``cargo build --features uniffi,vls`` and generated Python bindings)."
        )
        return

    ensure_regtest_available()
    node_a = node_b = None
    try:
        node_a, node_b, _signer, _asset_id, _channel = _setup_mixed_asset_channel_with_payment(
            "mixed-asset-channel-real"
        )
    finally:
        if node_a is not None:
            try:
                node_a.shutdown()
            except Exception:
                pass
        if node_b is not None:
            try:
                node_b.shutdown()
            except Exception:
                pass


def run_mixed_asset_channel_roundtrip_real():
    """Validate that the external-signer node can originate an RGB asset payment."""
    if os.getenv("RUN_MIXED_ASSET_EXTERNAL_E2E", "").lower() not in ("1", "true", "yes"):
        print(
            "SKIP mixed-asset-channel-roundtrip-real: set RUN_MIXED_ASSET_EXTERNAL_E2E=1 to run "
            "(requires regtest + ``cargo build --features uniffi,vls`` and generated Python bindings)."
        )
        return

    ensure_regtest_available()
    node_a = node_b = None
    try:
        node_a, node_b, _signer, asset_id, _channel = _setup_mixed_asset_channel_with_payment(
            "mixed-asset-channel-roundtrip-real",
            open_channel_push_msat=max(
                OPEN_CHANNEL_PUSH_MSAT, ROUNDTRIP_OPEN_CHANNEL_PUSH_MSAT
            ),
        )
        invoice = node_a.ln_invoice(
            rln.LnInvoiceRequest(
                amt_msat=PAYMENT_MSAT,
                expiry_sec=900,
                asset_id=asset_id,
                asset_amount=PAYMENT_ASSET_AMOUNT,
                payment_hash=None,
                description_hash=None,
                            min_final_cltv_expiry_delta=None,
)
        ).invoice
        send = node_b.sendpayment(
            rln.SdkSendPaymentRequest(
                invoice=str(invoice),
                amt_msat=None,
                asset_id=None,
                asset_amount=None,
            )
        )
        if send.payment_hash is None:
            raise RuntimeError("external signer sendpayment did not return payment_hash")

        try:
            wait_for_payment_succeeded(node_b, send.payment_hash, peer_node=node_a)
            wait_for_payment_succeeded(node_a, send.payment_hash, peer_node=node_b)
        except Exception as e:
            raise RuntimeError(
                "external signer outbound RGB round-trip payment failed "
                f"(payment_hash={send.payment_hash}): {e}"
            ) from e
        wait_for_asset_balance(
            node_a,
            asset_id,
            settled=1000,
            future=1000,
            spendable=1000,
            offchain_outbound=200,
            offchain_inbound=0,
            timeout_sec=120,
        )
        wait_for_asset_balance(
            node_b,
            asset_id,
            settled=0,
            future=0,
            spendable=0,
            offchain_outbound=0,
            offchain_inbound=200,
            timeout_sec=120,
        )
        print("mixed internal/external RGB round-trip succeeded")
    finally:
        if node_a is not None:
            try:
                node_a.shutdown()
            except Exception:
                pass
        if node_b is not None:
            try:
                node_b.shutdown()
            except Exception:
                pass


def run_mixed_asset_channel_close_settlement_real(force: bool):
    if os.getenv("RUN_MIXED_ASSET_EXTERNAL_E2E", "").lower() not in ("1", "true", "yes"):
        print(
            "SKIP mixed-asset-channel-*-close-real: set RUN_MIXED_ASSET_EXTERNAL_E2E=1 to run "
            "(requires regtest + ``cargo build --features uniffi,vls`` and generated Python bindings)."
        )
        return

    scenario_name = (
        "mixed-asset-channel-force-close-real"
        if force
        else "mixed-asset-channel-coop-close-real"
    )
    node_a = node_b = None
    try:
        node_a, node_b, _signer, asset_id, channel = _setup_mixed_asset_channel_with_payment(
            scenario_name
        )
        close_req = rln.SdkCloseChannelRequest(
            channel_id=channel.channel_id,
            peer_pubkey=node_b.node_info().pubkey,
            force=force,
        )
        node_a.closechannel(close_req)
        print(f"{'force' if force else 'coop'} close initiated")

        wait_for_channels_gone([node_a, node_b], asset_id=asset_id, timeout_sec=120)
        if force:
            for _ in range(16):
                run_regtest("mine", "10")
            wait_for_asset_balance(
                node_a,
                asset_id,
                settled=950,
                future=950,
                spendable=950,
                offchain_outbound=0,
                offchain_inbound=0,
                timeout_sec=60,
            )
            wait_for_asset_balance(
                node_b,
                asset_id,
                settled=50,
                future=50,
                spendable=50,
                offchain_outbound=0,
                offchain_inbound=0,
                timeout_sec=60,
            )
        else:
            run_regtest("mine", "12")
            wait_for_asset_balance(
                node_a,
                asset_id,
                settled=950,
                future=950,
                spendable=950,
                offchain_outbound=0,
                offchain_inbound=0,
                timeout_sec=120,
            )
            wait_for_asset_balance(
                node_b,
                asset_id,
                settled=50,
                future=50,
                spendable=50,
                offchain_outbound=0,
                offchain_inbound=0,
                timeout_sec=120,
            )
        print(f"{'force' if force else 'coop'} close RGB settlement succeeded")
    finally:
        if node_a is not None:
            try:
                node_a.shutdown()
            except Exception:
                pass
        if node_b is not None:
            try:
                node_b.shutdown()
            except Exception:
                pass


def run_connection_loss_restore_real():
    ensure_regtest_available()
    data_root = REPO_ROOT / "target" / "uniffi" / "python-e2e" / "external-real-loss"
    node_a_dir = data_root / "node_a"
    node_b_dir = data_root / "node_b"
    signer_dir = data_root / "signer_a"
    ensure_dir(node_a_dir)
    ensure_dir(node_b_dir)
    signer = make_native_signer(signer_dir, reset=True)
    bootstrap = signer.bootstrap()

    node_a_daemon_port = find_free_port()
    node_b_daemon_port = find_free_port()
    node_a_peer_port = find_free_port()
    node_b_peer_port = find_free_port()

    node_a = make_node(node_a_dir, node_a_daemon_port, node_a_peer_port)
    node_b = make_node(node_b_dir, node_b_daemon_port, node_b_peer_port)
    try:
        node_a.init_with_native_external_signer(signer)
        node_a.unlock_with_native_external_signer(
            signer,
            "user",
            "password",
            "localhost",
            18443,
            "127.0.0.1:50001",
            PROXY_ENDPOINT_LOCAL,
            [],
            "RLN_external_py",
        )
        node_b.init(NODE_B_PASSWORD, None)
        node_b.unlock(unlock_request(NODE_B_PASSWORD))

        ensure_funded(node_a, 300_000)
        ensure_funded(node_b, 100_000)
        create_utxos_if_possible(node_b)

        peer_uri = f"{node_b.node_info().pubkey}@127.0.0.1:{node_b_peer_port}"
        try:
            node_a.connectpeer(peer_uri)
        except rln.RlnError.Conflict:
            pass

        node_a.openchannel(
            rln.SdkOpenChannelRequest(
                peer_pubkey_and_opt_addr=peer_uri,
                capacity_sat=OPEN_CHANNEL_CAPACITY_SAT,
                push_msat=0,
                public=False,
                with_anchors=True,
                fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id=None,
                asset_amount=None,
                push_asset_amount=None,
                virtual_open_mode=None,
            )
        )
        txid = wait_for_channel_funding_tx(node_a)
        mine_until_tx_confirmed(node_a, txid)
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        wait_for_usable_channels(
            [(node_a, 1), (node_b, 1)], timeout_sec=CHANNEL_READY_TIMEOUT_SEC
        )

        inv_1 = node_b.ln_invoice(
            rln.LnInvoiceRequest(
                amt_msat=PAYMENT_MSAT,
                expiry_sec=900,
                asset_id=None,
                asset_amount=None,
                payment_hash=None,
                description_hash=None,
                            min_final_cltv_expiry_delta=None,
)
        ).invoice
        send_1 = node_a.sendpayment(
            rln.SdkSendPaymentRequest(
                invoice=str(inv_1),
                amt_msat=None,
                asset_id=None,
                asset_amount=None,
            )
        )
        if send_1.payment_hash is None:
            raise RuntimeError("sendpayment did not return payment_hash")
        wait_for_payment_succeeded(node_a, send_1.payment_hash, peer_node=node_b)
        wait_for_payment_succeeded(node_b, send_1.payment_hash, peer_node=node_a)
        print("payment #1 succeeded before signer outage")

        node_a.shutdown()
        time.sleep(0.5)
        node_a = make_node(node_a_dir, node_a_daemon_port, node_a_peer_port)
        try:
            unlock_with_attached_signer(node_a)
            raise RuntimeError("expected unlock failure while signer unavailable")
        except Exception as e:
            print("expected signer-unavailable failure:", str(e))

        # Reattach the same in-process signer instance (do not recreate it) for the same reason
        # as in `regular-flow-real`: the in-memory VLS transport does not persist enforcement state.
        node_a.attach_native_external_signer(signer)
        unlock_with_attached_signer(node_a)
        wait_for_usable_channels([(node_a, 1), (node_b, 1)])

        inv_2 = node_b.ln_invoice(
            rln.LnInvoiceRequest(
                amt_msat=PAYMENT_MSAT,
                expiry_sec=900,
                asset_id=None,
                asset_amount=None,
                payment_hash=None,
                description_hash=None,
                            min_final_cltv_expiry_delta=None,
)
        ).invoice
        send_2 = node_a.sendpayment(
            rln.SdkSendPaymentRequest(
                invoice=str(inv_2),
                amt_msat=None,
                asset_id=None,
                asset_amount=None,
            )
        )
        if send_2.payment_hash is None:
            raise RuntimeError("sendpayment did not return payment_hash after recovery")
        wait_for_payment_succeeded(node_a, send_2.payment_hash, peer_node=node_b)
        wait_for_payment_succeeded(node_b, send_2.payment_hash, peer_node=node_a)
        print("payment #2 succeeded after signer recovery")
    finally:
        try:
            node_a.shutdown()
        except Exception:
            pass
        try:
            node_b.shutdown()
        except Exception:
            pass


def run_restart_with_mismatched_signer_real():
    ensure_regtest_available()
    data_root = REPO_ROOT / "target" / "uniffi" / "python-e2e" / "external-real-mismatch"
    node_dir = data_root / "node_a"
    signer_a_dir = data_root / "signer_a"
    signer_b_dir = data_root / "signer_b"
    ensure_dir(node_dir)
    signer_a = make_native_signer_with_dir(signer_a_dir, reset=True)
    signer_b = make_native_signer_with_dir(signer_b_dir, reset=True)

    node_daemon_port = find_free_port()
    node_peer_port = find_free_port()

    node = make_node(node_dir, node_daemon_port, node_peer_port)
    try:
        node.init_with_native_external_signer(signer_a)
        node.unlock_with_native_external_signer(
            signer_a,
            "user",
            "password",
            "localhost",
            18443,
            "127.0.0.1:50001",
            PROXY_ENDPOINT_LOCAL,
            [],
            "RLN_external_py",
        )
        info = node.node_info()
        print("initial unlock succeeded for node id:", info.pubkey)
        node.shutdown()
    finally:
        try:
            node.shutdown()
        except Exception:
            pass

    time.sleep(0.5)
    restarted = make_node(node_dir, node_daemon_port, node_peer_port)
    try:
        try:
            restarted.unlock_with_native_external_signer(
                signer_b,
                "user",
                "password",
                "localhost",
                18443,
                "127.0.0.1:50001",
                PROXY_ENDPOINT_LOCAL,
                [],
                "RLN_external_py",
            )
            raise RuntimeError("expected mismatched signer unlock to fail")
        except Exception as e:
            msg = str(e).lower()
            if "mismatch" not in msg and "conflict" not in msg:
                raise RuntimeError(f"unexpected mismatched signer error: {e}") from e
            print("mismatched signer unlock failed as expected:", str(e))
    finally:
        try:
            restarted.shutdown()
        except Exception:
            pass
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python UniFFI external signer E2E scenarios"
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "regular-flow-real",
            "mixed-asset-channel-real",
            "mixed-asset-channel-roundtrip-real",
            "mixed-asset-channel-coop-close-real",
            "mixed-asset-channel-force-close-real",
            "restart-mismatch-real",
            "connection-loss-real",
        ],
        default=os.getenv("PY_EXT_SIGNER_SCENARIO", "regular-flow-real"),
        help="which scenario to run",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.scenario == "regular-flow-real":
        run_regular_channel_flow_external_real()
    elif args.scenario == "mixed-asset-channel-real":
        run_mixed_asset_channel_internal_external_real()
    elif args.scenario == "mixed-asset-channel-roundtrip-real":
        run_mixed_asset_channel_roundtrip_real()
    elif args.scenario == "mixed-asset-channel-coop-close-real":
        run_mixed_asset_channel_close_settlement_real(False)
    elif args.scenario == "mixed-asset-channel-force-close-real":
        run_mixed_asset_channel_close_settlement_real(True)
    elif args.scenario == "restart-mismatch-real":
        run_restart_with_mismatched_signer_real()
    elif args.scenario == "connection-loss-real":
        run_connection_loss_restore_real()
    else:
        raise RuntimeError(f"unsupported scenario: {args.scenario}")


if __name__ == "__main__":
    main()
