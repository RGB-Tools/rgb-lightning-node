#!/usr/bin/env python3
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import rgb_lightning_node as rln

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_ROOT = REPO_ROOT / "target" / "uniffi" / "python-e2e"

NODE_A_DAEMON_PORT = int(os.getenv("NODE_A_DAEMON_PORT", "3611"))
NODE_B_DAEMON_PORT = int(os.getenv("NODE_B_DAEMON_PORT", "3612"))
NODE_C_DAEMON_PORT = int(os.getenv("NODE_C_DAEMON_PORT", "3613"))
NODE_A_PEER_PORT = int(os.getenv("NODE_A_PEER_PORT", "12111"))
NODE_B_PEER_PORT = int(os.getenv("NODE_B_PEER_PORT", "12112"))
NODE_C_PEER_PORT = int(os.getenv("NODE_C_PEER_PORT", "12113"))

NODE_A_PASSWORD = os.getenv("NODE_A_PASSWORD", "nodeApass")
NODE_B_PASSWORD = os.getenv("NODE_B_PASSWORD", "nodeBpass")
NODE_C_PASSWORD = os.getenv("NODE_C_PASSWORD", "nodeCpass")

OPEN_CHANNEL_CAPACITY_SAT = int(os.getenv("OPEN_CHANNEL_CAPACITY_SAT", "500000"))
OPEN_CHANNEL_PUSH_MSAT = int(os.getenv("OPEN_CHANNEL_PUSH_MSAT", "0"))
PAYMENT_MSAT = int(os.getenv("PAYMENT_MSAT", "3000000"))
CREATE_UTXOS_NUM = int(os.getenv("CREATE_UTXOS_NUM", "10"))
CREATE_UTXOS_SIZE_SAT = int(os.getenv("CREATE_UTXOS_SIZE_SAT", "100000"))
CREATE_UTXOS_FEE_RATE = int(os.getenv("CREATE_UTXOS_FEE_RATE", "1"))
ISSUE_ASSET_TICKER = os.getenv("ISSUE_ASSET_TICKER", "USDT")
ISSUE_ASSET_NAME = os.getenv("ISSUE_ASSET_NAME", "Tether")
ISSUE_ASSET_PRECISION = int(os.getenv("ISSUE_ASSET_PRECISION", "0"))
ISSUE_ASSET_SUPPLY = int(os.getenv("ISSUE_ASSET_SUPPLY", "1000"))
OPEN_CHANNEL_ASSET_AMOUNT = int(os.getenv("OPEN_CHANNEL_ASSET_AMOUNT", "200"))
PAYMENT_ASSET_AMOUNT = int(os.getenv("PAYMENT_ASSET_AMOUNT", "50"))
OPEN_CHANNEL_CONFIRM_BLOCKS = 6
CHANNEL_READY_TIMEOUT_SEC = int(os.getenv("CHANNEL_READY_TIMEOUT_SEC", "300"))
RESET_DATA = os.getenv("RESET_DATA", "1") == "1"
SCENARIO = os.getenv("PYTHON_E2E_SCENARIO", "payment")

ALL_SCENARIOS = [
    "payment",
    "openchannel_push_asset_amount",
    "getchannelid_fail",
    "openchannel_fail_no_utxos",
    "openchannel_fail_unknown_asset",
]

RGB_MIN_HTLC_MSAT = 3_000_000
PROXY_ENDPOINT_LOCAL = "rpc://127.0.0.1:3000/json-rpc"


def scenario_storage(scenario: str, node_name: str) -> Path:
    return E2E_ROOT / "data" / scenario / node_name


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


def ensure_dir(path: Path):
    if RESET_DATA and path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def make_node(storage_dir: Path, daemon_port: int, peer_port: int) -> rln.SdkNode:
    req = rln.SdkInitRequest(
        storage_dir_path=str(storage_dir),
        daemon_listening_port=daemon_port,
        ldk_peer_listening_port=peer_port,
        network="regtest",
        max_media_upload_size_mb=20,
        enable_virtual_channels_v0=False,
        virtual_peer_pubkeys=None,
    )
    return rln.SdkNode.create(req)


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


def init_if_needed(node: rln.SdkNode, password: str, name: str):
    try:
        mnemonic = node.init(password, None)
        print(f"{name}: initialized")
        print(f"{name}: mnemonic[0..20]={mnemonic[:20]}...")
    except rln.RlnError.Conflict:
        print(f"{name}: already initialized")


def unlock_if_needed(node: rln.SdkNode, password: str, name: str):
    unlock_state = "unlocked"
    try:
        node.unlock(unlock_request(password))
    except rln.RlnError.Conflict:
        unlock_state = "already unlocked"
    try:
        node.node_info()
    except rln.RlnError.NotInitialized as err:
        raise RuntimeError(
            f"{name}: unlock did not leave node usable (state={unlock_state})"
        ) from err
    else:
        print(f"{name}: {unlock_state}")


def create_utxos(
    node: rln.SdkNode,
    name: str,
    num: int | None = None,
    size: int | None = None,
    fee_rate: int | None = None,
):
    req = rln.SdkCreateUtxosRequest(
        up_to=False,
        num=CREATE_UTXOS_NUM if num is None else num,
        size=CREATE_UTXOS_SIZE_SAT if size is None else size,
        fee_rate=CREATE_UTXOS_FEE_RATE if fee_rate is None else fee_rate,
        skip_sync=False,
    )
    node.createutxos(req)
    print(f"{name}: createutxos done")


def issue_asset_nia(node: rln.SdkNode, name: str):
    req = rln.SdkIssueAssetNiaRequest(
        amounts=[ISSUE_ASSET_SUPPLY],
        ticker=ISSUE_ASSET_TICKER,
        name=ISSUE_ASSET_NAME,
        precision=ISSUE_ASSET_PRECISION,
    )
    asset = node.issueassetnia(req)
    print(f"{name}: issued NIA asset_id={asset.asset_id}")
    return asset.asset_id


def ensure_funded_with_amount(
    node: rln.SdkNode,
    name: str,
    min_spendable_sat: int,
    amount_btc: str,
):
    spendable = node.btc_balance(False).vanilla.spendable
    print(f"{name} spendable sats: {spendable}")
    if spendable >= min_spendable_sat:
        return

    address = node.address().address
    print(f"Funding {name} address {address} with {amount_btc} BTC on regtest")
    run_regtest("sendtoaddress", address, amount_btc)
    run_regtest("mine", "6")
    node.sync()

    spendable_after = node.btc_balance(False).vanilla.spendable
    print(f"{name} spendable sats after funding: {spendable_after}")
    if spendable_after < min_spendable_sat:
        raise RuntimeError(
            f"{name} spendable balance still too low: {spendable_after} < {min_spendable_sat}"
        )


def fund_and_create_utxos(
    node: rln.SdkNode,
    name: str,
    num: int | None = None,
    amount_btc: str = "1",
):
    ensure_funded_with_amount(node, name, 1, amount_btc)
    create_utxos(node, name, num=num, size=None, fee_rate=7)
    run_regtest("mine", "1")
    node.sync()


def asset_balance_spendable(node: rln.SdkNode, asset_id) -> int:
    return node.asset_balance(asset_id).spendable


def asset_balance_offchain_outbound(node: rln.SdkNode, asset_id) -> int:
    return node.asset_balance(asset_id).offchain_outbound


def channel_matches_asset(channel_asset_id, expected_asset_id) -> bool:
    if expected_asset_id is None:
        return channel_asset_id is None
    return str(channel_asset_id) == str(expected_asset_id)


def wait_for_channel_funding_tx(
    node_a: rln.SdkNode,
    node_b: rln.SdkNode,
    asset_id,
    timeout_sec: int = 120,
):
    deadline = time.time() + timeout_sec
    last = "no channels"
    while time.time() < deadline:
        node_a.sync()
        node_b.sync()
        channels = node_a.list_channels()
        last = ", ".join(
            f"id={c.channel_id},asset={c.asset_id},funding={c.funding_txid},usable={c.is_usable}"
            for c in channels
        ) or "no channels"

        opening = next(
            (
                c
                for c in channels
                if channel_matches_asset(c.asset_id, asset_id) and c.funding_txid is not None
            ),
            None,
        )
        if opening is not None:
            print(f"channel funding tx found: {opening.funding_txid}")
            return str(opening.funding_txid)

        print("waiting for channel funding tx broadcast...")
        time.sleep(1)

    raise RuntimeError(
        f"No funding tx after {timeout_sec}s for asset_id={asset_id}; last_channels={last}"
    )


def mine_until_tx_confirmed(
    node: rln.SdkNode,
    txid: str,
    timeout_sec: int = 180,
):
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        node.sync()
        transactions = node.list_transactions(False)
        tx = next((t for t in transactions if str(t.txid) == str(txid)), None)
        if tx is not None and tx.confirmation_time is not None:
            print(f"funding tx confirmed in block: {txid}")
            return
        print("waiting for funding tx to be included in a block...")
        run_regtest("mine", "1")
        time.sleep(1)
    raise RuntimeError(f"funding tx was not confirmed before timeout: txid={txid}")


def wait_for_usable_channel(
    node_a: rln.SdkNode,
    node_b: rln.SdkNode,
    asset_id,
    timeout_sec: int = 120,
    mine_every_polls: int = 5,
):
    deadline = time.time() + timeout_sec
    polls = 0
    last = "no channels"
    while time.time() < deadline:
        polls += 1
        node_a.sync()
        node_b.sync()
        channels = node_a.list_channels()
        last = ", ".join(
            f"id={c.channel_id},asset={c.asset_id},ready={c.ready},usable={c.is_usable}"
            for c in channels
        ) or "no channels"

        ready = any(
            c.is_usable and channel_matches_asset(c.asset_id, asset_id) for c in channels
        )
        if ready:
            return

        if mine_every_polls > 0 and polls % mine_every_polls == 0:
            print("channel not usable yet, mining 1 block...")
            run_regtest("mine", "1")
        print("waiting for usable channel...")
        time.sleep(2)

    raise RuntimeError(
        f"No usable channel after {timeout_sec}s for asset_id={asset_id}; last_channels={last}"
    )


def wait_for_channel_ready(
    node: rln.SdkNode,
    channel_id,
    timeout_sec: int = 10,
):
    deadline = time.time() + timeout_sec
    last = "channel not found"
    while time.time() < deadline:
        node.sync()
        channel = next((c for c in node.list_channels() if c.channel_id == channel_id), None)
        if channel is not None:
            last = (
                f"id={channel.channel_id},status={channel.status},ready={channel.ready},"
                f"usable={channel.is_usable},funding={channel.funding_txid},"
                f"short_channel_id={channel.short_channel_id}"
            )
            if channel.ready:
                return
        time.sleep(1)
    raise RuntimeError(
        f"channel did not become ready after {timeout_sec}s: channel_id={channel_id} last={last}"
    )


def wait_for_channel_id(
    node: rln.SdkNode,
    temporary_channel_id,
    timeout_sec: int = 10,
):
    deadline = time.time() + timeout_sec
    last = "mapping not found"
    while time.time() < deadline:
        try:
            return node.get_channel_id(temporary_channel_id)
        except rln.RlnError.NotFound:
            node.sync()
            channels = node.list_channels()
            last = ", ".join(
                f"id={c.channel_id},status={c.status},ready={c.ready},usable={c.is_usable},funding={c.funding_txid}"
                for c in channels
            ) or "no channels"
            time.sleep(1)
    raise RuntimeError(
        "temporary_channel_id did not resolve to channel_id after "
        f"{timeout_sec}s: temporary_channel_id={temporary_channel_id} last_channels={last}"
    )


def wait_payment_final(node: rln.SdkNode, invoice: str, timeout_sec: int = 60):
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        node.sync()
        status = node.invoice_status(invoice)
        last = status
        if status in (
            rln.InvoiceStatus.SUCCEEDED,
            rln.InvoiceStatus.FAILED,
            rln.InvoiceStatus.EXPIRED,
        ):
            return status
        time.sleep(1)
    raise RuntimeError(
        f"Invoice did not finalize after {timeout_sec}s, last={last}"
    )


def wait_for_balance(node: rln.SdkNode, asset_id, expected: int, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last_balance = 0
    while time.time() < deadline:
        balance = asset_balance_spendable(node, asset_id)
        last_balance = balance
        if balance == expected:
            return
        node.refreshtransfers(rln.SdkRefreshTransfersRequest(skip_sync=False))
        time.sleep(1)
    raise RuntimeError(
        f"spendable balance did not become expected={expected} actual={last_balance} asset_id={asset_id} after {timeout_sec}s"
    )


def wait_for_ln_balance(node: rln.SdkNode, asset_id, expected: int, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last_balance = 0
    while time.time() < deadline:
        balance = asset_balance_offchain_outbound(node, asset_id)
        last_balance = balance
        if balance == expected:
            return
        time.sleep(1)
    raise RuntimeError(
        f"offchain_outbound balance did not become expected={expected} actual={last_balance} asset_id={asset_id} after {timeout_sec}s"
    )


def wait_for_payment_status(
    node: rln.SdkNode,
    payment_hash,
    timeout_sec: int,
):
    deadline = time.time() + timeout_sec
    last_status = "not found"
    while time.time() < deadline:
        try:
            payment = node.get_payment(payment_hash)
            last_status = payment.status.name
            if payment.status == rln.HtlcStatus.SUCCEEDED:
                return payment
        except rln.RlnError.NotFound:
            last_status = "not found"
        time.sleep(1)
    raise RuntimeError(
        f"timeout waiting for payment success: payment_hash={payment_hash} last_status={last_status} after {timeout_sec}s"
    )


def wait_for_payment_present_in_list(node: rln.SdkNode, payment_hash, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last_count = 0
    while time.time() < deadline:
        payments = node.list_payments()
        last_count = len(payments)
        payment = next((p for p in payments if p.payment_hash == payment_hash), None)
        if payment is not None:
            return payment
        time.sleep(1)
    raise RuntimeError(
        f"payment not found in list_payments: payment_hash={payment_hash} list_size={last_count} after {timeout_sec}s"
    )


def check_preimage_matches_hash(payment: rln.Payment, expected_payment_hash):
    if payment.preimage is None:
        raise RuntimeError("payment preimage is null")
    payment_preimage_hash = hashlib.sha256(bytes.fromhex(payment.preimage)).hexdigest()
    if payment_preimage_hash != expected_payment_hash:
        raise RuntimeError(
            f"payment preimage hash mismatch: expected={expected_payment_hash} actual={payment_preimage_hash}"
        )


def wait_for_usable_channels(node: rln.SdkNode, expected_count: int, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last_usable = -1
    while time.time() < deadline:
        node.sync()
        usable = sum(1 for c in node.list_channels() if c.ready and c.is_usable)
        last_usable = usable
        if usable == expected_count:
            return
        time.sleep(1)
    raise RuntimeError(
        f"usable channel count did not become expected={expected_count} actual={last_usable} after {timeout_sec}s"
    )


def wait_for_peer(node: rln.SdkNode, peer_pubkey, timeout_sec: int):
    expected = str(peer_pubkey)
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if any(str(peer.pubkey) == expected for peer in node.list_peers()):
            return
        print(f"waiting for peer connection: {expected}")
        time.sleep(1)
    raise RuntimeError(
        f"peer did not appear in list_peers() after {timeout_sec}s: peer={expected}"
    )


def keysend(sender: rln.SdkNode, dest_pubkey: str, amt_msat, asset_id, asset_amount):
    response = sender.keysend(
        rln.SdkKeysendRequest(
            dest_pubkey=dest_pubkey,
            amt_msat=PAYMENT_MSAT if amt_msat is None else amt_msat,
            asset_id=asset_id,
            asset_amount=asset_amount,
        )
    )
    if response.status not in (rln.HtlcStatus.PENDING, rln.HtlcStatus.SUCCEEDED):
        raise RuntimeError(f"unexpected keysend status: {response.status}")
    wait_for_payment_status(sender, response.payment_hash, 60)
    return response.payment_hash


def keysend_with_ln_balance(
    sender: rln.SdkNode,
    receiver: rln.SdkNode,
    dest_pubkey: str,
    amt_msat,
    asset_id,
    asset_amount: int,
    initial_sender_balance: int,
    initial_receiver_balance: int,
):
    payment_hash = keysend(sender, dest_pubkey, amt_msat, asset_id, asset_amount)
    wait_for_ln_balance(sender, asset_id, initial_sender_balance - asset_amount, 60)
    wait_for_ln_balance(receiver, asset_id, initial_receiver_balance + asset_amount, 60)
    wait_for_payment_status(receiver, payment_hash, 60)


def close_channel(node: rln.SdkNode, channel_id: str, peer_pubkey: str, force: bool = False):
    node.closechannel(
        rln.SdkCloseChannelRequest(
            channel_id=channel_id,
            peer_pubkey=peer_pubkey,
            force=force,
        )
    )
    deadline = time.time() + 30
    last_channels = "no channels"
    while time.time() < deadline:
        channels = node.list_channels()
        last_channels = ", ".join(str(c.channel_id) for c in channels) or "no channels"
        if all(str(c.channel_id) != str(channel_id) for c in channels):
            run_regtest("mine", "144" if force else "6")
            return
        time.sleep(1)
    raise RuntimeError(
        f"channel did not close in time: channel_id={channel_id} remaining_channels={last_channels}"
    )


def refresh_transfers(node: rln.SdkNode):
    node.refreshtransfers(rln.SdkRefreshTransfersRequest(skip_sync=False))


def rgb_invoice(node: rln.SdkNode):
    return node.rgbinvoice(
        rln.SdkRgbInvoiceRequest(
            asset_id=None,
            assignment_kind=None,
            assignment_amount=None,
            duration_seconds=None,
            min_confirmations=1,
            witness=False,
        )
    ).recipient_id


def safe_shutdown(node):
    try:
        if node is not None:
            node.shutdown()
    except Exception:
        pass


def getchannelid_fail_scenario():
    node_a_storage = scenario_storage("getchannelid_fail", "node_a")

    print("Python UniFFI getchannelid_fail flow")
    print(f"node A storage: {node_a_storage}")

    ensure_dir(node_a_storage)

    node_a = None
    try:
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + 200, NODE_A_PEER_PORT + 200)

        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")

        print("getting channel ID for an odd temporary one")
        try:
            node_a.get_channel_id("odd")
            raise RuntimeError("get_channel_id should fail for odd temporary channel id")
        except rln.RlnError.InvalidRequest:
            pass

        print("getting channel ID for a short temporary one")
        try:
            node_a.get_channel_id("0123456789abcdef")
            raise RuntimeError("get_channel_id should fail for short temporary channel id")
        except rln.RlnError.InvalidRequest:
            pass

        print("getting channel ID for an unknown temporary one")
        try:
            node_a.get_channel_id(
                "0011223344556677889900112233445566778899001122334455667788990011"
            )
            raise RuntimeError("get_channel_id should fail for unknown temporary channel id")
        except rln.RlnError.NotFound:
            pass

        print("SUCCESS: Python getchannelid_fail completed")
    finally:
        safe_shutdown(node_a)


def openchannel_fail_no_utxos_scenario():
    scenario = "openchannel_fail_no_utxos"
    node_a_storage = scenario_storage(scenario, "node_a")
    node_b_storage = scenario_storage(scenario, "node_b")

    print("Python UniFFI openchannel_fail_no_utxos flow")
    print(f"node A storage: {node_a_storage}")
    print(f"node B storage: {node_b_storage}")

    ensure_dir(node_a_storage)
    ensure_dir(node_b_storage)

    node_a = None
    node_b = None
    try:
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + 220, NODE_A_PEER_PORT + 220)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + 220, NODE_B_PEER_PORT + 220)

        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")
        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")

        fund_and_create_utxos(node_a, "node A", num=1)
        fund_and_create_utxos(node_b, "node B")

        asset_id = issue_asset_nia(node_a, "node A")
        node_b_pubkey = node_b.node_info().pubkey
        peer_uri = f"{node_b_pubkey}@127.0.0.1:{NODE_B_PEER_PORT + 220}"

        print("opening RGB channel with insufficient allocation slots")
        try:
            node_a.openchannel(
                rln.SdkOpenChannelRequest(
                    peer_pubkey_and_opt_addr=peer_uri,
                    capacity_sat=100_000,
                    push_msat=3_500_000,
                    public=True,
                    with_anchors=True,
                    fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id=asset_id,
                asset_amount=100,
                push_asset_amount=None,
                virtual_open_mode=None,
            )
        )
            raise RuntimeError("openchannel should fail when no uncolored UTXOs are available")
        except rln.RlnError.Conflict:
            pass

        assert len(node_a.list_channels()) == 0
        assert len(node_b.list_channels()) == 0

        print("SUCCESS: Python openchannel_fail_no_utxos completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)


def openchannel_fail_unknown_asset_scenario():
    scenario = "openchannel_fail_unknown_asset"
    node_a_storage = scenario_storage(scenario, "node_a")
    node_b_storage = scenario_storage(scenario, "node_b")

    print("Python UniFFI openchannel_fail_unknown_asset flow")
    print(f"node A storage: {node_a_storage}")
    print(f"node B storage: {node_b_storage}")

    ensure_dir(node_a_storage)
    ensure_dir(node_b_storage)

    node_a = None
    node_b = None
    try:
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + 230, NODE_A_PEER_PORT + 230)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + 230, NODE_B_PEER_PORT + 230)

        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")
        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")

        fund_and_create_utxos(node_a, "node A")
        fund_and_create_utxos(node_b, "node B")

        issue_asset_nia(node_a, "node A")
        node_b_pubkey = node_b.node_info().pubkey
        peer_uri = f"{node_b_pubkey}@127.0.0.1:{NODE_B_PEER_PORT + 230}"

        print("opening RGB channel with unknown asset id")
        try:
            node_a.openchannel(
                rln.SdkOpenChannelRequest(
                    peer_pubkey_and_opt_addr=peer_uri,
                    capacity_sat=100_000,
                    push_msat=3_500_000,
                    public=True,
                    with_anchors=True,
                    fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id="rgb:EIkAVQvq-WbAb5JG-CYxbUER-oqDNwne-ZNxBDID-p0cpf9U",
                asset_amount=100,
                push_asset_amount=None,
                virtual_open_mode=None,
            )
        )
            raise RuntimeError("openchannel should fail for unknown asset id")
        except rln.RlnError.NotFound:
            pass

        assert len(node_a.list_channels()) == 0
        assert len(node_b.list_channels()) == 0

        print("SUCCESS: Python openchannel_fail_unknown_asset completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)


def payment_scenario():
    node_a_storage = scenario_storage("payment", "node_a")
    node_b_storage = scenario_storage("payment", "node_b")

    print("Python UniFFI N2N payment flow")
    print(f"node A storage: {node_a_storage}")
    print(f"node B storage: {node_b_storage}")

    ensure_dir(node_a_storage)
    ensure_dir(node_b_storage)

    node_a = None
    node_b = None
    try:
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT, NODE_A_PEER_PORT)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT, NODE_B_PEER_PORT)

        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")
        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")

        ensure_funded_with_amount(
            node_a, "node A", OPEN_CHANNEL_CAPACITY_SAT + 200_000, "0.02"
        )
        ensure_funded_with_amount(node_b, "node B", 200_000, "0.02")

        create_utxos(node_a, "node A")
        create_utxos(node_b, "node B")
        run_regtest("mine", "1")
        node_a.sync()
        node_b.sync()

        asset_id = issue_asset_nia(node_a, "node A")

        info_a = node_a.node_info()
        info_b = node_b.node_info()
        print(f"node A pubkey: {info_a.pubkey}")
        print(f"node B pubkey: {info_b.pubkey}")

        peer_uri = f"{info_b.pubkey}@127.0.0.1:{NODE_B_PEER_PORT}"
        try:
            node_a.connectpeer(peer_uri)
            print("connectpeer: ok")
        except rln.RlnError.Conflict:
            print("connectpeer: already connected")
        wait_for_peer(node_a, info_b.pubkey, 20)

        open_response = node_a.openchannel(
            rln.SdkOpenChannelRequest(
                peer_pubkey_and_opt_addr=peer_uri,
                capacity_sat=OPEN_CHANNEL_CAPACITY_SAT,
                push_msat=OPEN_CHANNEL_PUSH_MSAT,
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
        print(f"openchannel temporary_channel_id: {open_response.temporary_channel_id}")

        funding_txid = wait_for_channel_funding_tx(node_a, node_b, asset_id, 120)
        print("Mining blocks one by one until funding tx is confirmed...")
        mine_until_tx_confirmed(node_a, funding_txid, 180)
        print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        channel_id = node_a.get_channel_id(open_response.temporary_channel_id)
        wait_for_channel_ready(node_a, channel_id, 10)
        wait_for_usable_channel(node_a, node_b, asset_id, CHANNEL_READY_TIMEOUT_SEC, 5)
        print("Channel is usable")

        print(f"node A channels: {len(node_a.list_channels())}")
        print(f"node B channels: {len(node_b.list_channels())}")

        if PAYMENT_MSAT < RGB_MIN_HTLC_MSAT:
            raise RuntimeError(
                f"PAYMENT_MSAT={PAYMENT_MSAT} is too low for RGB invoices, must be >= {RGB_MIN_HTLC_MSAT}"
            )

        invoice = node_b.ln_invoice(
            rln.LnInvoiceRequest(
                amt_msat=PAYMENT_MSAT,
                expiry_sec=3600,
                asset_id=asset_id,
                asset_amount=PAYMENT_ASSET_AMOUNT,
                description_hash=None,
                payment_hash=None,
            )
        ).invoice
        print(f"invoice: {invoice}")

        payment_response = node_a.sendpayment(
            rln.SdkSendPaymentRequest(
                invoice=invoice,
                amt_msat=None,
                asset_id=None,
                asset_amount=None,
            )
        )
        print(f"sendpayment status: {payment_response.status.name}")
        print(f"sendpayment payment_id: {payment_response.payment_id}")

        final_status = wait_payment_final(node_b, invoice)
        print(f"invoice final status on node B: {final_status.name}")
        if final_status != rln.InvoiceStatus.SUCCEEDED:
            raise RuntimeError(f"Payment did not succeed (status={final_status})")

        decoded = node_a.decode_ln_invoice(invoice)
        sender_payment = wait_for_payment_status(node_a, decoded.payment_hash, 60)
        receiver_payment = wait_for_payment_status(node_b, decoded.payment_hash, 60)
        check_preimage_matches_hash(sender_payment, decoded.payment_hash)
        check_preimage_matches_hash(receiver_payment, decoded.payment_hash)

        listed_sender_payment = wait_for_payment_present_in_list(
            node_a, decoded.payment_hash, 60
        )
        if listed_sender_payment.payment_hash != decoded.payment_hash:
            raise RuntimeError("sender payment hash mismatch in list_payments")
        check_preimage_matches_hash(listed_sender_payment, decoded.payment_hash)

        listed_receiver_payment = wait_for_payment_present_in_list(
            node_b, decoded.payment_hash, 60
        )
        if listed_receiver_payment.payment_hash != decoded.payment_hash:
            raise RuntimeError("receiver payment hash mismatch in list_payments")
        check_preimage_matches_hash(listed_receiver_payment, decoded.payment_hash)

        print("SUCCESS: Python SDK-only node-to-node payment completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)


def openchannel_push_asset_amount_scenario():
    scenario = "openchannel_push_asset_amount"
    node_a_storage = scenario_storage(scenario, "node_a")
    node_b_storage = scenario_storage(scenario, "node_b")
    node_c_storage = scenario_storage(scenario, "node_c")
    daemon_offset = 40
    peer_offset = 40
    channel_capacity = 100_000

    print("Python UniFFI openchannel_push_asset_amount flow")
    print(f"node A storage: {node_a_storage}")
    print(f"node B storage: {node_b_storage}")
    print(f"node C storage: {node_c_storage}")

    ensure_dir(node_a_storage)
    ensure_dir(node_b_storage)
    ensure_dir(node_c_storage)

    node_a = None
    node_b = None
    node_c = None
    try:
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + daemon_offset, NODE_A_PEER_PORT + peer_offset)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + daemon_offset, NODE_B_PEER_PORT + peer_offset)
        node_c = make_node(node_c_storage, NODE_C_DAEMON_PORT + daemon_offset, NODE_C_PEER_PORT + peer_offset)

        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")
        init_if_needed(node_c, NODE_C_PASSWORD, "node C")
        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")
        unlock_if_needed(node_c, NODE_C_PASSWORD, "node C")

        node_a_pubkey = node_a.node_info().pubkey
        node_b_pubkey = node_b.node_info().pubkey

        fund_and_create_utxos(node_a, "node A")
        fund_and_create_utxos(node_b, "node B")
        fund_and_create_utxos(node_c, "node C")

        asset_id = issue_asset_nia(node_a, "node A")
        peer_uri = f"{node_b_pubkey}@127.0.0.1:{NODE_B_PEER_PORT + peer_offset}"
        node_a.connectpeer(peer_uri)
        wait_for_peer(node_a, node_b_pubkey, 20)

        partial_push_channel = node_a.openchannel(
            rln.SdkOpenChannelRequest(
                peer_pubkey_and_opt_addr=peer_uri,
                capacity_sat=channel_capacity,
                push_msat=0,
                public=True,
                with_anchors=True,
                fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id=asset_id,
                asset_amount=600,
                push_asset_amount=250,
                virtual_open_mode=None,
            )
        )

        funding_txid = wait_for_channel_funding_tx(node_a, node_b, asset_id, 120)
        print("Mining blocks one by one until funding tx is confirmed...")
        mine_until_tx_confirmed(node_a, funding_txid, 180)
        print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        partial_channel_id = wait_for_channel_id(
            node_a, partial_push_channel.temporary_channel_id, 10
        )
        wait_for_channel_ready(node_a, partial_channel_id, 60)
        node_a_partial = next(c for c in node_a.list_channels() if c.channel_id == partial_channel_id)
        node_b_partial = next(c for c in node_b.list_channels() if c.channel_id == partial_channel_id)
        assert node_a_partial.asset_local_amount == 350 and node_a_partial.asset_remote_amount == 250
        assert node_b_partial.asset_local_amount == 250 and node_b_partial.asset_remote_amount == 350

        keysend_with_ln_balance(node_a, node_b, node_b_pubkey, None, asset_id, 100, 350, 250)
        btc_payment_hash = keysend(node_a, node_b_pubkey, 10_000_000, None, None)
        wait_for_payment_status(node_b, btc_payment_hash, 60)
        keysend_with_ln_balance(node_b, node_a, node_a_pubkey, None, asset_id, 50, 350, 250)

        node_a_partial_after = next(c for c in node_a.list_channels() if c.channel_id == partial_channel_id)
        node_b_partial_after = next(c for c in node_b.list_channels() if c.channel_id == partial_channel_id)
        assert node_a_partial_after.asset_local_amount == 300 and node_a_partial_after.asset_remote_amount == 300
        assert node_b_partial_after.asset_local_amount == 300 and node_b_partial_after.asset_remote_amount == 300

        close_channel(node_a, partial_channel_id, node_b_pubkey)
        wait_for_balance(node_a, asset_id, 700, 70)
        wait_for_balance(node_b, asset_id, 300, 70)

        full_push_channel = node_a.openchannel(
            rln.SdkOpenChannelRequest(
                peer_pubkey_and_opt_addr=peer_uri,
                capacity_sat=channel_capacity,
                push_msat=0,
                public=True,
                with_anchors=True,
                fee_base_msat=None,
                fee_proportional_millionths=None,
                temporary_channel_id=None,
                asset_id=asset_id,
                asset_amount=600,
                push_asset_amount=600,
                virtual_open_mode=None,
            )
        )
        print(
            "full_push_channel temporary_channel_id: "
            f"{full_push_channel.temporary_channel_id}"
        )

        funding_txid = wait_for_channel_funding_tx(node_a, node_b, asset_id, 120)
        print("Mining blocks one by one until funding tx is confirmed...")
        mine_until_tx_confirmed(node_a, funding_txid, 180)
        print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        full_channel_id = wait_for_channel_id(
            node_a, full_push_channel.temporary_channel_id, 10
        )
        wait_for_channel_ready(node_a, full_channel_id, 60)

        node_a.shutdown()
        node_b.shutdown()
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + daemon_offset, NODE_A_PEER_PORT + peer_offset)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + daemon_offset, NODE_B_PEER_PORT + peer_offset)
        node_a.unlock(unlock_request(NODE_A_PASSWORD))
        node_b.unlock(unlock_request(NODE_B_PASSWORD))

        wait_for_usable_channels(node_a, 1, 120)
        wait_for_usable_channels(node_b, 1, 120)

        assert asset_balance_spendable(node_a, asset_id) == 100
        assert asset_balance_spendable(node_b, asset_id) == 300

        node_a_full = next(c for c in node_a.list_channels() if c.channel_id == full_channel_id)
        node_b_full = next(c for c in node_b.list_channels() if c.channel_id == full_channel_id)
        assert node_a_full.asset_local_amount == 0 and node_a_full.asset_remote_amount == 600
        assert node_b_full.asset_local_amount == 600 and node_b_full.asset_remote_amount == 0

        btc_payment_hash = keysend(node_a, node_b_pubkey, 10_000_000, None, None)
        wait_for_payment_status(node_b, btc_payment_hash, 60)
        keysend_with_ln_balance(node_b, node_a, node_a_pubkey, None, asset_id, 100, 600, 0)

        node_a_full_after = next(c for c in node_a.list_channels() if c.channel_id == full_channel_id)
        node_b_full_after = next(c for c in node_b.list_channels() if c.channel_id == full_channel_id)
        assert node_a_full_after.asset_local_amount == 100 and node_a_full_after.asset_remote_amount == 500
        assert node_b_full_after.asset_local_amount == 500 and node_b_full_after.asset_remote_amount == 100

        close_channel(node_a, full_channel_id, node_b_pubkey)
        wait_for_balance(node_a, asset_id, 200, 70)
        wait_for_balance(node_b, asset_id, 800, 70)

        recipient_id = rgb_invoice(node_c)
        node_b.send_rgb(
            rln.SendRgbRequest(
                donation=True,
                fee_rate=CREATE_UTXOS_FEE_RATE,
                min_confirmations=1,
                skip_sync=False,
                recipient_groups=[
                    rln.AssetRecipients(
                        asset_id=asset_id,
                        recipients=[
                            rln.RgbRecipient(
                                recipient_id=recipient_id,
                                witness_data=None,
                                assignment_kind=rln.AssignmentKind.FUNGIBLE,
                                assignment_amount=100,
                                transport_endpoints=[PROXY_ENDPOINT_LOCAL],
                            )
                        ],
                    )
                ],
            )
        )
        run_regtest("mine", "1")
        refresh_transfers(node_c)
        refresh_transfers(node_c)
        refresh_transfers(node_b)

        assert asset_balance_spendable(node_a, asset_id) == 200
        assert asset_balance_spendable(node_b, asset_id) == 700
        assert asset_balance_spendable(node_c, asset_id) == 100

        print("SUCCESS: Python openchannel_push_asset_amount completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)
        safe_shutdown(node_c)


SCENARIO_HANDLERS = {
    "payment": payment_scenario,
    "openchannel_push_asset_amount": openchannel_push_asset_amount_scenario,
    "getchannelid_fail": getchannelid_fail_scenario,
    "openchannel_fail_no_utxos": openchannel_fail_no_utxos_scenario,
    "openchannel_fail_unknown_asset": openchannel_fail_unknown_asset_scenario,
}


def main():
    if SCENARIO == "all":
        for scenario in ALL_SCENARIOS:
            print(f"=== PYTHON_E2E_SCENARIO={scenario} ===")
            SCENARIO_HANDLERS[scenario]()
        return
    try:
        SCENARIO_HANDLERS[SCENARIO]()
    except KeyError:
        raise RuntimeError(f"Unsupported PYTHON_E2E_SCENARIO={SCENARIO}") from None


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
