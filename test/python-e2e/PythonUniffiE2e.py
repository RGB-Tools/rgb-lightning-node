#!/usr/bin/env python3
import hashlib
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import rgb_lightning_node as rln

from config import *  # noqa: F401,F403

SCENARIO = os.getenv("PYTHON_E2E_SCENARIO", "payment")

ALL_SCENARIOS = [
    "payment",
    "hodl_e2e",
    "hodl_expiry",
    "openchannel_push_asset_amount",
    "getchannelid_fail",
    "openchannel_fail_no_utxos",
    "openchannel_fail_unknown_asset",
]


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
        lsp_base_url=None,
        lsp_bearer_token=None,
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
    run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
    refresh_transfers(node)
    refresh_transfers(node)
    wait_for_balance(node, asset.asset_id, ISSUE_ASSET_SUPPLY, 60)
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
    try:
        return node.asset_balance(asset_id).spendable
    except rln.RlnError.NotFound:
        return 0


def asset_balance_offchain_outbound(node: rln.SdkNode, asset_id) -> int:
    try:
        return node.asset_balance(asset_id).offchain_outbound
    except rln.RlnError.NotFound:
        return 0


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
            rln.InvoiceStatus.CANCELLED,
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
        node.sync()
        balance = asset_balance_spendable(node, asset_id)
        last_balance = balance
        if balance == expected:
            return
        node.refreshtransfers(rln.SdkRefreshTransfersRequest(skip_sync=False))
        time.sleep(1)
    raise RuntimeError(
        "spendable balance did not become "
        f"expected={expected} actual={last_balance} "
        f"asset_id={asset_id} after {timeout_sec}s"
    )


def wait_for_ln_balance(node: rln.SdkNode, asset_id, expected: int, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last_balance = 0
    while time.time() < deadline:
        node.sync()
        balance = asset_balance_offchain_outbound(node, asset_id)
        last_balance = balance
        if balance == expected:
            return
        node.refreshtransfers(rln.SdkRefreshTransfersRequest(skip_sync=False))
        time.sleep(1)
    raise RuntimeError(
        "offchain_outbound balance did not become "
        f"expected={expected} actual={last_balance} "
        f"asset_id={asset_id} after {timeout_sec}s"
    )


def wait_for_payment_status(
    node: rln.SdkNode,
    payment_hash,
    payment_type,
    timeout_sec: int,
):
    deadline = time.time() + timeout_sec
    last_status = "not found"
    while time.time() < deadline:
        payment = next(
            (
                p
                for p in node.list_payments()
                if p.payment_hash == payment_hash and p.payment_type == payment_type
            ),
            None,
        )
        if payment is not None:
            last_status = payment.status.name
            if payment.status == rln.HtlcStatus.SUCCEEDED:
                return payment
        time.sleep(1)
    raise RuntimeError(
        f"timeout waiting for payment success: payment_hash={payment_hash} "
        f"payment_type={payment_type.name} last_status={last_status} after {timeout_sec}s"
    )


def wait_for_payment_present_in_list(
    node: rln.SdkNode,
    payment_hash,
    payment_type,
    timeout_sec: int,
):
    deadline = time.time() + timeout_sec
    last_count = 0
    while time.time() < deadline:
        payments = node.list_payments()
        last_count = len(payments)
        payment = next(
            (
                p
                for p in payments
                if p.payment_hash == payment_hash and p.payment_type == payment_type
            ),
            None,
        )
        if payment is not None:
            return payment
        time.sleep(1)
    raise RuntimeError(
        f"payment not found in list_payments: payment_hash={payment_hash} "
        f"payment_type={payment_type.name} list_size={last_count} after {timeout_sec}s"
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
    wait_for_payment_status(sender, response.payment_hash, rln.PaymentType.OUTBOUND, 60)
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
    wait_for_payment_status(receiver, payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60)


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
        except Exception as e:
            no_utxos_err = getattr(rln.RlnError, "NoAvailableUtxos", None)
            if isinstance(e, rln.RlnError.Conflict) or (
                no_utxos_err is not None and isinstance(e, no_utxos_err)
            ):
                pass
            else:
                raise

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
                min_final_cltv_expiry_delta=None,
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
        sender_payment = wait_for_payment_status(
            node_a, decoded.payment_hash, rln.PaymentType.OUTBOUND, 60
        )
        receiver_payment = wait_for_payment_status(
            node_b, decoded.payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60
        )
        check_preimage_matches_hash(sender_payment, decoded.payment_hash)
        check_preimage_matches_hash(receiver_payment, decoded.payment_hash)

        listed_sender_payment = wait_for_payment_present_in_list(
            node_a, decoded.payment_hash, rln.PaymentType.OUTBOUND, 60
        )
        if listed_sender_payment.payment_hash != decoded.payment_hash:
            raise RuntimeError("sender payment hash mismatch in list_payments")
        check_preimage_matches_hash(listed_sender_payment, decoded.payment_hash)

        listed_receiver_payment = wait_for_payment_present_in_list(
            node_b, decoded.payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60
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
        wait_for_payment_status(node_b, btc_payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60)
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
        wait_for_payment_status(node_b, btc_payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60)
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
                min_confirmations=1,                recipient_groups=[
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
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        refresh_transfers(node_c)
        refresh_transfers(node_c)
        refresh_transfers(node_b)
        refresh_transfers(node_b)

        assert asset_balance_spendable(node_a, asset_id) == 200
        assert asset_balance_spendable(node_b, asset_id) == 700
        assert asset_balance_spendable(node_c, asset_id) == 100

        print("SUCCESS: Python openchannel_push_asset_amount completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)
        safe_shutdown(node_c)


def get_block_count() -> int:
    return int(
        run_command(
            "docker",
            "compose",
            "exec",
            "-T",
            "-u",
            "blits",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "getblockcount",
        )
    )


def wait_for_payment_state(
    node: rln.SdkNode,
    payment_hash,
    payment_type,
    expected_status,
    timeout_sec: int,
):
    deadline = time.time() + timeout_sec
    last_status = "not found"
    while time.time() < deadline:
        payment = next(
            (
                p
                for p in node.list_payments()
                if p.payment_hash == payment_hash and p.payment_type == payment_type
            ),
            None,
        )
        if payment is not None:
            last_status = payment.status.name
            if payment.status == expected_status:
                return payment
        time.sleep(1)
    raise RuntimeError(
        f"timeout waiting for payment state: payment_hash={payment_hash} "
        f"payment_type={payment_type.name} expected={expected_status.name} "
        f"last={last_status} after {timeout_sec}s"
    )


def random_preimage_hex() -> str:
    return secrets.token_hex(32)


def payment_hash_from_preimage(preimage_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()


def assert_payment_core_fields(
    payment: rln.Payment,
    expected_type,
    expected_status,
    expected_asset_id,
    expected_asset_amount: int,
    expected_amt_msat: int,
):
    if payment.payment_type != expected_type:
        raise RuntimeError(
            f"unexpected payment_type: expected={expected_type.name} actual={payment.payment_type.name}"
        )
    if payment.status != expected_status:
        raise RuntimeError(
            f"unexpected payment status: expected={expected_status.name} actual={payment.status.name}"
        )
    if str(payment.asset_id) != str(expected_asset_id):
        raise RuntimeError(
            f"unexpected asset_id: expected={expected_asset_id} actual={payment.asset_id}"
        )
    if payment.asset_amount != expected_asset_amount:
        raise RuntimeError(
            f"unexpected asset_amount: expected={expected_asset_amount} actual={payment.asset_amount}"
        )
    if payment.amt_msat != expected_amt_msat:
        raise RuntimeError(
            f"unexpected amt_msat: expected={expected_amt_msat} actual={payment.amt_msat}"
        )


def _read_bigsize(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first <= 0xFC:
        return first, offset
    if first == 0xFD:
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if first == 0xFE:
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    return int.from_bytes(data[offset : offset + 8], "big"), offset + 8


def _read_collection_length(data: bytes, offset: int) -> tuple[int, int]:
    value = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    if value == 0xFFFF:
        value = int.from_bytes(data[offset : offset + 8], "big") + 0xFFFF
        offset += 8
    return value, offset


def _read_inbound_payments_bytes(receiver_storage: Path) -> tuple[bytes, str]:
    db_path = receiver_storage / RLN_DB_FNAME
    if db_path.exists():
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30) as conn:
            row = conn.execute(
                "select value from kv_store "
                "where primary_namespace = '' "
                "and secondary_namespace = '' "
                "and key = ?",
                (INBOUND_PAYMENTS_FNAME,),
            ).fetchone()
        if row is not None:
            return bytes(row[0]), str(db_path)

    inbound_payments_path = receiver_storage / LDK_DIR / INBOUND_PAYMENTS_FNAME
    return inbound_payments_path.read_bytes(), str(inbound_payments_path)


def read_claim_deadline_height(receiver_storage: Path, payment_hash) -> int:
    data, source = _read_inbound_payments_bytes(receiver_storage)

    offset = 0
    tlv_stream_len, offset = _read_bigsize(data, offset)
    stream_end = offset + tlv_stream_len
    payments_blob = None

    while offset < stream_end:
        field_type, offset = _read_bigsize(data, offset)
        field_len, offset = _read_bigsize(data, offset)
        field_end = offset + field_len
        if field_type == 0:
            payments_blob = data[offset:field_end]
            break
        offset = field_end

    if payments_blob is None:
        raise RuntimeError(f"could not find inbound payments map in {source}")

    target_hash = bytes.fromhex(str(payment_hash))
    offset = 0
    payment_count, offset = _read_collection_length(payments_blob, offset)

    for _ in range(payment_count):
        stored_hash = payments_blob[offset : offset + PAYMENT_HASH_LEN]
        offset += PAYMENT_HASH_LEN

        payment_info_len, offset = _read_bigsize(payments_blob, offset)
        payment_info_end = offset + payment_info_len

        if stored_hash == target_hash:
            info_offset = offset
            while info_offset < payment_info_end:
                field_type, info_offset = _read_bigsize(payments_blob, info_offset)
                field_len, info_offset = _read_bigsize(payments_blob, info_offset)
                field_end = info_offset + field_len
                if field_type == 16:
                    if field_len != 4:
                        raise RuntimeError(
                            f"unexpected claim_deadline_height length={field_len}"
                        )
                    return int.from_bytes(payments_blob[info_offset:field_end], "big")
                info_offset = field_end
            raise RuntimeError(
                f"claim_deadline_height is missing for payment_hash={payment_hash}"
            )

        offset = payment_info_end

    raise RuntimeError(f"payment_hash={payment_hash} not found in {source}")


def wait_for_peer_channel_funding_tx(
    sender: rln.SdkNode,
    receiver_pubkey,
    asset_id,
    timeout_sec: int = 120,
):
    deadline = time.time() + timeout_sec
    last = "no channels"
    while time.time() < deadline:
        sender.sync()
        channels = sender.list_channels()
        last = ", ".join(
            f"id={c.channel_id},peer={c.peer_pubkey},asset={c.asset_id},funding={c.funding_txid}"
            for c in channels
        ) or "no channels"

        opening = next(
            (
                c
                for c in channels
                if str(c.peer_pubkey) == str(receiver_pubkey)
                and str(c.asset_id) == str(asset_id)
                and c.funding_txid is not None
            ),
            None,
        )
        if opening is not None:
            print(
                f"channel funding tx found for peer {receiver_pubkey}: {opening.funding_txid}"
            )
            return str(opening.funding_txid)
        print(f"waiting for channel funding tx broadcast for peer {receiver_pubkey}...")
        time.sleep(1)

    raise RuntimeError(
        f"No funding tx after {timeout_sec}s for peer={receiver_pubkey} asset_id={asset_id}; "
        f"last_channels={last}"
    )


def wait_for_channel_usable(
    node: rln.SdkNode,
    channel_id,
    timeout_sec: int = 120,
):
    deadline = time.time() + timeout_sec
    last = "channel not found"
    while time.time() < deadline:
        node.sync()
        channel = next((c for c in node.list_channels() if c.channel_id == channel_id), None)
        if channel is not None:
            last = (
                f"id={channel.channel_id},ready={channel.ready},usable={channel.is_usable},"
                f"funding={channel.funding_txid}"
            )
            if channel.is_usable:
                return
        time.sleep(1)
    raise RuntimeError(
        f"channel did not become usable after {timeout_sec}s: channel_id={channel_id} last={last}"
    )


def wait_for_invoice_status(
    node: rln.SdkNode,
    invoice,
    expected_status,
    timeout_sec: int,
):
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        node.sync()
        status = node.invoice_status(invoice)
        last = status
        if status == expected_status:
            return status
        time.sleep(1)
    raise RuntimeError(
        f"invoice did not reach expected status after {timeout_sec}s: "
        f"expected={expected_status.name} actual={last.name if last else None}"
    )


def open_hodl_asset_channel(
    sender: rln.SdkNode,
    receiver: rln.SdkNode,
    receiver_name: str,
    receiver_peer_port: int,
    asset_id,
):
    receiver_info = receiver.node_info()
    peer_uri = f"{receiver_info.pubkey}@127.0.0.1:{receiver_peer_port}"
    try:
        sender.connectpeer(peer_uri)
        print(f"connectpeer to {receiver_name}: ok")
    except rln.RlnError.Conflict:
        print(f"connectpeer to {receiver_name}: already connected")
    wait_for_peer(sender, receiver_info.pubkey, 20)

    open_response = sender.openchannel(
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
    print(
        f"openchannel to {receiver_name} temporary_channel_id: "
        f"{open_response.temporary_channel_id}"
    )

    funding_txid = wait_for_peer_channel_funding_tx(
        sender, receiver_info.pubkey, asset_id, 120
    )
    print(f"Mining blocks until {receiver_name} funding tx is confirmed...")
    mine_until_tx_confirmed(sender, funding_txid, 180)
    print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
    run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
    channel_id = sender.get_channel_id(open_response.temporary_channel_id)
    wait_for_channel_ready(sender, channel_id, 10)
    wait_for_channel_usable(sender, channel_id, CHANNEL_READY_TIMEOUT_SEC)
    wait_for_channel_usable(receiver, channel_id, CHANNEL_READY_TIMEOUT_SEC)
    print(f"Channel to {receiver_name} is usable")
    return channel_id


def send_asset_for_second_channel(
    sender: rln.SdkNode,
    receiver: rln.SdkNode,
    receiver_name: str,
    asset_id,
    asset_amount: int,
):
    sender_initial_balance = asset_balance_spendable(sender, asset_id)
    receiver_initial_balance = asset_balance_spendable(receiver, asset_id)
    recipient_id = rgb_invoice(receiver)
    sender.send_rgb(
        rln.SendRgbRequest(
            donation=True,
            fee_rate=1,
            min_confirmations=1,            recipient_groups=[
                rln.AssetRecipients(
                    asset_id=asset_id,
                    recipients=[
                        rln.RgbRecipient(
                            recipient_id=recipient_id,
                            witness_data=None,
                            assignment_kind=rln.AssignmentKind.FUNGIBLE,
                            assignment_amount=asset_amount,
                            transport_endpoints=[PROXY_ENDPOINT_LOCAL],
                        )
                    ],
                )
            ],
        )
    )
    print(f"sent on-chain asset {asset_amount} to {receiver_name} for second channel setup")
    run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
    refresh_transfers(receiver)
    refresh_transfers(receiver)
    refresh_transfers(sender)
    refresh_transfers(sender)
    wait_for_balance(receiver, asset_id, receiver_initial_balance + asset_amount, 60)
    wait_for_balance(sender, asset_id, sender_initial_balance - asset_amount, 60)


def assert_decoded_hodl_invoice(decoded, payment_hash_hex: str, asset_id):
    if str(decoded.payment_hash) != payment_hash_hex:
        raise RuntimeError(
            f"decoded payment_hash mismatch: expected={payment_hash_hex} actual={decoded.payment_hash}"
        )
    if str(decoded.asset_id) != str(asset_id):
        raise RuntimeError(
            f"decoded asset_id mismatch: expected={asset_id} actual={decoded.asset_id}"
        )
    if decoded.asset_amount != PAYMENT_ASSET_AMOUNT:
        raise RuntimeError(
            f"decoded asset_amount mismatch: expected={PAYMENT_ASSET_AMOUNT} actual={decoded.asset_amount}"
        )
    if decoded.amt_msat != PAYMENT_MSAT:
        raise RuntimeError(
            f"decoded amt_msat mismatch: expected={PAYMENT_MSAT} actual={decoded.amt_msat}"
        )


def assert_sender_not_succeeded(sender: rln.SdkNode, payment_hash, phase: str):
    try:
        sender_payment = sender.get_payment(payment_hash, rln.PaymentType.OUTBOUND)
        if sender_payment.status == rln.HtlcStatus.SUCCEEDED:
            raise RuntimeError(f"sender payment succeeded before explicit hodl {phase}")
    except rln.RlnError.NotFound:
        pass


def get_channel(node: rln.SdkNode, channel_id):
    channel = next((c for c in node.list_channels() if c.channel_id == channel_id), None)
    if channel is None:
        raise RuntimeError(f"channel not found: channel_id={channel_id}")
    return channel


def assert_channel_asset_amounts(
    node: rln.SdkNode,
    channel_id,
    expected_local: int,
    expected_remote: int,
    node_name: str,
):
    channel = get_channel(node, channel_id)
    if channel.asset_local_amount != expected_local:
        raise RuntimeError(
            f"{node_name} unexpected channel asset_local_amount: "
            f"expected={expected_local} actual={channel.asset_local_amount}"
        )
    if channel.asset_remote_amount != expected_remote:
        raise RuntimeError(
            f"{node_name} unexpected channel asset_remote_amount: "
            f"expected={expected_remote} actual={channel.asset_remote_amount}"
        )


def assert_node_channel_counts(
    node: rln.SdkNode,
    expected_channels: int,
    expected_usable_channels: int,
    expected_peers: int,
    node_name: str,
):
    info = node.node_info()
    if info.num_channels != expected_channels:
        raise RuntimeError(
            f"{node_name} unexpected num_channels: "
            f"expected={expected_channels} actual={info.num_channels}"
        )
    if info.num_usable_channels != expected_usable_channels:
        raise RuntimeError(
            f"{node_name} unexpected num_usable_channels: "
            f"expected={expected_usable_channels} actual={info.num_usable_channels}"
        )
    if info.num_peers != expected_peers:
        raise RuntimeError(
            f"{node_name} unexpected num_peers: "
            f"expected={expected_peers} actual={info.num_peers}"
        )


def assert_offchain_balances(
    node: rln.SdkNode,
    asset_id,
    expected_outbound: int,
    expected_inbound: int,
    node_name: str,
    timeout_sec: int = 30,
):
    deadline = time.time() + timeout_sec
    last_outbound = None
    last_inbound = None
    while time.time() < deadline:
        node.sync()
        balance = node.asset_balance(asset_id)
        last_outbound = balance.offchain_outbound
        last_inbound = balance.offchain_inbound
        if (
            balance.offchain_outbound == expected_outbound
            and balance.offchain_inbound == expected_inbound
        ):
            return
        time.sleep(1)
    raise RuntimeError(
        f"{node_name} unexpected offchain balances after {timeout_sec}s: "
        f"expected_outbound={expected_outbound} actual_outbound={last_outbound} "
        f"expected_inbound={expected_inbound} actual_inbound={last_inbound}"
    )


def run_hodl_claim_phase(
    sender: rln.SdkNode, receiver: rln.SdkNode, asset_id, sender_channel_id, receiver_channel_id
):
    print("=== HODL phase: claim ===")

    preimage_hex = random_preimage_hex()
    payment_hash_hex = payment_hash_from_preimage(preimage_hex)
    invoice = receiver.ln_invoice(
        rln.LnInvoiceRequest(
            amt_msat=PAYMENT_MSAT,
            expiry_sec=3600,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
            payment_hash=payment_hash_hex,
            description_hash=None,
            min_final_cltv_expiry_delta=None,
        )
    ).invoice
    print(f"hodl claim invoice: {invoice}")

    decoded = sender.decode_ln_invoice(invoice)
    assert_decoded_hodl_invoice(decoded, payment_hash_hex, asset_id)

    send_payment = sender.sendpayment(
        rln.SdkSendPaymentRequest(
            invoice=invoice,
            amt_msat=None,
            asset_id=None,
            asset_amount=None,
        )
    )
    print(f"sendpayment claim status: {send_payment.status.name}")
    if send_payment.status in (rln.HtlcStatus.FAILED, rln.HtlcStatus.CANCELLED):
        raise RuntimeError(
            f"unexpected initial sendpayment status on claim phase: {send_payment.status.name}"
        )

    claimable_payment = wait_for_payment_state(
        receiver,
        decoded.payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CLAIMABLE,
        60,
    )
    assert_payment_core_fields(
        claimable_payment,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CLAIMABLE,
        asset_id,
        PAYMENT_ASSET_AMOUNT,
        PAYMENT_MSAT,
    )
    assert_sender_not_succeeded(sender, decoded.payment_hash, "claim")

    claim_response = receiver.claimhodlinvoice(
        rln.ClaimHodlInvoiceRequest(
            payment_hash=decoded.payment_hash,
            payment_preimage=preimage_hex,
        )
    )
    if not claim_response.changed:
        raise RuntimeError("first claimhodlinvoice should report changed=True")

    sender_final = wait_for_payment_state(
        sender,
        decoded.payment_hash,
        rln.PaymentType.OUTBOUND,
        rln.HtlcStatus.SUCCEEDED,
        60,
    )
    receiver_final = wait_for_payment_state(
        receiver,
        decoded.payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.SUCCEEDED,
        60,
    )
    assert_payment_core_fields(
        receiver_final,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.SUCCEEDED,
        asset_id,
        PAYMENT_ASSET_AMOUNT,
        PAYMENT_MSAT,
    )
    if sender_final.preimage != preimage_hex:
        raise RuntimeError(
            f"unexpected sender preimage: expected={preimage_hex} actual={sender_final.preimage}"
        )
    check_preimage_matches_hash(sender_final, str(decoded.payment_hash))

    final_status = wait_payment_final(receiver, invoice, 30)
    if final_status != rln.InvoiceStatus.SUCCEEDED:
        raise RuntimeError(
            f"unexpected final invoice_status on claim phase: {final_status.name}"
        )

    claim_response_again = receiver.claimhodlinvoice(
        rln.ClaimHodlInvoiceRequest(
            payment_hash=decoded.payment_hash,
            payment_preimage=preimage_hex,
        )
    )
    if claim_response_again.changed:
        raise RuntimeError("second claimhodlinvoice should report changed=False")

    assert_channel_asset_amounts(
        sender,
        sender_channel_id,
        OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
        PAYMENT_ASSET_AMOUNT,
        "claim sender",
    )
    assert_channel_asset_amounts(
        receiver,
        receiver_channel_id,
        PAYMENT_ASSET_AMOUNT,
        OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
        "claim receiver",
    )


def run_hodl_cancel_phase(
    sender: rln.SdkNode, receiver: rln.SdkNode, asset_id, sender_channel_id, receiver_channel_id
):
    print("=== HODL phase: cancel ===")

    preimage_hex = random_preimage_hex()
    payment_hash_hex = payment_hash_from_preimage(preimage_hex)
    invoice = receiver.ln_invoice(
        rln.LnInvoiceRequest(
            amt_msat=PAYMENT_MSAT,
            expiry_sec=3600,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
            payment_hash=payment_hash_hex,
            description_hash=None,
            min_final_cltv_expiry_delta=None,
        )
    ).invoice
    print(f"hodl cancel invoice: {invoice}")

    decoded = sender.decode_ln_invoice(invoice)
    assert_decoded_hodl_invoice(decoded, payment_hash_hex, asset_id)

    send_payment = sender.sendpayment(
        rln.SdkSendPaymentRequest(
            invoice=invoice,
            amt_msat=None,
            asset_id=None,
            asset_amount=None,
        )
    )
    print(f"sendpayment cancel status: {send_payment.status.name}")
    if send_payment.status in (rln.HtlcStatus.FAILED, rln.HtlcStatus.CANCELLED):
        raise RuntimeError(
            f"unexpected initial sendpayment status on cancel phase: {send_payment.status.name}"
        )

    claimable_payment = wait_for_payment_state(
        receiver,
        decoded.payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CLAIMABLE,
        60,
    )
    assert_payment_core_fields(
        claimable_payment,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CLAIMABLE,
        asset_id,
        PAYMENT_ASSET_AMOUNT,
        PAYMENT_MSAT,
    )
    assert_sender_not_succeeded(sender, decoded.payment_hash, "cancel")

    receiver.cancelhodlinvoice(
        rln.CancelHodlInvoiceRequest(payment_hash=decoded.payment_hash)
    )

    sender_final = wait_for_payment_state(
        sender,
        decoded.payment_hash,
        rln.PaymentType.OUTBOUND,
        rln.HtlcStatus.FAILED,
        60,
    )
    receiver_final = wait_for_payment_state(
        receiver,
        decoded.payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CANCELLED,
        60,
    )
    assert_payment_core_fields(
        receiver_final,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CANCELLED,
        asset_id,
        PAYMENT_ASSET_AMOUNT,
        PAYMENT_MSAT,
    )
    if sender_final.payment_type != rln.PaymentType.OUTBOUND:
        raise RuntimeError(
            f"unexpected sender payment_type after cancel: {sender_final.payment_type.name}"
        )

    final_status = wait_payment_final(receiver, invoice, 30)
    if final_status != rln.InvoiceStatus.CANCELLED:
        raise RuntimeError(
            f"unexpected final invoice_status on cancel phase: {final_status.name}"
        )

    assert_channel_asset_amounts(
        sender,
        sender_channel_id,
        OPEN_CHANNEL_ASSET_AMOUNT,
        0,
        "cancel sender",
    )
    assert_channel_asset_amounts(
        receiver,
        receiver_channel_id,
        0,
        OPEN_CHANNEL_ASSET_AMOUNT,
        "cancel receiver",
    )


def setup_two_node_hodl_channel(
    node_a: rln.SdkNode,
    node_b: rln.SdkNode,
    scenario_name: str,
    node_b_peer_port: int,
    node_a_storage: Path | None = None,
    node_b_storage: Path | None = None,
):
    print(f"Python UniFFI HODL expiry flow: {scenario_name}")

    init_if_needed(node_a, NODE_A_PASSWORD, "node A")
    init_if_needed(node_b, NODE_B_PASSWORD, "node B")
    unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
    unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")

    ensure_funded_with_amount(node_a, "node A", OPEN_CHANNEL_CAPACITY_SAT + 300_000, "0.02")
    ensure_funded_with_amount(node_b, "node B", 200_000, "0.02")

    create_utxos(node_a, "node A")
    create_utxos(node_b, "node B")
    run_regtest("mine", "1")
    node_a.sync()
    node_b.sync()

    asset_id = issue_asset_nia(node_a, "node A")
    channel_id = open_hodl_asset_channel(
        node_a,
        node_b,
        "node B",
        node_b_peer_port,
        asset_id,
    )

    assert_node_channel_counts(node_a, 1, 1, 1, "node A")
    assert_node_channel_counts(node_b, 1, 1, 1, "node B")
    assert_channel_asset_amounts(node_a, channel_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "node A")
    assert_channel_asset_amounts(node_b, channel_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node B")
    assert_offchain_balances(node_a, asset_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "node A")
    assert_offchain_balances(node_b, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node B")

    return asset_id, channel_id


def run_hodl_to_claimable(sender: rln.SdkNode, receiver: rln.SdkNode, asset_id, expiry_sec: int):
    preimage_hex = random_preimage_hex()
    payment_hash_hex = payment_hash_from_preimage(preimage_hex)
    invoice = receiver.ln_invoice(
        rln.LnInvoiceRequest(
            amt_msat=PAYMENT_MSAT,
            expiry_sec=expiry_sec,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
            payment_hash=payment_hash_hex,
            description_hash=None,
            min_final_cltv_expiry_delta=None,
        )
    ).invoice
    print(f"hodl expiry invoice: {invoice}")

    decoded = sender.decode_ln_invoice(invoice)
    assert_decoded_hodl_invoice(decoded, payment_hash_hex, asset_id)

    send_payment = sender.sendpayment(
        rln.SdkSendPaymentRequest(
            invoice=invoice,
            amt_msat=None,
            asset_id=None,
            asset_amount=None,
        )
    )
    print(f"sendpayment expiry status: {send_payment.status.name}")
    if send_payment.status in (rln.HtlcStatus.FAILED, rln.HtlcStatus.CANCELLED):
        raise RuntimeError(
            f"unexpected initial sendpayment status on expiry phase: {send_payment.status.name}"
        )

    claimable_payment = wait_for_payment_state(
        receiver,
        decoded.payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CLAIMABLE,
        60,
    )
    assert_payment_core_fields(
        claimable_payment,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.CLAIMABLE,
        asset_id,
        PAYMENT_ASSET_AMOUNT,
        PAYMENT_MSAT,
    )

    claimable_status = wait_for_invoice_status(
        receiver, invoice, rln.InvoiceStatus.CLAIMABLE, 30
    )
    if claimable_status != rln.InvoiceStatus.CLAIMABLE:
        raise RuntimeError(
            f"unexpected invoice_status before expiry: expected=CLAIMABLE actual={claimable_status.name}"
        )

    return invoice, decoded.payment_hash, preimage_hex


def assert_hodl_not_claimable(receiver: rln.SdkNode, payment_hash, preimage_hex: str):
    try:
        receiver.claimhodlinvoice(
            rln.ClaimHodlInvoiceRequest(
                payment_hash=payment_hash,
                payment_preimage=preimage_hex,
            )
        )
        raise RuntimeError("claimhodlinvoice should fail after expiry")
    except RuntimeError:
        raise
    except Exception:
        pass

    try:
        receiver.cancelhodlinvoice(rln.CancelHodlInvoiceRequest(payment_hash=payment_hash))
        raise RuntimeError("cancelhodlinvoice should fail after expiry")
    except RuntimeError:
        raise
    except Exception:
        pass


def run_hodl_time_expiry_phase(sender: rln.SdkNode, receiver: rln.SdkNode, asset_id, channel_id):
    print("=== HODL phase: expiry by time ===")
    invoice, payment_hash, preimage_hex = run_hodl_to_claimable(sender, receiver, asset_id, 20)
    decoded = sender.decode_ln_invoice(invoice)

    expiry_at = decoded.timestamp + decoded.expiry_sec
    pre_expiry_margin_sec = 3
    seconds_before_expiry = expiry_at - int(time.time()) - pre_expiry_margin_sec
    if seconds_before_expiry < 1:
        raise RuntimeError(
            "not enough distance to test pre-expiry boundary: "
            f"now={int(time.time())} expiry_at={expiry_at}"
        )

    print(
        "waiting to just before time expiry: "
        f"now={int(time.time())} expiry_at={expiry_at} "
        f"sleep_before_boundary={seconds_before_expiry}"
    )
    time.sleep(seconds_before_expiry)
    sender.sync()
    receiver.sync()

    receiver_pre_expiry = receiver.get_payment(payment_hash, rln.PaymentType.INBOUND_HODL)
    sender_pre_expiry = sender.get_payment(payment_hash, rln.PaymentType.OUTBOUND)
    if receiver_pre_expiry.status != rln.HtlcStatus.CLAIMABLE:
        raise RuntimeError(
            "receiver payment expired before invoice expiry boundary: "
            f"expected=CLAIMABLE actual={receiver_pre_expiry.status.name}"
        )
    if sender_pre_expiry.status != rln.HtlcStatus.PENDING:
        raise RuntimeError(
            "sender payment finalized before invoice expiry boundary: "
            f"expected=PENDING actual={sender_pre_expiry.status.name}"
        )
    pre_expiry_status = wait_for_invoice_status(receiver, invoice, rln.InvoiceStatus.CLAIMABLE, 10)
    if pre_expiry_status != rln.InvoiceStatus.CLAIMABLE:
        raise RuntimeError(
            f"unexpected invoice_status before time expiry: expected=CLAIMABLE actual={pre_expiry_status.name}"
        )

    assert_channel_asset_amounts(
        sender, channel_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "time expiry sender before expiry"
    )
    assert_channel_asset_amounts(
        receiver, channel_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "time expiry receiver before expiry"
    )
    assert_offchain_balances(
        sender, asset_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "time expiry node A before expiry"
    )
    assert_offchain_balances(
        receiver, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "time expiry node B before expiry"
    )

    receiver_failed = wait_for_payment_state(
        receiver,
        payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.FAILED,
        90,
    )
    sender_failed = wait_for_payment_state(
        sender,
        payment_hash,
        rln.PaymentType.OUTBOUND,
        rln.HtlcStatus.FAILED,
        90,
    )
    assert receiver_failed.payment_type == rln.PaymentType.INBOUND_HODL
    final_status = wait_payment_final(receiver, invoice, 30)
    if final_status != rln.InvoiceStatus.FAILED:
        raise RuntimeError(
            f"unexpected final invoice_status on time expiry phase: {final_status.name}"
        )

    assert sender_failed.payment_type == rln.PaymentType.OUTBOUND
    assert_channel_asset_amounts(sender, channel_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "time expiry sender")
    assert_channel_asset_amounts(receiver, channel_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "time expiry receiver")
    assert_offchain_balances(sender, asset_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "time expiry node A")
    assert_offchain_balances(receiver, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "time expiry node B")
    assert_hodl_not_claimable(receiver, payment_hash, preimage_hex)


def run_hodl_block_expiry_phase(
    sender: rln.SdkNode,
    receiver: rln.SdkNode,
    receiver_storage: Path,
    asset_id,
    channel_id,
):
    print("=== HODL phase: expiry by blocks ===")
    invoice, payment_hash, preimage_hex = run_hodl_to_claimable(sender, receiver, asset_id, 900)

    deadline_height = read_claim_deadline_height(receiver_storage, payment_hash)
    current_height = get_block_count()
    blocks_before_deadline = deadline_height - current_height - 1
    if blocks_before_deadline < 1:
        raise RuntimeError(
            "not enough distance to test pre-deadline boundary: "
            f"current_height={current_height} deadline_height={deadline_height}"
        )
    print(
        "mining to just before block expiry: "
        f"current_height={current_height} deadline_height={deadline_height} "
        f"blocks_before_deadline={blocks_before_deadline}"
    )
    run_regtest("mine", str(blocks_before_deadline))
    sender.sync()
    receiver.sync()

    receiver_pre_deadline = receiver.get_payment(payment_hash, rln.PaymentType.INBOUND_HODL)
    sender_pre_deadline = sender.get_payment(payment_hash, rln.PaymentType.OUTBOUND)
    if receiver_pre_deadline.status != rln.HtlcStatus.CLAIMABLE:
        raise RuntimeError(
            "receiver payment expired before deadline: "
            f"expected=CLAIMABLE actual={receiver_pre_deadline.status.name}"
        )
    if sender_pre_deadline.status != rln.HtlcStatus.PENDING:
        raise RuntimeError(
            "sender payment finalized before deadline: "
            f"expected=PENDING actual={sender_pre_deadline.status.name}"
        )
    pre_deadline_status = wait_for_invoice_status(receiver, invoice, rln.InvoiceStatus.CLAIMABLE, 10)
    if pre_deadline_status != rln.InvoiceStatus.CLAIMABLE:
        raise RuntimeError(
            f"unexpected invoice_status before deadline: expected=CLAIMABLE actual={pre_deadline_status.name}"
        )

    assert_channel_asset_amounts(
        sender, channel_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "block expiry sender before deadline"
    )
    assert_channel_asset_amounts(
        receiver, channel_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "block expiry receiver before deadline"
    )
    assert_offchain_balances(
        sender, asset_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "block expiry node A before deadline"
    )
    assert_offchain_balances(
        receiver, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "block expiry node B before deadline"
    )

    remaining_blocks = max(deadline_height - get_block_count(), 0) + 1
    print(
        "mining across block expiry: "
        f"current_height={get_block_count()} deadline_height={deadline_height} "
        f"remaining_blocks={remaining_blocks}"
    )
    run_regtest("mine", str(remaining_blocks))
    sender.sync()
    receiver.sync()

    receiver_failed = wait_for_payment_state(
        receiver,
        payment_hash,
        rln.PaymentType.INBOUND_HODL,
        rln.HtlcStatus.FAILED,
        60,
    )
    sender_failed = wait_for_payment_state(
        sender,
        payment_hash,
        rln.PaymentType.OUTBOUND,
        rln.HtlcStatus.FAILED,
        60,
    )
    assert receiver_failed.payment_type == rln.PaymentType.INBOUND_HODL
    final_status = wait_payment_final(receiver, invoice, 30)
    if final_status != rln.InvoiceStatus.FAILED:
        raise RuntimeError(
            f"unexpected final invoice_status on block expiry phase: {final_status.name}"
        )

    assert sender_failed.payment_type == rln.PaymentType.OUTBOUND
    assert_channel_asset_amounts(sender, channel_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "block expiry sender")
    assert_channel_asset_amounts(receiver, channel_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "block expiry receiver")
    assert_offchain_balances(sender, asset_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "block expiry node A")
    assert_offchain_balances(receiver, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "block expiry node B")
    assert_hodl_not_claimable(receiver, payment_hash, preimage_hex)


def hodl_e2e_scenario():
    scenario = "hodl_e2e"
    node_a_storage = scenario_storage(scenario, "node_a")
    node_b_storage = scenario_storage(scenario, "node_b")
    node_c_storage = scenario_storage(scenario, "node_c")

    print("Python UniFFI HODL 3-node flow")
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
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + 20, NODE_A_PEER_PORT + 20)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + 20, NODE_B_PEER_PORT + 20)
        node_c = make_node(node_c_storage, NODE_C_DAEMON_PORT + 20, NODE_C_PEER_PORT + 20)

        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")
        init_if_needed(node_c, NODE_C_PASSWORD, "node C")
        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")
        unlock_if_needed(node_c, NODE_C_PASSWORD, "node C")

        ensure_funded_with_amount(node_a, "node A", OPEN_CHANNEL_CAPACITY_SAT * 2 + 300_000, "0.02")
        ensure_funded_with_amount(node_b, "node B", 200_000, "0.02")
        ensure_funded_with_amount(node_c, "node C", 200_000, "0.02")

        create_utxos(node_a, "node A")
        create_utxos(node_b, "node B")
        create_utxos(node_c, "node C")
        run_regtest("mine", "1")
        node_a.sync()
        node_b.sync()
        node_c.sync()

        asset_id = issue_asset_nia(node_a, "node A")
        send_asset_for_second_channel(
            node_a, node_b, "node B", asset_id, OPEN_CHANNEL_ASSET_AMOUNT + PAYMENT_ASSET_AMOUNT
        )

        channel_ab = open_hodl_asset_channel(
            node_a, node_b, "node B", NODE_B_PEER_PORT + 20, asset_id
        )
        channel_bc = open_hodl_asset_channel(
            node_b, node_c, "node C", NODE_C_PEER_PORT + 20, asset_id
        )

        assert_node_channel_counts(node_a, 1, 1, 1, "node A")
        assert_node_channel_counts(node_b, 2, 2, 2, "node B")
        assert_node_channel_counts(node_c, 1, 1, 1, "node C")

        assert_channel_asset_amounts(node_a, channel_ab, OPEN_CHANNEL_ASSET_AMOUNT, 0, "node A")
        assert_channel_asset_amounts(node_b, channel_ab, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node B")
        assert_channel_asset_amounts(node_b, channel_bc, OPEN_CHANNEL_ASSET_AMOUNT, 0, "node B")
        assert_channel_asset_amounts(node_c, channel_bc, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node C")

        assert_offchain_balances(node_a, asset_id, OPEN_CHANNEL_ASSET_AMOUNT, 0, "node A")
        assert_offchain_balances(
            node_b,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT,
            OPEN_CHANNEL_ASSET_AMOUNT,
            "node B",
        )
        assert_offchain_balances(node_c, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node C")

        run_hodl_claim_phase(node_a, node_b, asset_id, channel_ab, channel_ab)
        assert_offchain_balances(
            node_a,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            PAYMENT_ASSET_AMOUNT,
            "node A",
        )
        assert_offchain_balances(
            node_b,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT + PAYMENT_ASSET_AMOUNT,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            "node B",
        )
        assert_offchain_balances(node_c, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node C")

        print("=== HODL phase: restart ===")
        node_a.shutdown()
        node_b.shutdown()
        node_c.shutdown()
        time.sleep(1)

        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + 20, NODE_A_PEER_PORT + 20)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + 20, NODE_B_PEER_PORT + 20)
        node_c = make_node(node_c_storage, NODE_C_DAEMON_PORT + 20, NODE_C_PEER_PORT + 20)

        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")
        unlock_if_needed(node_c, NODE_C_PASSWORD, "node C")

        wait_for_usable_channels(node_a, 1, 120)
        wait_for_usable_channels(node_b, 2, 120)
        wait_for_usable_channels(node_c, 1, 120)
        wait_for_channel_usable(node_a, channel_ab, CHANNEL_READY_TIMEOUT_SEC)
        wait_for_channel_usable(node_b, channel_ab, CHANNEL_READY_TIMEOUT_SEC)
        wait_for_channel_usable(node_b, channel_bc, CHANNEL_READY_TIMEOUT_SEC)
        wait_for_channel_usable(node_c, channel_bc, CHANNEL_READY_TIMEOUT_SEC)

        assert_node_channel_counts(node_a, 1, 1, 1, "node A")
        assert_node_channel_counts(node_b, 2, 2, 2, "node B")
        assert_node_channel_counts(node_c, 1, 1, 1, "node C")

        assert_channel_asset_amounts(
            node_a,
            channel_ab,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            PAYMENT_ASSET_AMOUNT,
            "node A after restart",
        )
        assert_channel_asset_amounts(
            node_b,
            channel_ab,
            PAYMENT_ASSET_AMOUNT,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            "node B channel AB after restart",
        )
        assert_channel_asset_amounts(
            node_b,
            channel_bc,
            OPEN_CHANNEL_ASSET_AMOUNT,
            0,
            "node B channel BC after restart",
        )
        assert_channel_asset_amounts(
            node_c,
            channel_bc,
            0,
            OPEN_CHANNEL_ASSET_AMOUNT,
            "node C after restart",
        )

        assert_offchain_balances(
            node_a,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            PAYMENT_ASSET_AMOUNT,
            "node A after restart",
        )
        assert_offchain_balances(
            node_b,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT + PAYMENT_ASSET_AMOUNT,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            "node B after restart",
        )
        assert_offchain_balances(
            node_c,
            asset_id,
            0,
            OPEN_CHANNEL_ASSET_AMOUNT,
            "node C after restart",
        )

        run_hodl_cancel_phase(node_b, node_c, asset_id, channel_bc, channel_bc)
        assert_offchain_balances(
            node_a,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            PAYMENT_ASSET_AMOUNT,
            "node A",
        )
        assert_offchain_balances(
            node_b,
            asset_id,
            OPEN_CHANNEL_ASSET_AMOUNT + PAYMENT_ASSET_AMOUNT,
            OPEN_CHANNEL_ASSET_AMOUNT - PAYMENT_ASSET_AMOUNT,
            "node B",
        )
        assert_offchain_balances(node_c, asset_id, 0, OPEN_CHANNEL_ASSET_AMOUNT, "node C")

        print("SUCCESS: Python HODL 3-node flow completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)
        safe_shutdown(node_c)


def hodl_expiry_scenario():
    scenario = "hodl_expiry"
    node_a_storage = scenario_storage(scenario, "node_a")
    node_b_storage = scenario_storage(scenario, "node_b")

    print("Python UniFFI HODL expiry flow")
    print(f"node A storage: {node_a_storage}")
    print(f"node B storage: {node_b_storage}")

    ensure_dir(node_a_storage)
    ensure_dir(node_b_storage)

    node_a = None
    node_b = None
    try:
        node_a = make_node(node_a_storage, NODE_A_DAEMON_PORT + 30, NODE_A_PEER_PORT + 30)
        node_b = make_node(node_b_storage, NODE_B_DAEMON_PORT + 30, NODE_B_PEER_PORT + 30)

        asset_id, channel_id = setup_two_node_hodl_channel(
            node_a, node_b, scenario, NODE_B_PEER_PORT + 30, node_a_storage, node_b_storage
        )
        run_hodl_time_expiry_phase(node_a, node_b, asset_id, channel_id)
        run_hodl_block_expiry_phase(node_a, node_b, node_b_storage, asset_id, channel_id)

        print("SUCCESS: Python HODL expiry flow completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)


SCENARIO_HANDLERS = {
    "payment": payment_scenario,
    "hodl_e2e": hodl_e2e_scenario,
    "hodl_expiry": hodl_expiry_scenario,
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
