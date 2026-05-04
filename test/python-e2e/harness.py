import hashlib
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import rgb_lightning_node as rln

from config import (
    CREATE_UTXOS_FEE_RATE,
    CREATE_UTXOS_NUM,
    CREATE_UTXOS_SIZE_SAT,
    ISSUE_ASSET_NAME,
    ISSUE_ASSET_PRECISION,
    ISSUE_ASSET_SUPPLY,
    ISSUE_ASSET_TICKER,
    OPEN_CHANNEL_CONFIRM_BLOCKS,
    PAYMENT_MSAT,
    PROXY_ENDPOINT_LOCAL,
    REPO_ROOT,
    RESET_DATA,
)


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
    deadline = time.time() + 90
    last_state = "unlock not attempted"
    next_unlock_attempt_at = 0.0
    while time.time() < deadline:
        try:
            node.node_info()
            print(f"{name}: {last_state}")
            return
        except rln.RlnError.NotInitialized:
            pass

        now = time.time()
        if now >= next_unlock_attempt_at:
            try:
                node.unlock(unlock_request(password))
                last_state = "unlocked"
            except rln.RlnError.Conflict:
                last_state = "already unlocked or still changing state"
            next_unlock_attempt_at = now + 1.0

        time.sleep(0.5)

    raise RuntimeError(f"{name}: unlock did not leave node usable (state={last_state})")


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


def wait_for_channel_asset_state(
    label: str,
    node: rln.SdkNode,
    channel_id,
    expected_asset_local,
    expected_asset_remote,
    min_outbound_msat,
    timeout_sec: int,
):
    deadline = time.time() + timeout_sec
    last = "channel not found"
    while time.time() < deadline:
        node.sync()
        channel = next((c for c in node.list_channels() if c.channel_id == channel_id), None)
        if channel is not None:
            last = (
                f"id={channel.channel_id},ready={channel.ready},usable={channel.is_usable},"
                f"asset_local={channel.asset_local_amount},"
                f"asset_remote={channel.asset_remote_amount},"
                f"outbound_msat={channel.outbound_balance_msat}"
            )
            outbound_ok = (
                min_outbound_msat is None
                or channel.outbound_balance_msat >= min_outbound_msat
            )
            if (
                channel.ready
                and channel.is_usable
                and channel.asset_local_amount == expected_asset_local
                and channel.asset_remote_amount == expected_asset_remote
                and outbound_ok
            ):
                return
        time.sleep(1)
    raise RuntimeError(
        f"{label} did not reach expected channel state after {timeout_sec}s: last={last}"
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
    raise RuntimeError(f"Invoice did not finalize after {timeout_sec}s, last={last}")


def wait_for_balance(node: rln.SdkNode, asset_id, expected: int, timeout_sec: int):
    deadline = time.time() + timeout_sec
    last_balance = 0
    while time.time() < deadline:
        node.refreshtransfers(rln.SdkRefreshTransfersRequest(skip_sync=False))
        balance = asset_balance_spendable(node, asset_id)
        last_balance = balance
        if balance == expected:
            return
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
    wait_for_payment_status(
        receiver, payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60
    )


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
