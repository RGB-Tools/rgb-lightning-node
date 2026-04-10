#!/usr/bin/env python3
import os
import shutil
import subprocess
import time
from pathlib import Path

import rgb_lightning_node as rln

REPO_ROOT = Path(__file__).resolve().parents[4]

NODE_A_STORAGE = Path(os.getenv("NODE_A_STORAGE", REPO_ROOT / "sdkdata_py" / "node_a"))
NODE_B_STORAGE = Path(os.getenv("NODE_B_STORAGE", REPO_ROOT / "sdkdata_py" / "node_b"))

# These ports are part of node config even when HTTP API is not used.
NODE_A_DAEMON_PORT = int(os.getenv("NODE_A_DAEMON_PORT", "3101"))
NODE_B_DAEMON_PORT = int(os.getenv("NODE_B_DAEMON_PORT", "3102"))

NODE_A_PEER_PORT = int(os.getenv("NODE_A_PEER_PORT", "9735"))
NODE_B_PEER_PORT = int(os.getenv("NODE_B_PEER_PORT", "9736"))

NODE_A_PASSWORD = os.getenv("NODE_A_PASSWORD", "nodeApass")
NODE_B_PASSWORD = os.getenv("NODE_B_PASSWORD", "nodeBpass")

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
OPEN_CHANNEL_CONFIRM_BLOCKS = int(os.getenv("OPEN_CHANNEL_CONFIRM_BLOCKS", "12"))
CHANNEL_READY_TIMEOUT_SEC = int(os.getenv("CHANNEL_READY_TIMEOUT_SEC", "300"))
RGB_MIN_HTLC_MSAT = 3_000_000

RESET_DATA = os.getenv("RESET_DATA", "0") == "1"


def run_regtest(*args: str) -> str:
    cmd = ["./regtest.sh", *args]
    res = subprocess.run(
        cmd,
        check=True,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return (res.stdout or "").strip()


def ensure_dir(path: Path):
    if RESET_DATA and path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def make_node(storage: Path, daemon_port: int, peer_port: int) -> rln.SdkNode:
    req = rln.SdkInitRequest(
        storage_dir_path=str(storage),
        daemon_listening_port=daemon_port,
        ldk_peer_listening_port=peer_port,
        network="regtest",
        max_media_upload_size_mb=20,
        enable_virtual_channels_v0=False,
        virtual_peer_pubkeys=None,
    )
    return rln.SdkNode.create(req)


def init_if_needed(node: rln.SdkNode, password: str, name: str):
    try:
        mnemonic = node.init(password, None)
        print(f"{name}: initialized")
        print(f"{name}: mnemonic[0..20]={mnemonic[:20]}...")
    except rln.RlnError.Conflict:
        print(f"{name}: already initialized")


def unlock_if_needed(node: rln.SdkNode, password: str, name: str):
    req = rln.SdkUnlockRequest(
        password=password,
        bitcoind_rpc_username="user",
        bitcoind_rpc_password="password",
        bitcoind_rpc_host="localhost",
        bitcoind_rpc_port=18443,
        indexer_url="127.0.0.1:50001",
        proxy_endpoint="rpc://127.0.0.1:3000/json-rpc",
        announce_addresses=[],
        announce_alias=None,
    )
    try:
        node.unlock(req)
        print(f"{name}: unlocked")
    except rln.RlnError.Conflict:
        print(f"{name}: already unlocked")


def create_utxos(node: rln.SdkNode, name: str):
    req = rln.SdkCreateUtxosRequest(
        up_to=False,
        num=CREATE_UTXOS_NUM,
        size=CREATE_UTXOS_SIZE_SAT,
        fee_rate=CREATE_UTXOS_FEE_RATE,
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
    asset_id = asset.asset_id
    print(f"{name}: issued NIA asset_id={asset_id}")
    return asset_id


def ensure_funded(node: rln.SdkNode, name: str, min_spendable_sat: int):
    bal = node.btc_balance(False)
    spendable = bal.vanilla.spendable
    print(f"{name} spendable sats: {spendable}")
    if spendable >= min_spendable_sat:
        return

    addr = node.address().address
    print(f"Funding {name} address {addr} with 0.02 BTC on regtest")
    run_regtest("sendtoaddress", addr, "0.02")
    run_regtest("mine", "6")
    node.sync()

    bal2 = node.btc_balance(False)
    spendable2 = bal2.vanilla.spendable
    print(f"{name} spendable sats after funding: {spendable2}")
    if spendable2 < min_spendable_sat:
        raise RuntimeError(
            f"{name} spendable balance still too low: {spendable2} < {min_spendable_sat}"
        )


def has_usable_channel(node: rln.SdkNode, asset_id: str | None = None) -> bool:
    channels = node.list_channels()
    if asset_id is None:
        return any(ch.is_usable for ch in channels)
    return any(ch.is_usable and str(ch.asset_id) == asset_id for ch in channels)


def wait_for_usable_channel(
    node_a: rln.SdkNode,
    node_b: rln.SdkNode,
    asset_id: str | None = None,
    timeout_sec: int = 120,
    mine_every_polls: int = 5,
):
    deadline = time.time() + timeout_sec
    last = []
    polls = 0
    while time.time() < deadline:
        polls += 1
        node_a.sync()
        node_b.sync()
        chans = node_a.list_channels()
        last = [
            (
                str(c.channel_id),
                c.status.name,
                c.is_usable,
                str(c.funding_txid),
                str(c.asset_id),
            )
            for c in chans
        ]
        if asset_id is None:
            ready = any(c.is_usable for c in chans)
        else:
            ready = any(c.is_usable and str(c.asset_id) == asset_id for c in chans)
        if ready:
            return
        if mine_every_polls > 0 and polls % mine_every_polls == 0:
            print("channel not usable yet, mining 1 block...")
            run_regtest("mine", "1")
        print("waiting for usable channel...")
        time.sleep(2)
    raise RuntimeError(f"No usable channel after {timeout_sec}s. last={last}")


def wait_for_channel_funding_tx(
    node_a: rln.SdkNode,
    node_b: rln.SdkNode,
    asset_id: str | None = None,
    timeout_sec: int = 120,
):
    deadline = time.time() + timeout_sec
    last = []
    while time.time() < deadline:
        node_a.sync()
        node_b.sync()
        chans = node_a.list_channels()
        last = [
            (
                str(c.channel_id),
                c.status.name,
                c.is_usable,
                str(c.funding_txid),
                str(c.asset_id),
            )
            for c in chans
        ]

        if asset_id is None:
            opening = next(
                (c for c in chans if c.funding_txid is not None),
                None,
            )
        else:
            opening = next(
                (
                    c
                    for c in chans
                    if str(c.asset_id) == asset_id and c.funding_txid is not None
                ),
                None,
            )

        if opening is not None:
            print(f"channel funding tx found: {opening.funding_txid}")
            return str(opening.funding_txid)

        print("waiting for channel funding tx broadcast...")
        time.sleep(1)

    raise RuntimeError(f"No funding tx after {timeout_sec}s. last={last}")


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


def wait_payment_final(node_b: rln.SdkNode, invoice: str, timeout_sec: int = 60):
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        node_b.sync()
        status = node_b.invoice_status(invoice)
        last = status
        if status in (rln.InvoiceStatus.SUCCEEDED, rln.InvoiceStatus.FAILED, rln.InvoiceStatus.EXPIRED):
            return status
        time.sleep(1)
    raise RuntimeError(f"Invoice did not finalize after {timeout_sec}s, last={last}")


def main():
    print("UniFFI N2N flow with createutxos + issueassetnia before asset channel open")
    print(f"node A storage: {NODE_A_STORAGE}")
    print(f"node B storage: {NODE_B_STORAGE}")

    ensure_dir(NODE_A_STORAGE)
    ensure_dir(NODE_B_STORAGE)

    node_a = make_node(NODE_A_STORAGE, NODE_A_DAEMON_PORT, NODE_A_PEER_PORT)
    node_b = make_node(NODE_B_STORAGE, NODE_B_DAEMON_PORT, NODE_B_PEER_PORT)

    try:
        init_if_needed(node_a, NODE_A_PASSWORD, "node A")
        init_if_needed(node_b, NODE_B_PASSWORD, "node B")

        unlock_if_needed(node_a, NODE_A_PASSWORD, "node A")
        unlock_if_needed(node_b, NODE_B_PASSWORD, "node B")

        ensure_funded(node_a, "node A", OPEN_CHANNEL_CAPACITY_SAT + 200_000)
        ensure_funded(node_b, "node B", 200_000)

        create_utxos(node_a, "node A")
        create_utxos(node_b, "node B")
        run_regtest("mine", "1")
        node_a.sync()
        node_b.sync()

        asset_id = issue_asset_nia(node_a, "node A")

        info_a = node_a.node_info()
        info_b = node_b.node_info()
        print("node A pubkey:", info_a.pubkey)
        print("node B pubkey:", info_b.pubkey)

        peer_uri = f"{info_b.pubkey}@127.0.0.1:{NODE_B_PEER_PORT}"
        try:
            node_a.connectpeer(peer_uri)
            print("connectpeer: ok")
        except rln.RlnError.Conflict:
            print("connectpeer: already connected")

        if has_usable_channel(node_a, asset_id):
            print(f"usable asset channel for {asset_id} already exists, skipping openchannel")
        else:
            open_req = rln.SdkOpenChannelRequest(
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
            open_resp = node_a.openchannel(open_req)
            print("openchannel temporary_channel_id:", open_resp.temporary_channel_id)

            funding_txid = wait_for_channel_funding_tx(
                node_a,
                node_b,
                asset_id=asset_id,
                timeout_sec=120,
            )

            print("Mining blocks one by one until funding tx is confirmed...")
            mine_until_tx_confirmed(node_a, funding_txid, 180)
            print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
            run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))

            wait_for_usable_channel(
                node_a,
                node_b,
                asset_id=asset_id,
                timeout_sec=CHANNEL_READY_TIMEOUT_SEC,
                mine_every_polls=5,
            )
            print("Channel is usable")

        print("node A channels:", len(node_a.list_channels()))
        print("node B channels:", len(node_b.list_channels()))

        if PAYMENT_MSAT < RGB_MIN_HTLC_MSAT:
            raise RuntimeError(
                f"PAYMENT_MSAT={PAYMENT_MSAT} is too low for RGB invoices, must be >= {RGB_MIN_HTLC_MSAT}"
            )

        inv_req = rln.LnInvoiceRequest(
            amt_msat=PAYMENT_MSAT,
            expiry_sec=3600,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
        )
        invoice = node_b.ln_invoice(inv_req).invoice
        print("invoice:", invoice)

        pay_req = rln.SdkSendPaymentRequest(
            invoice=invoice,
            amt_msat=PAYMENT_MSAT,
            asset_id=asset_id,
            asset_amount=PAYMENT_ASSET_AMOUNT,
        )
        pay_resp = node_a.sendpayment(pay_req)
        print("sendpayment status:", pay_resp.status.name)
        print("sendpayment payment_id:", pay_resp.payment_id)

        final_status = wait_payment_final(node_b, invoice)
        print("invoice final status on node B:", final_status.name)

        if final_status != rln.InvoiceStatus.SUCCEEDED:
            raise RuntimeError(f"Payment did not succeed (status={final_status})")

        print("SUCCESS: SDK-only node-to-node payment completed")
    finally:
        node_a.shutdown()
        node_b.shutdown()


if __name__ == "__main__":
    main()
