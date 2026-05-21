from pathlib import Path
import sqlite3
import time

import rgb_lightning_node as rln

from config import (
    CHANNEL_READY_TIMEOUT_SEC,
    NODE_A_DAEMON_PORT,
    NODE_A_PASSWORD,
    NODE_A_PEER_PORT,
    NODE_B_DAEMON_PORT,
    NODE_B_PASSWORD,
    NODE_B_PEER_PORT,
    NODE_C_DAEMON_PORT,
    NODE_C_PASSWORD,
    NODE_C_PEER_PORT,
    OPEN_CHANNEL_ASSET_AMOUNT,
    OPEN_CHANNEL_CAPACITY_SAT,
    OPEN_CHANNEL_CONFIRM_BLOCKS,
    OPEN_CHANNEL_PUSH_MSAT,
    PAYMENT_ASSET_AMOUNT,
    PAYMENT_MSAT,
    scenario_storage,
)
from harness import (
    assert_payment_core_fields,
    asset_balance_spendable,
    check_preimage_matches_hash,
    create_utxos,
    ensure_dir,
    ensure_funded_with_amount,
    get_block_count,
    init_if_needed,
    refresh_transfers,
    rgb_invoice,
    issue_asset_nia,
    make_node,
    mine_until_tx_confirmed,
    payment_hash_from_preimage,
    random_preimage_hex,
    run_regtest,
    safe_shutdown,
    unlock_if_needed,
    wait_for_channel_ready,
    wait_for_balance,
    wait_for_payment_state,
    wait_for_peer,
    wait_payment_final,
    wait_for_usable_channels,
)

INBOUND_PAYMENTS_FNAME = "inbound_payments"
LDK_DIR = ".ldk"
PAYMENT_HASH_LEN = 32
RLN_DB_FNAME = "rln_db"


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
            # We only need TLV type 16 from PaymentInfo, which stores claim_deadline_height.
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

    raise RuntimeError(
        f"payment_hash={payment_hash} not found in {source}"
    )


def wait_for_peer_channel_funding_tx(
    sender: rln.SdkNode,
    receiver_pubkey,
    asset_id,
    timeout_sec: int = 240,
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
            print(f"channel funding tx found for peer {receiver_pubkey}: {opening.funding_txid}")
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
    timeout_sec: int = 240,
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
        sender, receiver_info.pubkey, asset_id, 240
    )
    print(f"Mining blocks until {receiver_name} funding tx is confirmed...")
    mine_until_tx_confirmed(sender, funding_txid, 180)
    print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
    run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
    channel_id = sender.get_channel_id(open_response.temporary_channel_id)
    wait_for_channel_ready(sender, channel_id, 60)
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
    recipient_id = rgb_invoice(receiver)
    sender.send_rgb(
        rln.SendRgbRequest(
            donation=True,
            fee_rate=1,
            min_confirmations=1,
            recipient_groups=[
                rln.AssetRecipients(
                    asset_id=asset_id,
                    recipients=[
                        rln.RgbRecipient(
                            recipient_id=recipient_id,
                            witness_data=None,
                            assignment_kind=rln.AssignmentKind.FUNGIBLE,
                            assignment_amount=asset_amount,
                            transport_endpoints=["rpc://127.0.0.1:3000/json-rpc"],
                        )
                    ],
                )
            ],
        )
    )
    print(f"sent on-chain asset {asset_amount} to {receiver_name} for second channel setup")
    run_regtest("mine", "1")
    refresh_transfers(receiver)
    refresh_transfers(receiver)
    refresh_transfers(sender)
    wait_for_balance(receiver, asset_id, asset_amount, 180)


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
    timeout_sec: int = 60,
):
    deadline = time.time() + timeout_sec
    last_outbound = None
    last_inbound = None
    while time.time() < deadline:
        node.sync()
        balance = node.asset_balance(asset_id)
        last_outbound = balance.offchain_outbound
        last_inbound = balance.offchain_inbound
        if balance.offchain_outbound == expected_outbound and balance.offchain_inbound == expected_inbound:
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
    channel_id = open_hodl_asset_channel(node_a, node_b, "node B", node_b_peer_port, asset_id)

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

    # First prove the invoice is still claimable just before its timestamp-based expiry.
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

    # Use the exact LDK-provided block deadline instead of mining with a large margin.
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

    # The payment must still be alive immediately before the block deadline.
    receiver_pre_deadline = receiver.get_payment(
        payment_hash, rln.PaymentType.INBOUND_HODL
    )
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

    # Crossing the deadline should flip the held HTLC into a failed payment on both sides.
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

        ensure_funded_with_amount(
            node_a, "node A", OPEN_CHANNEL_CAPACITY_SAT * 2 + 300_000, "0.02"
        )
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

        node_a_asset = asset_balance_spendable(node_a, asset_id)
        node_b_asset = asset_balance_spendable(node_b, asset_id)
        print(f"node A spendable asset after transfer: {node_a_asset}")
        print(f"node B spendable asset after transfer: {node_b_asset}")

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

        wait_for_usable_channels(node_a, 1, 240)
        wait_for_usable_channels(node_b, 2, 240)
        wait_for_usable_channels(node_c, 1, 240)
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
            node_a, node_b, scenario, NODE_B_PEER_PORT + 30
        )
        run_hodl_time_expiry_phase(node_a, node_b, asset_id, channel_id)
        run_hodl_block_expiry_phase(node_a, node_b, node_b_storage, asset_id, channel_id)

        print("SUCCESS: Python HODL expiry flow completed")
    finally:
        safe_shutdown(node_a)
        safe_shutdown(node_b)
