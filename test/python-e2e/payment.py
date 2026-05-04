import rgb_lightning_node as rln

from config import (
    CHANNEL_READY_TIMEOUT_SEC,
    NODE_A_DAEMON_PORT,
    NODE_A_PASSWORD,
    NODE_A_PEER_PORT,
    NODE_B_DAEMON_PORT,
    NODE_B_PASSWORD,
    NODE_B_PEER_PORT,
    OPEN_CHANNEL_ASSET_AMOUNT,
    OPEN_CHANNEL_CAPACITY_SAT,
    OPEN_CHANNEL_CONFIRM_BLOCKS,
    OPEN_CHANNEL_PUSH_MSAT,
    PAYMENT_ASSET_AMOUNT,
    PAYMENT_MSAT,
    RGB_MIN_HTLC_MSAT,
    scenario_storage,
)
from harness import (
    check_preimage_matches_hash,
    create_utxos,
    ensure_dir,
    ensure_funded_with_amount,
    init_if_needed,
    issue_asset_nia,
    make_node,
    mine_until_tx_confirmed,
    run_regtest,
    safe_shutdown,
    unlock_if_needed,
    wait_for_channel_funding_tx,
    wait_for_channel_ready,
    wait_for_payment_present_in_list,
    wait_for_payment_status,
    wait_for_peer,
    wait_for_usable_channel,
    wait_payment_final,
)


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
