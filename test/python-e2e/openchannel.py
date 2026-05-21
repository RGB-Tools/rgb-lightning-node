import rgb_lightning_node as rln

from config import (
    CREATE_UTXOS_FEE_RATE,
    NODE_A_DAEMON_PORT,
    NODE_A_PASSWORD,
    NODE_A_PEER_PORT,
    NODE_B_DAEMON_PORT,
    NODE_B_PASSWORD,
    NODE_B_PEER_PORT,
    NODE_C_DAEMON_PORT,
    NODE_C_PASSWORD,
    NODE_C_PEER_PORT,
    OPEN_CHANNEL_CONFIRM_BLOCKS,
    PROXY_ENDPOINT_LOCAL,
    scenario_storage,
)
from harness import (
    asset_balance_spendable,
    close_channel,
    fund_and_create_utxos,
    init_if_needed,
    issue_asset_nia,
    keysend,
    keysend_with_ln_balance,
    make_node,
    mine_until_tx_confirmed,
    refresh_transfers,
    rgb_invoice,
    run_regtest,
    safe_shutdown,
    unlock_if_needed,
    unlock_request,
    wait_for_balance,
    wait_for_channel_asset_state,
    wait_for_channel_funding_tx,
    wait_for_channel_id,
    wait_for_channel_ready,
    wait_for_payment_status,
    wait_for_peer,
    wait_for_usable_channels,
    ensure_dir,
)


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
        node_a = make_node(
            node_a_storage, NODE_A_DAEMON_PORT + daemon_offset, NODE_A_PEER_PORT + peer_offset
        )
        node_b = make_node(
            node_b_storage, NODE_B_DAEMON_PORT + daemon_offset, NODE_B_PEER_PORT + peer_offset
        )
        node_c = make_node(
            node_c_storage, NODE_C_DAEMON_PORT + daemon_offset, NODE_C_PEER_PORT + peer_offset
        )

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
        wait_for_balance(node_a, asset_id, 1000, 180)
        peer_uri = f"{node_b_pubkey}@127.0.0.1:{NODE_B_PEER_PORT + peer_offset}"
        node_a.connectpeer(peer_uri)
        wait_for_peer(node_a, node_b_pubkey, 20)
        wait_for_peer(node_b, node_a_pubkey, 20)

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
        print(
            "partial_push_channel temporary_channel_id: "
            f"{partial_push_channel.temporary_channel_id}"
        )

        funding_txid = wait_for_channel_funding_tx(node_a, node_b, asset_id, 240)
        print("Mining blocks one by one until funding tx is confirmed...")
        mine_until_tx_confirmed(node_a, funding_txid, 180)
        print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        partial_channel_id = wait_for_channel_id(
            node_a, partial_push_channel.temporary_channel_id, 10
        )
        wait_for_channel_ready(node_a, partial_channel_id, 120)
        node_a_partial = next(
            c for c in node_a.list_channels() if c.channel_id == partial_channel_id
        )
        node_b_partial = next(
            c for c in node_b.list_channels() if c.channel_id == partial_channel_id
        )
        assert (
            node_a_partial.asset_local_amount == 350
            and node_a_partial.asset_remote_amount == 250
        )
        assert (
            node_b_partial.asset_local_amount == 250
            and node_b_partial.asset_remote_amount == 350
        )

        keysend_with_ln_balance(node_a, node_b, node_b_pubkey, None, asset_id, 100, 350, 250)
        wait_for_channel_asset_state(
            "node A partial push after first RGB keysend",
            node_a,
            partial_channel_id,
            250,
            350,
            None,
            30,
        )
        wait_for_channel_asset_state(
            "node B partial push after first RGB keysend",
            node_b,
            partial_channel_id,
            350,
            250,
            None,
            30,
        )
        btc_payment_hash = keysend(node_a, node_b_pubkey, 10_000_000, None, None)
        wait_for_payment_status(
            node_b, btc_payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60
        )
        wait_for_channel_asset_state(
            "node B partial push before reverse RGB keysend",
            node_b,
            partial_channel_id,
            350,
            250,
            3_000_000,
            30,
        )
        keysend_with_ln_balance(node_b, node_a, node_a_pubkey, None, asset_id, 50, 350, 250)

        node_a_partial_after = next(
            c for c in node_a.list_channels() if c.channel_id == partial_channel_id
        )
        node_b_partial_after = next(
            c for c in node_b.list_channels() if c.channel_id == partial_channel_id
        )
        assert (
            node_a_partial_after.asset_local_amount == 300
            and node_a_partial_after.asset_remote_amount == 300
        )
        assert (
            node_b_partial_after.asset_local_amount == 300
            and node_b_partial_after.asset_remote_amount == 300
        )

        close_channel(node_a, partial_channel_id, node_b_pubkey)
        wait_for_balance(node_a, asset_id, 700, 180)
        wait_for_balance(node_b, asset_id, 300, 180)

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

        funding_txid = wait_for_channel_funding_tx(node_a, node_b, asset_id, 240)
        print("Mining blocks one by one until funding tx is confirmed...")
        mine_until_tx_confirmed(node_a, funding_txid, 180)
        print(f"Mining {OPEN_CHANNEL_CONFIRM_BLOCKS} blocks for channel confirmations...")
        run_regtest("mine", str(OPEN_CHANNEL_CONFIRM_BLOCKS))
        full_channel_id = wait_for_channel_id(node_a, full_push_channel.temporary_channel_id, 10)
        wait_for_channel_ready(node_a, full_channel_id, 120)

        node_a.shutdown()
        node_b.shutdown()
        node_a = make_node(
            node_a_storage, NODE_A_DAEMON_PORT + daemon_offset, NODE_A_PEER_PORT + peer_offset
        )
        node_b = make_node(
            node_b_storage, NODE_B_DAEMON_PORT + daemon_offset, NODE_B_PEER_PORT + peer_offset
        )
        node_a.unlock(unlock_request(NODE_A_PASSWORD))
        node_b.unlock(unlock_request(NODE_B_PASSWORD))

        wait_for_usable_channels(node_a, 1, 240)
        wait_for_usable_channels(node_b, 1, 240)

        assert asset_balance_spendable(node_a, asset_id) == 100
        assert asset_balance_spendable(node_b, asset_id) == 300

        node_a_full = next(c for c in node_a.list_channels() if c.channel_id == full_channel_id)
        node_b_full = next(c for c in node_b.list_channels() if c.channel_id == full_channel_id)
        assert node_a_full.asset_local_amount == 0 and node_a_full.asset_remote_amount == 600
        assert node_b_full.asset_local_amount == 600 and node_b_full.asset_remote_amount == 0

        btc_payment_hash = keysend(node_a, node_b_pubkey, 10_000_000, None, None)
        wait_for_payment_status(
            node_b, btc_payment_hash, rln.PaymentType.INBOUND_AUTO_CLAIM, 60
        )
        keysend_with_ln_balance(node_b, node_a, node_a_pubkey, None, asset_id, 100, 600, 0)

        node_a_full_after = next(
            c for c in node_a.list_channels() if c.channel_id == full_channel_id
        )
        node_b_full_after = next(
            c for c in node_b.list_channels() if c.channel_id == full_channel_id
        )
        assert (
            node_a_full_after.asset_local_amount == 100
            and node_a_full_after.asset_remote_amount == 500
        )
        assert (
            node_b_full_after.asset_local_amount == 500
            and node_b_full_after.asset_remote_amount == 100
        )

        close_channel(node_a, full_channel_id, node_b_pubkey)
        wait_for_balance(node_a, asset_id, 200, 180)
        wait_for_balance(node_b, asset_id, 800, 180)

        recipient_id = rgb_invoice(node_c)
        node_b.send_rgb(
            rln.SendRgbRequest(
                donation=True,
                fee_rate=CREATE_UTXOS_FEE_RATE,
                min_confirmations=1,
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
