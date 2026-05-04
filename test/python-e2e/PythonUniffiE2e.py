#!/usr/bin/env python3
import os
import sys

from hodl import hodl_e2e_scenario, hodl_expiry_scenario
from openchannel import (
    getchannelid_fail_scenario,
    openchannel_fail_no_utxos_scenario,
    openchannel_fail_unknown_asset_scenario,
    openchannel_push_asset_amount_scenario,
)
from payment import payment_scenario

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
