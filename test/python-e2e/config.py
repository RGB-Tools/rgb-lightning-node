import os
from pathlib import Path

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

RGB_MIN_HTLC_MSAT = 3_000_000
PROXY_ENDPOINT_LOCAL = "rpc://127.0.0.1:3000/json-rpc"


def scenario_storage(scenario: str, node_name: str) -> Path:
    return E2E_ROOT / "data" / scenario / node_name
