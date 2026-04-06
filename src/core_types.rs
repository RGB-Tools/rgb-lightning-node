use lightning::impl_writeable_tlv_based_enum;
use serde::{Deserialize, Serialize};

pub(crate) const FEE_RATE: u64 = 7;
pub(crate) const UTXO_SIZE_SAT: u32 = 32000;
pub(crate) const MIN_CHANNEL_CONFIRMATIONS: u8 = 6;
pub(crate) const DUST_LIMIT_MSAT: u64 = 546000;
pub(crate) const HTLC_MIN_MSAT: u64 = 3_000_000;
pub(crate) const MAX_SWAP_FEE_MSAT: u64 = HTLC_MIN_MSAT;
pub(crate) const DEFAULT_FINAL_CLTV_EXPIRY_DELTA: u32 = 14;

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub(crate) enum HTLCStatus {
    Pending,
    Succeeded,
    Failed,
    Claimable,
    Claiming,
    Cancelled,
}

impl std::fmt::Display for HTLCStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            HTLCStatus::Pending => "Pending",
            HTLCStatus::Succeeded => "Succeeded",
            HTLCStatus::Failed => "Failed",
            HTLCStatus::Claimable => "Claimable",
            HTLCStatus::Claiming => "Claiming",
            HTLCStatus::Cancelled => "Cancelled",
        };
        write!(f, "{label}")
    }
}

impl_writeable_tlv_based_enum!(HTLCStatus,
    (0, Pending) => {},
    (1, Succeeded) => {},
    (2, Failed) => {},
    (3, Claimable) => {},
    (4, Claiming) => {},
    (5, Cancelled) => {},
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum SwapStatus {
    Waiting,
    Pending,
    Succeeded,
    Expired,
    Failed,
}

impl_writeable_tlv_based_enum!(SwapStatus,
    (0, Waiting) => {},
    (1, Pending) => {},
    (2, Succeeded) => {},
    (3, Expired) => {},
    (4, Failed) => {},
);

#[derive(Clone, Debug)]
pub(crate) struct UnlockRequest {
    pub(crate) bitcoind_rpc_username: String,
    pub(crate) bitcoind_rpc_password: String,
    pub(crate) bitcoind_rpc_host: String,
    pub(crate) bitcoind_rpc_port: u16,
    pub(crate) indexer_url: Option<String>,
    pub(crate) proxy_endpoint: Option<String>,
    pub(crate) announce_addresses: Vec<String>,
    pub(crate) announce_alias: Option<String>,
}
