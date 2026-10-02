use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::AppError;

/// Mirror of the TOML config file. Every field is optional: absent keys keep
/// the built-in defaults, unknown keys are hard errors.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlConfig {
    pub(crate) auth: Option<TomlAuth>,
    pub(crate) chain: Option<TomlChain>,
    pub(crate) channels: Option<TomlChannels>,
    pub(crate) media: Option<TomlMedia>,
    pub(crate) node: Option<TomlNode>,
    pub(crate) payments: Option<TomlPayments>,
    pub(crate) rgb: Option<TomlRgb>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlAuth {
    pub(crate) disable_authentication: Option<bool>,
    pub(crate) password_min_length: Option<u8>,
    pub(crate) root_public_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlChain {
    pub(crate) fee_refresh_interval_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlChannels {
    pub(crate) accept_forwards_to_priv_channels: Option<bool>,
    pub(crate) cltv_expiry_delta: Option<u16>,
    pub(crate) dust_limit_msat: Option<u64>,
    pub(crate) forwarding_fee_base_msat: Option<u32>,
    pub(crate) forwarding_fee_proportional_millionths: Option<u32>,
    pub(crate) htlc_min_msat: Option<u64>,
    pub(crate) max_dust_htlc_exposure_fixed_msat: Option<u64>,
    pub(crate) max_dust_htlc_exposure_multiplier: Option<u64>,
    pub(crate) max_inbound_htlc_value_in_flight_percent: Option<u8>,
    pub(crate) max_minimum_depth: Option<u32>,
    pub(crate) open_max_sat: Option<u64>,
    pub(crate) open_min_rgb_amount: Option<u64>,
    pub(crate) open_min_sat: Option<u64>,
    pub(crate) our_max_accepted_htlcs: Option<u16>,
    pub(crate) our_to_self_delay: Option<u16>,
    pub(crate) their_to_self_delay: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlMedia {
    pub(crate) max_aggregated_media_size_per_channel_mb: Option<u16>,
    pub(crate) max_media_files_per_channel: Option<usize>,
    pub(crate) max_media_upload_size_mb: Option<u16>,
    pub(crate) max_pending_consignments: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlNode {
    pub(crate) announce_initial_delay_secs: Option<u64>,
    pub(crate) announce_refresh_interval_secs: Option<u64>,
    pub(crate) daemon_listening_port: Option<u16>,
    pub(crate) ldk_peer_listening_port: Option<u16>,
    pub(crate) network: Option<String>,
    pub(crate) peer_reconnect_interval_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlPayments {
    pub(crate) final_cltv_expiry_delta: Option<u32>,
    pub(crate) max_swap_fee_msat: Option<u64>,
    pub(crate) retry_timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TomlRgb {
    pub(crate) fee_rate_sat_vb: Option<u64>,
    pub(crate) min_channel_confirmations: Option<u8>,
    pub(crate) utxo_num: Option<u8>,
    pub(crate) utxo_size_sat: Option<u32>,
}

impl TomlConfig {
    pub(crate) fn parse(content: &str) -> Result<Self, AppError> {
        toml::from_str(content).map_err(|e| AppError::InvalidConfig(e.to_string()))
    }
}

pub(crate) fn load_config_file(path: &Path) -> Result<TomlConfig, AppError> {
    let content = fs::read_to_string(path).map_err(|e| {
        AppError::InvalidConfig(format!("cannot read config file {}: {e}", path.display()))
    })?;
    TomlConfig::parse(&content).map_err(|e| match e {
        AppError::InvalidConfig(m) => AppError::InvalidConfig(format!("{}: {m}", path.display())),
        other => other,
    })
}
