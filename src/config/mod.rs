mod file;
#[cfg(test)]
mod tests;

pub(crate) use file::{load_config_file, TomlConfig};

use lightning::ln::channelmanager::{BREAKDOWN_TIMEOUT, MIN_CLTV_EXPIRY_DELTA};
use lightning::util::config::{
    ChannelConfig as LdkChannelConfig, ChannelHandshakeConfig as LdkChannelHandshakeConfig,
    ChannelHandshakeLimits as LdkChannelHandshakeLimits, MaxDustHTLCExposure,
};

use crate::error::AppError;
use crate::ldk::{FEE_RATE, MIN_CHANNEL_CONFIRMATIONS, UTXO_SIZE_SAT};
use crate::routes::{DEFAULT_FINAL_CLTV_EXPIRY_DELTA, DUST_LIMIT_MSAT, HTLC_MIN_MSAT};

pub(crate) const DEFAULT_CONFIG_FILENAME: &str = "config.toml";

const DEFAULT_ANNOUNCE_INITIAL_DELAY_SECS: u64 = 60;
const DEFAULT_ANNOUNCE_REFRESH_INTERVAL_SECS: u64 = 3600;
const DEFAULT_FEE_REFRESH_INTERVAL_SECS: u64 = 60;
const DEFAULT_MAX_SWAP_FEE_MSAT: u64 = 3_000_000;
const DEFAULT_OPENCHANNEL_MAX_SAT: u64 = 16_777_215;
const DEFAULT_OPENCHANNEL_MIN_RGB_AMT: u64 = 1;
const DEFAULT_OPENCHANNEL_MIN_SAT: u64 = 5506;
const DEFAULT_PASSWORD_MIN_LENGTH: u8 = 8;
const DEFAULT_PAYMENT_RETRY_TIMEOUT_SECS: u64 = 10;
const DEFAULT_PEER_RECONNECT_INTERVAL_SECS: u64 = 1;
// lnd's max to_self_delay is 2016, so we want to be compatible
const DEFAULT_THEIR_TO_SELF_DELAY: u16 = 2016;
const DEFAULT_UTXO_NUM: u8 = 4;

// BOLT-2 maximum for max_accepted_htlcs (LDK silently clamps higher values)
const MAX_ACCEPTED_HTLCS_CAP: u16 = 483;
const MAX_CHANNEL_SAT: u64 = 16_777_215;
const MAX_TO_SELF_DELAY: u16 = 2016;

/// Node settings resolved from built-in defaults overridden by the optional
/// TOML config file. With no config file every value matches the historical
/// hardcoded behavior.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Config {
    pub(crate) auth: AuthSection,
    pub(crate) chain: ChainSection,
    pub(crate) channels: ChannelsSection,
    pub(crate) node: NodeSection,
    pub(crate) payments: PaymentsSection,
    pub(crate) rgb: RgbSection,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AuthSection {
    pub(crate) password_min_length: u8,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            password_min_length: DEFAULT_PASSWORD_MIN_LENGTH,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChainSection {
    pub(crate) fee_refresh_interval_secs: u64,
}

impl Default for ChainSection {
    fn default() -> Self {
        Self {
            fee_refresh_interval_secs: DEFAULT_FEE_REFRESH_INTERVAL_SECS,
        }
    }
}

/// Maximum dust HTLC exposure, mirroring LDK's `MaxDustHTLCExposure`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DustExposure {
    FeeRateMultiplier(u64),
    FixedLimitMsat(u64),
}

impl DustExposure {
    fn from_ldk(value: MaxDustHTLCExposure) -> Self {
        match value {
            MaxDustHTLCExposure::FeeRateMultiplier(m) => Self::FeeRateMultiplier(m),
            MaxDustHTLCExposure::FixedLimitMsat(m) => Self::FixedLimitMsat(m),
        }
    }

    fn to_ldk(&self) -> MaxDustHTLCExposure {
        match self {
            Self::FeeRateMultiplier(m) => MaxDustHTLCExposure::FeeRateMultiplier(*m),
            Self::FixedLimitMsat(m) => MaxDustHTLCExposure::FixedLimitMsat(*m),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChannelsSection {
    pub(crate) accept_forwards_to_priv_channels: bool,
    pub(crate) cltv_expiry_delta: u16,
    pub(crate) dust_limit_msat: u64,
    pub(crate) forwarding_fee_base_msat: u32,
    pub(crate) forwarding_fee_proportional_millionths: u32,
    pub(crate) htlc_min_msat: u64,
    pub(crate) max_dust_htlc_exposure: DustExposure,
    pub(crate) max_inbound_htlc_value_in_flight_percent: u8,
    pub(crate) max_minimum_depth: u32,
    pub(crate) open_max_sat: u64,
    pub(crate) open_min_rgb_amount: u64,
    pub(crate) open_min_sat: u64,
    pub(crate) our_max_accepted_htlcs: u16,
    pub(crate) our_to_self_delay: u16,
    pub(crate) their_to_self_delay: u16,
}

impl Default for ChannelsSection {
    fn default() -> Self {
        // LDK-inherited defaults are sourced from LDK itself so they track the fork
        let ldk_channel = LdkChannelConfig::default();
        let ldk_handshake = LdkChannelHandshakeConfig::default();
        let ldk_limits = LdkChannelHandshakeLimits::default();
        Self {
            accept_forwards_to_priv_channels: false,
            cltv_expiry_delta: ldk_channel.cltv_expiry_delta,
            dust_limit_msat: DUST_LIMIT_MSAT,
            forwarding_fee_base_msat: ldk_channel.forwarding_fee_base_msat,
            forwarding_fee_proportional_millionths: ldk_channel
                .forwarding_fee_proportional_millionths,
            htlc_min_msat: HTLC_MIN_MSAT,
            max_dust_htlc_exposure: DustExposure::from_ldk(ldk_channel.max_dust_htlc_exposure),
            max_inbound_htlc_value_in_flight_percent: ldk_handshake
                .max_inbound_htlc_value_in_flight_percent_of_channel,
            max_minimum_depth: ldk_limits.max_minimum_depth,
            open_max_sat: DEFAULT_OPENCHANNEL_MAX_SAT,
            open_min_rgb_amount: DEFAULT_OPENCHANNEL_MIN_RGB_AMT,
            open_min_sat: DEFAULT_OPENCHANNEL_MIN_SAT,
            our_max_accepted_htlcs: ldk_handshake.our_max_accepted_htlcs,
            our_to_self_delay: ldk_handshake.our_to_self_delay,
            their_to_self_delay: DEFAULT_THEIR_TO_SELF_DELAY,
        }
    }
}

impl ChannelsSection {
    /// LDK per-channel config with the configured forwarding values applied.
    pub(crate) fn channel_config(&self) -> LdkChannelConfig {
        LdkChannelConfig {
            forwarding_fee_proportional_millionths: self.forwarding_fee_proportional_millionths,
            forwarding_fee_base_msat: self.forwarding_fee_base_msat,
            cltv_expiry_delta: self.cltv_expiry_delta,
            max_dust_htlc_exposure: self.max_dust_htlc_exposure.to_ldk(),
            ..Default::default()
        }
    }

    /// Minimum capacity for an RGB channel, derived from the HTLC minimum.
    pub(crate) fn open_rgb_min_sat(&self) -> u64 {
        self.htlc_min_msat / 1000 * 10 + 10
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NodeSection {
    pub(crate) announce_initial_delay_secs: u64,
    pub(crate) announce_refresh_interval_secs: u64,
    pub(crate) peer_reconnect_interval_secs: u64,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            announce_initial_delay_secs: DEFAULT_ANNOUNCE_INITIAL_DELAY_SECS,
            announce_refresh_interval_secs: DEFAULT_ANNOUNCE_REFRESH_INTERVAL_SECS,
            peer_reconnect_interval_secs: DEFAULT_PEER_RECONNECT_INTERVAL_SECS,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PaymentsSection {
    pub(crate) final_cltv_expiry_delta: u32,
    pub(crate) max_swap_fee_msat: u64,
    pub(crate) retry_timeout_secs: u64,
}

impl Default for PaymentsSection {
    fn default() -> Self {
        Self {
            final_cltv_expiry_delta: DEFAULT_FINAL_CLTV_EXPIRY_DELTA,
            max_swap_fee_msat: DEFAULT_MAX_SWAP_FEE_MSAT,
            retry_timeout_secs: DEFAULT_PAYMENT_RETRY_TIMEOUT_SECS,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RgbSection {
    pub(crate) fee_rate_sat_vb: u64,
    pub(crate) min_channel_confirmations: u8,
    pub(crate) utxo_num: u8,
    pub(crate) utxo_size_sat: u32,
}

impl Default for RgbSection {
    fn default() -> Self {
        Self {
            fee_rate_sat_vb: FEE_RATE,
            min_channel_confirmations: MIN_CHANNEL_CONFIRMATIONS,
            utxo_num: DEFAULT_UTXO_NUM,
            utxo_size_sat: UTXO_SIZE_SAT,
        }
    }
}

fn invalid(msg: String) -> AppError {
    AppError::InvalidConfig(msg)
}

impl Config {
    /// Overlay the file values on the defaults and validate the result.
    pub(crate) fn from_toml(toml: &TomlConfig) -> Result<Self, AppError> {
        if let Some(channels) = &toml.channels {
            if channels.max_dust_htlc_exposure_multiplier.is_some()
                && channels.max_dust_htlc_exposure_fixed_msat.is_some()
            {
                return Err(invalid(
                    "channels.max_dust_htlc_exposure_multiplier and \
                     channels.max_dust_htlc_exposure_fixed_msat are mutually exclusive"
                        .to_string(),
                ));
            }
        }
        let mut config = Config::default();
        config.apply_toml(toml);
        config.validate()?;
        Ok(config)
    }

    fn apply_toml(&mut self, toml: &TomlConfig) {
        if let Some(auth) = &toml.auth {
            apply(&mut self.auth.password_min_length, auth.password_min_length);
        }
        if let Some(chain) = &toml.chain {
            apply(
                &mut self.chain.fee_refresh_interval_secs,
                chain.fee_refresh_interval_secs,
            );
        }
        if let Some(channels) = &toml.channels {
            apply(
                &mut self.channels.accept_forwards_to_priv_channels,
                channels.accept_forwards_to_priv_channels,
            );
            apply(
                &mut self.channels.cltv_expiry_delta,
                channels.cltv_expiry_delta,
            );
            apply(&mut self.channels.dust_limit_msat, channels.dust_limit_msat);
            apply(
                &mut self.channels.forwarding_fee_base_msat,
                channels.forwarding_fee_base_msat,
            );
            apply(
                &mut self.channels.forwarding_fee_proportional_millionths,
                channels.forwarding_fee_proportional_millionths,
            );
            apply(&mut self.channels.htlc_min_msat, channels.htlc_min_msat);
            if let Some(fixed_msat) = channels.max_dust_htlc_exposure_fixed_msat {
                self.channels.max_dust_htlc_exposure = DustExposure::FixedLimitMsat(fixed_msat);
            }
            if let Some(multiplier) = channels.max_dust_htlc_exposure_multiplier {
                self.channels.max_dust_htlc_exposure = DustExposure::FeeRateMultiplier(multiplier);
            }
            apply(
                &mut self.channels.max_inbound_htlc_value_in_flight_percent,
                channels.max_inbound_htlc_value_in_flight_percent,
            );
            apply(
                &mut self.channels.max_minimum_depth,
                channels.max_minimum_depth,
            );
            apply(&mut self.channels.open_max_sat, channels.open_max_sat);
            apply(
                &mut self.channels.open_min_rgb_amount,
                channels.open_min_rgb_amount,
            );
            apply(&mut self.channels.open_min_sat, channels.open_min_sat);
            apply(
                &mut self.channels.our_max_accepted_htlcs,
                channels.our_max_accepted_htlcs,
            );
            apply(
                &mut self.channels.our_to_self_delay,
                channels.our_to_self_delay,
            );
            apply(
                &mut self.channels.their_to_self_delay,
                channels.their_to_self_delay,
            );
        }
        if let Some(node) = &toml.node {
            apply(
                &mut self.node.announce_initial_delay_secs,
                node.announce_initial_delay_secs,
            );
            apply(
                &mut self.node.announce_refresh_interval_secs,
                node.announce_refresh_interval_secs,
            );
            apply(
                &mut self.node.peer_reconnect_interval_secs,
                node.peer_reconnect_interval_secs,
            );
        }
        if let Some(payments) = &toml.payments {
            apply(
                &mut self.payments.final_cltv_expiry_delta,
                payments.final_cltv_expiry_delta,
            );
            apply(
                &mut self.payments.max_swap_fee_msat,
                payments.max_swap_fee_msat,
            );
            apply(
                &mut self.payments.retry_timeout_secs,
                payments.retry_timeout_secs,
            );
        }
        if let Some(rgb) = &toml.rgb {
            apply(&mut self.rgb.fee_rate_sat_vb, rgb.fee_rate_sat_vb);
            apply(
                &mut self.rgb.min_channel_confirmations,
                rgb.min_channel_confirmations,
            );
            apply(&mut self.rgb.utxo_num, rgb.utxo_num);
            apply(&mut self.rgb.utxo_size_sat, rgb.utxo_size_sat);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), AppError> {
        nonzero(
            self.auth.password_min_length as u64,
            "auth.password_min_length",
        )?;
        nonzero(
            self.chain.fee_refresh_interval_secs,
            "chain.fee_refresh_interval_secs",
        )?;
        if self.channels.cltv_expiry_delta < MIN_CLTV_EXPIRY_DELTA {
            return Err(invalid(format!(
                "channels.cltv_expiry_delta must be at least {MIN_CLTV_EXPIRY_DELTA}"
            )));
        }
        nonzero(self.channels.dust_limit_msat, "channels.dust_limit_msat")?;
        nonzero(self.channels.htlc_min_msat, "channels.htlc_min_msat")?;
        match self.channels.max_dust_htlc_exposure {
            DustExposure::FeeRateMultiplier(0) => {
                return Err(invalid(
                    "channels.max_dust_htlc_exposure_multiplier must be greater than 0".to_string(),
                ));
            }
            DustExposure::FixedLimitMsat(0) => {
                return Err(invalid(
                    "channels.max_dust_htlc_exposure_fixed_msat must be greater than 0".to_string(),
                ));
            }
            _ => {}
        }
        if self.channels.max_inbound_htlc_value_in_flight_percent == 0
            || self.channels.max_inbound_htlc_value_in_flight_percent > 100
        {
            return Err(invalid(
                "channels.max_inbound_htlc_value_in_flight_percent must be between 1 and 100"
                    .to_string(),
            ));
        }
        nonzero(
            self.channels.max_minimum_depth as u64,
            "channels.max_minimum_depth",
        )?;
        if self.channels.open_max_sat > MAX_CHANNEL_SAT {
            return Err(invalid(format!(
                "channels.open_max_sat cannot exceed the protocol limit of {MAX_CHANNEL_SAT} sats"
            )));
        }
        nonzero(
            self.channels.open_min_rgb_amount,
            "channels.open_min_rgb_amount",
        )?;
        nonzero(self.channels.open_min_sat, "channels.open_min_sat")?;
        if self.channels.open_min_sat > self.channels.open_max_sat {
            return Err(invalid(format!(
                "channels.open_min_sat ({}) cannot exceed channels.open_max_sat ({})",
                self.channels.open_min_sat, self.channels.open_max_sat
            )));
        }
        if self.channels.open_rgb_min_sat() > self.channels.open_max_sat {
            return Err(invalid(format!(
                "the RGB channel minimum derived from channels.htlc_min_msat ({} sats) \
                 cannot exceed channels.open_max_sat ({})",
                self.channels.open_rgb_min_sat(),
                self.channels.open_max_sat
            )));
        }
        if self.channels.our_max_accepted_htlcs == 0
            || self.channels.our_max_accepted_htlcs > MAX_ACCEPTED_HTLCS_CAP
        {
            return Err(invalid(format!(
                "channels.our_max_accepted_htlcs must be between 1 and {MAX_ACCEPTED_HTLCS_CAP}"
            )));
        }
        if self.channels.our_to_self_delay < BREAKDOWN_TIMEOUT
            || self.channels.our_to_self_delay > MAX_TO_SELF_DELAY
        {
            return Err(invalid(format!(
                "channels.our_to_self_delay must be between {BREAKDOWN_TIMEOUT} and {MAX_TO_SELF_DELAY}"
            )));
        }
        if self.channels.their_to_self_delay == 0
            || self.channels.their_to_self_delay > MAX_TO_SELF_DELAY
        {
            return Err(invalid(format!(
                "channels.their_to_self_delay must be between 1 and {MAX_TO_SELF_DELAY}"
            )));
        }
        nonzero(
            self.node.announce_refresh_interval_secs,
            "node.announce_refresh_interval_secs",
        )?;
        nonzero(
            self.node.peer_reconnect_interval_secs,
            "node.peer_reconnect_interval_secs",
        )?;
        nonzero(
            self.payments.final_cltv_expiry_delta as u64,
            "payments.final_cltv_expiry_delta",
        )?;
        nonzero(
            self.payments.max_swap_fee_msat,
            "payments.max_swap_fee_msat",
        )?;
        nonzero(
            self.payments.retry_timeout_secs,
            "payments.retry_timeout_secs",
        )?;
        nonzero(self.rgb.fee_rate_sat_vb, "rgb.fee_rate_sat_vb")?;
        nonzero(
            self.rgb.min_channel_confirmations as u64,
            "rgb.min_channel_confirmations",
        )?;
        nonzero(self.rgb.utxo_num as u64, "rgb.utxo_num")?;
        nonzero(self.rgb.utxo_size_sat as u64, "rgb.utxo_size_sat")?;
        Ok(())
    }
}

fn apply<T: Copy>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

fn nonzero(value: u64, key: &str) -> Result<(), AppError> {
    if value == 0 {
        return Err(invalid(format!("{key} must be greater than 0")));
    }
    Ok(())
}
