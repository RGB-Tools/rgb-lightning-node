use super::*;

fn cfg(content: &str) -> Result<Config, AppError> {
    Config::from_toml(&TomlConfig::parse(content)?)
}

fn err_msg(res: Result<Config, AppError>) -> String {
    match res {
        Err(AppError::InvalidConfig(m)) => m,
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn defaults_match_hardcoded_values() {
    let c = Config::default();
    assert_eq!(c.auth.password_min_length, 8);
    assert_eq!(c.channels.dust_limit_msat, 546_000);
    assert_eq!(c.channels.htlc_min_msat, 3_000_000);
    assert_eq!(c.channels.open_max_sat, 16_777_215);
    assert_eq!(c.channels.open_min_rgb_amount, 1);
    assert_eq!(c.channels.open_min_sat, 5506);
    assert_eq!(c.channels.open_rgb_min_sat(), 30_010);
    assert_eq!(c.channels.their_to_self_delay, 2016);
    assert_eq!(c.payments.final_cltv_expiry_delta, 14);
    assert_eq!(c.payments.max_swap_fee_msat, 3_000_000);
    assert_eq!(c.payments.retry_timeout_secs, 10);
    assert_eq!(c.rgb.fee_rate_sat_vb, 7);
    assert_eq!(c.rgb.min_channel_confirmations, 6);
    assert_eq!(c.rgb.utxo_num, 4);
    assert_eq!(c.rgb.utxo_size_sat, 32000);
    assert!(c.validate().is_ok());
}

#[test]
fn timing_defaults_match_hardcoded_values() {
    let c = Config::default();
    assert_eq!(c.chain.fee_refresh_interval_secs, 60);
    assert_eq!(c.node.announce_initial_delay_secs, 60);
    assert_eq!(c.node.announce_refresh_interval_secs, 3600);
    assert_eq!(c.node.peer_reconnect_interval_secs, 1);
}

#[test]
fn empty_toml_keeps_defaults() {
    assert_eq!(cfg("").unwrap(), Config::default());
}

#[test]
fn partial_override_leaves_other_defaults() {
    let c = cfg("[rgb]\nfee_rate_sat_vb = 12\n").unwrap();
    assert_eq!(c.rgb.fee_rate_sat_vb, 12);
    assert_eq!(c.rgb.utxo_size_sat, 32000);
    assert_eq!(c.channels, Config::default().channels);
}

#[test]
fn all_policy_sections_apply() {
    let c = cfg(r#"
[auth]
password_min_length = 12

[chain]
fee_refresh_interval_secs = 120

[channels]
dust_limit_msat = 600000
htlc_min_msat = 2000000
open_max_sat = 1000000
open_min_rgb_amount = 2
open_min_sat = 10000
their_to_self_delay = 1440

[node]
announce_initial_delay_secs = 30
announce_refresh_interval_secs = 1800
peer_reconnect_interval_secs = 2

[payments]
final_cltv_expiry_delta = 18
max_swap_fee_msat = 5000000
retry_timeout_secs = 30

[rgb]
fee_rate_sat_vb = 3
min_channel_confirmations = 3
utxo_num = 8
utxo_size_sat = 64000
"#)
    .unwrap();
    assert_eq!(c.auth.password_min_length, 12);
    assert_eq!(c.chain.fee_refresh_interval_secs, 120);
    assert_eq!(c.channels.dust_limit_msat, 600_000);
    assert_eq!(c.channels.htlc_min_msat, 2_000_000);
    assert_eq!(c.channels.open_max_sat, 1_000_000);
    assert_eq!(c.channels.open_min_rgb_amount, 2);
    assert_eq!(c.channels.open_min_sat, 10_000);
    assert_eq!(c.channels.open_rgb_min_sat(), 20_010);
    assert_eq!(c.channels.their_to_self_delay, 1440);
    assert_eq!(c.node.announce_initial_delay_secs, 30);
    assert_eq!(c.node.announce_refresh_interval_secs, 1800);
    assert_eq!(c.node.peer_reconnect_interval_secs, 2);
    assert_eq!(c.payments.final_cltv_expiry_delta, 18);
    assert_eq!(c.payments.max_swap_fee_msat, 5_000_000);
    assert_eq!(c.payments.retry_timeout_secs, 30);
    assert_eq!(c.rgb.fee_rate_sat_vb, 3);
    assert_eq!(c.rgb.min_channel_confirmations, 3);
    assert_eq!(c.rgb.utxo_num, 8);
    assert_eq!(c.rgb.utxo_size_sat, 64000);
}

#[test]
fn startup_sections_parse() {
    let t = TomlConfig::parse(
        r#"
[auth]
disable_authentication = true

[media]
max_aggregated_media_size_per_channel_mb = 48
max_media_files_per_channel = 84
max_media_upload_size_mb = 10
max_pending_consignments = 20

[node]
daemon_listening_port = 8888
ldk_peer_listening_port = 9999
network = "regtest"
"#,
    )
    .unwrap();
    let auth = t.auth.unwrap();
    assert_eq!(auth.disable_authentication, Some(true));
    let media = t.media.unwrap();
    assert_eq!(media.max_aggregated_media_size_per_channel_mb, Some(48));
    assert_eq!(media.max_media_files_per_channel, Some(84));
    assert_eq!(media.max_media_upload_size_mb, Some(10));
    assert_eq!(media.max_pending_consignments, Some(20));
    let node = t.node.unwrap();
    assert_eq!(node.daemon_listening_port, Some(8888));
    assert_eq!(node.ldk_peer_listening_port, Some(9999));
    assert_eq!(node.network.as_deref(), Some("regtest"));
}

#[test]
fn unknown_section_rejected() {
    let res = TomlConfig::parse("[bogus]\nkey = 1\n");
    assert!(matches!(res, Err(AppError::InvalidConfig(ref m)) if m.contains("bogus")));
}

#[test]
fn unknown_key_rejected() {
    let res = TomlConfig::parse("[rgb]\nbogus_key = 1\n");
    assert!(matches!(res, Err(AppError::InvalidConfig(ref m)) if m.contains("bogus_key")));
}

#[test]
fn wrong_type_rejected() {
    assert!(TomlConfig::parse("[rgb]\nfee_rate_sat_vb = \"high\"\n").is_err());
}

#[test]
fn zero_fee_rate_rejected() {
    let m = err_msg(cfg("[rgb]\nfee_rate_sat_vb = 0\n"));
    assert!(m.contains("fee_rate_sat_vb"));
}

#[test]
fn zero_utxo_size_rejected() {
    let m = err_msg(cfg("[rgb]\nutxo_size_sat = 0\n"));
    assert!(m.contains("utxo_size_sat"));
}

#[test]
fn zero_utxo_num_rejected() {
    let m = err_msg(cfg("[rgb]\nutxo_num = 0\n"));
    assert!(m.contains("utxo_num"));
}

#[test]
fn zero_min_channel_confirmations_rejected() {
    let m = err_msg(cfg("[rgb]\nmin_channel_confirmations = 0\n"));
    assert!(m.contains("min_channel_confirmations"));
}

#[test]
fn zero_htlc_min_rejected() {
    let m = err_msg(cfg("[channels]\nhtlc_min_msat = 0\n"));
    assert!(m.contains("htlc_min_msat"));
}

#[test]
fn zero_dust_limit_rejected() {
    let m = err_msg(cfg("[channels]\ndust_limit_msat = 0\n"));
    assert!(m.contains("dust_limit_msat"));
}

#[test]
fn zero_open_min_rejected() {
    let m = err_msg(cfg("[channels]\nopen_min_sat = 0\n"));
    assert!(m.contains("open_min_sat"));
}

#[test]
fn open_min_above_max_rejected() {
    let m = err_msg(cfg(
        "[channels]\nopen_min_sat = 20000\nopen_max_sat = 10000\n",
    ));
    assert!(m.contains("open_min_sat") && m.contains("open_max_sat"));
}

#[test]
fn open_max_above_protocol_cap_rejected() {
    let m = err_msg(cfg("[channels]\nopen_max_sat = 16777216\n"));
    assert!(m.contains("open_max_sat"));
}

#[test]
fn derived_rgb_min_above_max_rejected() {
    // 20_000_000_000 msat derives a 200_000_010 sat RGB minimum, above the default open_max_sat
    let m = err_msg(cfg("[channels]\nhtlc_min_msat = 20000000000\n"));
    assert!(m.contains("open_max_sat"));
}

#[test]
fn zero_open_min_rgb_amount_rejected() {
    let m = err_msg(cfg("[channels]\nopen_min_rgb_amount = 0\n"));
    assert!(m.contains("open_min_rgb_amount"));
}

#[test]
fn zero_their_to_self_delay_rejected() {
    let m = err_msg(cfg("[channels]\ntheir_to_self_delay = 0\n"));
    assert!(m.contains("their_to_self_delay"));
}

#[test]
fn their_to_self_delay_above_2016_rejected() {
    let m = err_msg(cfg("[channels]\ntheir_to_self_delay = 2017\n"));
    assert!(m.contains("their_to_self_delay"));
}

#[test]
fn zero_final_cltv_rejected() {
    let m = err_msg(cfg("[payments]\nfinal_cltv_expiry_delta = 0\n"));
    assert!(m.contains("final_cltv_expiry_delta"));
}

#[test]
fn zero_retry_timeout_rejected() {
    let m = err_msg(cfg("[payments]\nretry_timeout_secs = 0\n"));
    assert!(m.contains("retry_timeout_secs"));
}

#[test]
fn zero_max_swap_fee_rejected() {
    let m = err_msg(cfg("[payments]\nmax_swap_fee_msat = 0\n"));
    assert!(m.contains("max_swap_fee_msat"));
}

#[test]
fn zero_password_min_length_rejected() {
    let m = err_msg(cfg("[auth]\npassword_min_length = 0\n"));
    assert!(m.contains("password_min_length"));
}

#[test]
fn zero_timing_values_rejected() {
    for (section, key) in [
        ("chain", "fee_refresh_interval_secs"),
        ("node", "announce_refresh_interval_secs"),
        ("node", "peer_reconnect_interval_secs"),
    ] {
        let m = err_msg(cfg(&format!("[{section}]\n{key} = 0\n")));
        assert!(m.contains(key), "expected error naming {key}, got: {m}");
    }
}

#[test]
fn zero_announce_initial_delay_allowed() {
    let c = cfg("[node]\nannounce_initial_delay_secs = 0\n").unwrap();
    assert_eq!(c.node.announce_initial_delay_secs, 0);
}

#[test]
fn load_missing_file_errors() {
    assert!(matches!(
        load_config_file(std::path::Path::new("/nonexistent/config.toml")),
        Err(AppError::InvalidConfig(_))
    ));
}

#[test]
fn ldk_channel_defaults_match_upstream() {
    let c = Config::default();
    assert_eq!(c.channels.cltv_expiry_delta, 72);
    assert_eq!(c.channels.forwarding_fee_base_msat, 1000);
    assert_eq!(c.channels.forwarding_fee_proportional_millionths, 0);
    assert_eq!(
        c.channels.max_dust_htlc_exposure,
        DustExposure::FeeRateMultiplier(10000)
    );
    assert_eq!(c.channels.max_inbound_htlc_value_in_flight_percent, 10);
    assert_eq!(c.channels.max_minimum_depth, 144);
    assert_eq!(c.channels.our_max_accepted_htlcs, 50);
    assert_eq!(c.channels.our_to_self_delay, 144);
    assert_eq!(
        c.channels.channel_config(),
        lightning::util::config::ChannelConfig::default()
    );
}

#[test]
fn ldk_channel_overrides_apply() {
    let c = cfg(r#"
[channels]
cltv_expiry_delta = 80
forwarding_fee_base_msat = 0
forwarding_fee_proportional_millionths = 100
max_dust_htlc_exposure_fixed_msat = 5000000
max_inbound_htlc_value_in_flight_percent = 25
max_minimum_depth = 6
our_max_accepted_htlcs = 100
our_to_self_delay = 288
"#)
    .unwrap();
    assert_eq!(c.channels.cltv_expiry_delta, 80);
    assert_eq!(c.channels.forwarding_fee_base_msat, 0);
    assert_eq!(c.channels.forwarding_fee_proportional_millionths, 100);
    assert_eq!(
        c.channels.max_dust_htlc_exposure,
        DustExposure::FixedLimitMsat(5_000_000)
    );
    assert_eq!(c.channels.max_inbound_htlc_value_in_flight_percent, 25);
    assert_eq!(c.channels.max_minimum_depth, 6);
    assert_eq!(c.channels.our_max_accepted_htlcs, 100);
    assert_eq!(c.channels.our_to_self_delay, 288);
    let ldk = c.channels.channel_config();
    assert_eq!(ldk.cltv_expiry_delta, 80);
    assert_eq!(ldk.forwarding_fee_base_msat, 0);
    assert_eq!(ldk.forwarding_fee_proportional_millionths, 100);
}

#[test]
fn dust_exposure_multiplier_key_applies() {
    let c = cfg("[channels]\nmax_dust_htlc_exposure_multiplier = 20000\n").unwrap();
    assert_eq!(
        c.channels.max_dust_htlc_exposure,
        DustExposure::FeeRateMultiplier(20000)
    );
}

#[test]
fn dust_exposure_keys_mutually_exclusive() {
    let m = err_msg(cfg(
        "[channels]\nmax_dust_htlc_exposure_multiplier = 20000\nmax_dust_htlc_exposure_fixed_msat = 5000000\n",
    ));
    assert!(m.contains("max_dust_htlc_exposure"));
}

#[test]
fn zero_dust_exposure_rejected() {
    for key in [
        "max_dust_htlc_exposure_fixed_msat",
        "max_dust_htlc_exposure_multiplier",
    ] {
        let m = err_msg(cfg(&format!("[channels]\n{key} = 0\n")));
        assert!(m.contains(key), "expected error naming {key}, got: {m}");
    }
}

#[test]
fn cltv_expiry_delta_below_ldk_minimum_rejected() {
    let m = err_msg(cfg("[channels]\ncltv_expiry_delta = 47\n"));
    assert!(m.contains("cltv_expiry_delta"));
    assert!(cfg("[channels]\ncltv_expiry_delta = 48\n").is_ok());
}

#[test]
fn our_to_self_delay_out_of_bounds_rejected() {
    let m = err_msg(cfg("[channels]\nour_to_self_delay = 143\n"));
    assert!(m.contains("our_to_self_delay"));
    let m = err_msg(cfg("[channels]\nour_to_self_delay = 2017\n"));
    assert!(m.contains("our_to_self_delay"));
    assert!(cfg("[channels]\nour_to_self_delay = 2016\n").is_ok());
}

#[test]
fn max_inbound_htlc_percent_out_of_bounds_rejected() {
    let m = err_msg(cfg(
        "[channels]\nmax_inbound_htlc_value_in_flight_percent = 0\n",
    ));
    assert!(m.contains("max_inbound_htlc_value_in_flight_percent"));
    let m = err_msg(cfg(
        "[channels]\nmax_inbound_htlc_value_in_flight_percent = 101\n",
    ));
    assert!(m.contains("max_inbound_htlc_value_in_flight_percent"));
    assert!(cfg("[channels]\nmax_inbound_htlc_value_in_flight_percent = 100\n").is_ok());
}

#[test]
fn our_max_accepted_htlcs_out_of_bounds_rejected() {
    let m = err_msg(cfg("[channels]\nour_max_accepted_htlcs = 0\n"));
    assert!(m.contains("our_max_accepted_htlcs"));
    let m = err_msg(cfg("[channels]\nour_max_accepted_htlcs = 484\n"));
    assert!(m.contains("our_max_accepted_htlcs"));
    assert!(cfg("[channels]\nour_max_accepted_htlcs = 483\n").is_ok());
}

#[test]
fn zero_max_minimum_depth_rejected() {
    let m = err_msg(cfg("[channels]\nmax_minimum_depth = 0\n"));
    assert!(m.contains("max_minimum_depth"));
}

#[test]
fn accept_forwards_to_priv_channels_defaults_off_and_applies() {
    assert!(!Config::default().channels.accept_forwards_to_priv_channels);
    let c = cfg("[channels]\naccept_forwards_to_priv_channels = true\n").unwrap();
    assert!(c.channels.accept_forwards_to_priv_channels);
}
