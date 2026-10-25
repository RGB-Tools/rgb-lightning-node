use clap::parser::ValueSource;
use clap::{value_parser, ArgMatches, CommandFactory, FromArgMatches, Parser};
use rgb_lib::BitcoinNetwork;
use std::path::PathBuf;

use crate::auth::check_auth_args;
use crate::config::{load_config_file, Config, TomlConfig, DEFAULT_CONFIG_FILENAME};
use crate::error::AppError;
use crate::utils::check_port_is_available;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path for the node storage directory
    storage_directory_path: PathBuf,

    /// Path to the TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Listening port of the daemon
    #[arg(long, default_value_t = 3001)]
    daemon_listening_port: u16,

    /// Listening port for LN peers
    #[arg(long, default_value_t = 9735)]
    ldk_peer_listening_port: u16,

    /// Bitcoin network
    #[arg(long, default_value_t = BitcoinNetwork::Testnet, value_parser = value_parser!(BitcoinNetwork))]
    network: BitcoinNetwork,

    /// Max allowed media size for upload (in MB)
    #[arg(long, default_value_t = 5)]
    max_media_upload_size_mb: u16,

    /// Max aggregate size of RGB media accepted over p2p per channel-open (in MB)
    #[arg(long, default_value_t = crate::rgb_file_transfer::MAX_MEDIA_MB_PER_CHANNEL)]
    max_aggregated_media_size_per_channel_mb: u16,

    /// Max number of pending channel-open consignments buffered over p2p at once
    #[arg(long, default_value_t = crate::rgb_file_transfer::MAX_PENDING_CONSIGNMENTS)]
    max_pending_consignments: usize,

    /// Max number of RGB media files accepted over p2p per channel-open
    #[arg(long, default_value_t = crate::rgb_file_transfer::MAX_MEDIA_FILES_PER_CHANNEL)]
    max_media_files_per_channel: usize,

    /// Root public key for biscuit token authentication (hex-encoded)
    #[arg(long)]
    root_public_key: Option<String>,

    /// Disable authentication
    #[arg(long, default_value_t = false)]
    disable_authentication: bool,
}

pub(crate) struct UserArgs {
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) daemon_listening_port: u16,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) network: BitcoinNetwork,
    pub(crate) max_media_upload_size_mb: u16,
    pub(crate) max_aggregated_media_size_per_channel_mb: u16,
    pub(crate) max_pending_consignments: usize,
    pub(crate) max_media_files_per_channel: usize,
    pub(crate) root_public_key: Option<biscuit_auth::PublicKey>,
    pub(crate) config: Config,
}

pub(crate) fn parse_startup_args() -> Result<UserArgs, AppError> {
    let matches = Args::command().get_matches();
    let args =
        Args::from_arg_matches(&matches).map_err(|e| AppError::InvalidConfig(e.to_string()))?;
    let toml = load_startup_toml(&args)?;
    let user_args = resolve_user_args(args, &matches, toml)?;

    check_port_is_available(user_args.daemon_listening_port)?;
    check_port_is_available(user_args.ldk_peer_listening_port)?;

    Ok(user_args)
}

fn load_startup_toml(args: &Args) -> Result<TomlConfig, AppError> {
    if let Some(path) = &args.config {
        return load_config_file(path);
    }
    let default_path = args.storage_directory_path.join(DEFAULT_CONFIG_FILENAME);
    if default_path.exists() {
        load_config_file(&default_path)
    } else {
        Ok(TomlConfig::default())
    }
}

/// Merge the three configuration layers: built-in defaults, then the config
/// file, then explicit CLI options.
fn resolve_user_args(
    args: Args,
    matches: &ArgMatches,
    toml: TomlConfig,
) -> Result<UserArgs, AppError> {
    let config = Config::from_toml(&toml)?;
    let from_cli = |name: &str| matches.value_source(name) == Some(ValueSource::CommandLine);

    let node = toml.node.unwrap_or_default();
    let auth = toml.auth.unwrap_or_default();
    let media = toml.media.unwrap_or_default();

    let network = match node.network {
        Some(ref s) if !from_cli("network") => s
            .parse::<BitcoinNetwork>()
            .map_err(|_| AppError::InvalidConfig(format!("invalid node.network: {s}")))?,
        _ => args.network,
    };

    let daemon_listening_port = if from_cli("daemon_listening_port") {
        args.daemon_listening_port
    } else {
        node.daemon_listening_port
            .unwrap_or(args.daemon_listening_port)
    };
    let ldk_peer_listening_port = if from_cli("ldk_peer_listening_port") {
        args.ldk_peer_listening_port
    } else {
        node.ldk_peer_listening_port
            .unwrap_or(args.ldk_peer_listening_port)
    };
    if daemon_listening_port == ldk_peer_listening_port {
        return Err(AppError::InvalidConfig(format!(
            "daemon_listening_port and ldk_peer_listening_port cannot both be {daemon_listening_port}"
        )));
    }

    let max_media_upload_size_mb = if from_cli("max_media_upload_size_mb") {
        args.max_media_upload_size_mb
    } else {
        media
            .max_media_upload_size_mb
            .unwrap_or(args.max_media_upload_size_mb)
    };
    let max_aggregated_media_size_per_channel_mb =
        if from_cli("max_aggregated_media_size_per_channel_mb") {
            args.max_aggregated_media_size_per_channel_mb
        } else {
            media
                .max_aggregated_media_size_per_channel_mb
                .unwrap_or(args.max_aggregated_media_size_per_channel_mb)
        };
    let max_pending_consignments = if from_cli("max_pending_consignments") {
        args.max_pending_consignments
    } else {
        media
            .max_pending_consignments
            .unwrap_or(args.max_pending_consignments)
    };
    let max_media_files_per_channel = if from_cli("max_media_files_per_channel") {
        args.max_media_files_per_channel
    } else {
        media
            .max_media_files_per_channel
            .unwrap_or(args.max_media_files_per_channel)
    };

    let disable_authentication =
        args.disable_authentication || auth.disable_authentication.unwrap_or(false);
    let root_public_key_hex = args.root_public_key.or(auth.root_public_key);
    let root_public_key = check_auth_args(disable_authentication, root_public_key_hex)?;

    Ok(UserArgs {
        storage_dir_path: args.storage_directory_path,
        daemon_listening_port,
        ldk_peer_listening_port,
        network,
        max_media_upload_size_mb,
        max_aggregated_media_size_per_channel_mb,
        max_pending_consignments,
        max_media_files_per_channel,
        root_public_key,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TomlConfig;

    const PUBKEY: &str = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";

    fn resolve(argv: &[&str], toml: &str) -> Result<UserArgs, AppError> {
        let matches = <Args as clap::CommandFactory>::command()
            .try_get_matches_from(argv)
            .unwrap();
        let args = <Args as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
        resolve_user_args(args, &matches, TomlConfig::parse(toml).unwrap())
    }

    fn base(extra: &[&str]) -> Vec<&'static str> {
        let mut argv = vec!["rln", "/tmp/storage", "--disable-authentication"];
        argv.extend(
            extra
                .iter()
                .map(|s| -> &'static str { Box::leak(s.to_string().into_boxed_str()) }),
        );
        argv
    }

    #[test]
    fn defaults_without_file_or_flags() {
        let ua = resolve(&base(&[]), "").unwrap();
        assert_eq!(ua.daemon_listening_port, 3001);
        assert_eq!(ua.ldk_peer_listening_port, 9735);
        assert_eq!(ua.network, BitcoinNetwork::Testnet);
        assert_eq!(ua.max_media_upload_size_mb, 5);
        assert_eq!(ua.max_aggregated_media_size_per_channel_mb, 24);
        assert_eq!(ua.max_pending_consignments, 10);
        assert_eq!(ua.max_media_files_per_channel, 42);
        assert_eq!(ua.config, crate::config::Config::default());
    }

    #[test]
    fn file_overrides_defaults() {
        let ua = resolve(
            &base(&[]),
            "[node]\nnetwork = \"regtest\"\ndaemon_listening_port = 8888\nldk_peer_listening_port = 9999\n\n[media]\nmax_media_upload_size_mb = 10\nmax_pending_consignments = 20\n",
        )
        .unwrap();
        assert_eq!(ua.network, BitcoinNetwork::Regtest);
        assert_eq!(ua.daemon_listening_port, 8888);
        assert_eq!(ua.ldk_peer_listening_port, 9999);
        assert_eq!(ua.max_media_upload_size_mb, 10);
        assert_eq!(ua.max_pending_consignments, 20);
    }

    #[test]
    fn cli_overrides_file() {
        let ua = resolve(
            &base(&[
                "--daemon-listening-port",
                "9999",
                "--network",
                "signet",
                "--max-media-upload-size-mb",
                "7",
            ]),
            "[node]\nnetwork = \"regtest\"\ndaemon_listening_port = 8888\n\n[media]\nmax_media_upload_size_mb = 10\n",
        )
        .unwrap();
        assert_eq!(ua.daemon_listening_port, 9999);
        assert_eq!(ua.network, BitcoinNetwork::Signet);
        assert_eq!(ua.max_media_upload_size_mb, 7);
    }

    #[test]
    fn invalid_network_in_file_rejected() {
        let res = resolve(&base(&[]), "[node]\nnetwork = \"bogus\"\n");
        assert!(matches!(res, Err(AppError::InvalidConfig(ref m)) if m.contains("bogus")));
    }

    #[test]
    fn same_ports_rejected() {
        let res = resolve(
            &base(&[]),
            "[node]\ndaemon_listening_port = 4000\nldk_peer_listening_port = 4000\n",
        );
        assert!(matches!(res, Err(AppError::InvalidConfig(_))));
    }

    #[test]
    fn auth_from_file() {
        let argv = vec!["rln", "/tmp/storage"];
        let ua = resolve(&argv, "[auth]\ndisable_authentication = true\n").unwrap();
        assert!(ua.root_public_key.is_none());
    }

    #[test]
    fn auth_conflict_rejected() {
        let res = resolve(
            &base(&[]),
            &format!("[auth]\nroot_public_key = \"{PUBKEY}\"\n"),
        );
        assert!(matches!(res, Err(AppError::InvalidAuthenticationArgs)));
    }

    #[test]
    fn missing_auth_rejected() {
        let argv = vec!["rln", "/tmp/storage"];
        let res = resolve(&argv, "");
        assert!(matches!(res, Err(AppError::InvalidAuthenticationArgs)));
    }

    #[test]
    fn policy_sections_attached_to_user_args() {
        let ua = resolve(&base(&[]), "[rgb]\nfee_rate_sat_vb = 12\n").unwrap();
        assert_eq!(ua.config.rgb.fee_rate_sat_vb, 12);
    }

    #[test]
    fn invalid_policy_in_file_rejected() {
        let res = resolve(&base(&[]), "[rgb]\nfee_rate_sat_vb = 0\n");
        assert!(matches!(res, Err(AppError::InvalidConfig(_))));
    }
}
