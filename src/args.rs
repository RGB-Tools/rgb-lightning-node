use clap::{value_parser, Parser};
use rgb_lib::BitcoinNetwork;
use std::path::PathBuf;

use crate::auth::check_auth_args;
use crate::error::AppError;
use crate::utils::check_port_is_available;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path for the node storage directory
    storage_directory_path: PathBuf,

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
}

pub(crate) fn parse_startup_args() -> Result<UserArgs, AppError> {
    let args = Args::parse();

    let network = args.network;

    let daemon_listening_port = args.daemon_listening_port;
    check_port_is_available(daemon_listening_port)?;
    let ldk_peer_listening_port = args.ldk_peer_listening_port;
    check_port_is_available(ldk_peer_listening_port)?;

    let root_public_key = check_auth_args(args.disable_authentication, args.root_public_key)?;

    Ok(UserArgs {
        storage_dir_path: args.storage_directory_path,
        daemon_listening_port,
        ldk_peer_listening_port,
        network,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
        max_aggregated_media_size_per_channel_mb: args.max_aggregated_media_size_per_channel_mb,
        max_pending_consignments: args.max_pending_consignments,
        max_media_files_per_channel: args.max_media_files_per_channel,
        root_public_key,
    })
}
