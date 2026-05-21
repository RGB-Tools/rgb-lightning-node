use bitcoin::secp256k1::PublicKey;
use clap::{value_parser, Parser};
use rgb_lib::BitcoinNetwork;
use std::path::PathBuf;

use crate::auth::check_auth_args;
use crate::error::AppError;
use crate::utils::{check_port_is_available, hex_str_to_compressed_pubkey};

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

    /// Root public key for biscuit token authentication (hex-encoded)
    #[arg(long)]
    root_public_key: Option<String>,

    /// Disable authentication
    #[arg(long, default_value_t = false)]
    disable_authentication: bool,

    #[arg(long, default_value_t = false)]
    enable_virtual_channels_v0: bool,

    #[arg(long, value_delimiter = ',')]
    virtual_peer_pubkeys: Vec<String>,

    #[arg(long)]
    lsp_base_url: Option<String>,

    #[arg(long)]
    lsp_bearer_token: Option<String>,

    /// VSS server URL for cloud backup (e.g., https://example.com/vss).
    ///
    /// HTTPS is required for non-loopback hosts unless `--vss-allow-http` is
    /// also set; this prevents accidentally shipping channel state plaintext
    /// over the network.
    #[arg(long)]
    vss_url: Option<String>,

    /// Allow `--vss-url` to use the `http://` scheme for non-loopback hosts.
    ///
    /// Without this flag, only `https://` URLs and loopback HTTP URLs
    /// (e.g. `http://localhost:8081/vss`) are accepted. Set this only when
    /// you have an out-of-band reason to trust the link (e.g. a private
    /// network with link-layer encryption).
    #[arg(long, default_value_t = false)]
    vss_allow_http: bool,

    /// On a fresh device with no local LDK state, if VSS restore fails
    /// (server unreachable, wrong signing key, etc.), start with an empty
    /// local state instead of aborting unlock.
    ///
    /// **Use with care.** A node started fresh has no channel monitors and
    /// can lose funds if it had active channels. The default behavior
    /// (abort on restore failure) is the safe choice in almost all cases.
    #[arg(long, default_value_t = false)]
    vss_allow_empty_restore: bool,
}

pub(crate) struct UserArgs {
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) daemon_listening_port: u16,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) network: BitcoinNetwork,
    pub(crate) max_media_upload_size_mb: u16,
    pub(crate) root_public_key: Option<biscuit_auth::PublicKey>,
    pub(crate) enable_virtual_channels_v0: bool,
    pub(crate) virtual_peer_pubkeys: Vec<PublicKey>,
    pub(crate) lsp_base_url: Option<String>,
    pub(crate) lsp_bearer_token: Option<String>,
    pub(crate) vss_url: Option<String>,
    pub(crate) vss_allow_empty_restore: bool,
}

pub(crate) fn parse_startup_args() -> Result<UserArgs, AppError> {
    let args = Args::parse();

    let network = args.network;

    let daemon_listening_port = args.daemon_listening_port;
    check_port_is_available(daemon_listening_port)?;
    let ldk_peer_listening_port = args.ldk_peer_listening_port;
    check_port_is_available(ldk_peer_listening_port)?;

    let root_public_key = check_auth_args(args.disable_authentication, args.root_public_key)?;

    let mut virtual_peer_pubkeys = Vec::new();
    for pubkey in args.virtual_peer_pubkeys {
        let Some(parsed_pubkey) = hex_str_to_compressed_pubkey(&pubkey) else {
            return Err(AppError::InvalidVirtualPeerPubkey(pubkey));
        };
        virtual_peer_pubkeys.push(parsed_pubkey);
    }

    // Reject http:// URLs unless the host is loopback or --vss-allow-http is set.
    if let Some(url) = &args.vss_url {
        crate::utils::validate_vss_url(url, args.vss_allow_http)?;
    }

    Ok(UserArgs {
        storage_dir_path: args.storage_directory_path,
        daemon_listening_port,
        ldk_peer_listening_port,
        network,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
        root_public_key,
        enable_virtual_channels_v0: args.enable_virtual_channels_v0,
        virtual_peer_pubkeys,
        lsp_base_url: args.lsp_base_url,
        lsp_bearer_token: args.lsp_bearer_token,
        vss_url: args.vss_url,
        vss_allow_empty_restore: args.vss_allow_empty_restore,
    })
}
