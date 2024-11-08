use amplify::s;
use clap::{value_parser, Parser};
use lightning::ln::msgs::SocketAddress;
use rgb_lib::BitcoinNetwork;
use std::path::PathBuf;
use std::str::FromStr;

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

    /// Announced node name
    #[arg(long)]
    announced_node_name: Option<String>,

    /// Announced listen addresses
    #[arg(long, value_delimiter = ',')]
    announced_listen_addreses: Option<Vec<String>>,

    /// Max allowed media size for upload (in MB)
    #[arg(long, default_value_t = 5)]
    max_media_upload_size_mb: u16,
}

pub(crate) struct LdkUserInfo {
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) daemon_listening_port: u16,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) ldk_announced_listen_addr: Vec<SocketAddress>,
    pub(crate) ldk_announced_node_name: [u8; 32],
    pub(crate) network: BitcoinNetwork,
    pub(crate) max_media_upload_size_mb: u16,
}

pub(crate) fn parse_startup_args() -> Result<LdkUserInfo, AppError> {
    let args = Args::parse();

    let network = args.network;

    if ![BitcoinNetwork::Testnet, BitcoinNetwork::Regtest].contains(&network) {
        return Err(AppError::UnsupportedBitcoinNetwork);
    }

    let daemon_listening_port = args.daemon_listening_port;
    check_port_is_available(daemon_listening_port)?;
    let ldk_peer_listening_port = args.ldk_peer_listening_port;
    check_port_is_available(ldk_peer_listening_port)?;

    let ldk_announced_node_name = match args.announced_node_name {
        Some(s) => {
            if s.len() > 32 {
                return Err(AppError::InvalidNodeAlias(s!(
                    "cannot be longer than 32 bytes"
                )));
            }
            let mut bytes = [0; 32];
            bytes[..s.len()].copy_from_slice(s.as_bytes());
            bytes
        }
        None => [0; 32],
    };

    let mut ldk_announced_listen_addr = Vec::new();
    if let Some(addreses) = args.announced_listen_addreses {
        for addr in addreses {
            match SocketAddress::from_str(&addr) {
                Ok(sa) => {
                    ldk_announced_listen_addr.push(sa);
                }
                Err(_) => {
                    return Err(AppError::InvalidAnnouncedListenAddresses(s!(
                        "failed to parse announced-listen-addr into a socket address"
                    )))
                }
            }
        }
    }

    Ok(LdkUserInfo {
        storage_dir_path: args.storage_directory_path,
        daemon_listening_port,
        ldk_peer_listening_port,
        ldk_announced_listen_addr,
        ldk_announced_node_name,
        network,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
    })
}
