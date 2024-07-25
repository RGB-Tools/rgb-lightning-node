use amplify::s;
use bitcoin::network::constants::Network;
use clap::{value_parser, Parser};
use dirs::home_dir;
use lightning::ln::msgs::SocketAddress;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::AppError;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bitcoind RPC connection info
    bitcoind_rpc_info: String,

    /// Path for the node storage directory
    storage_directory_path: PathBuf,

    /// Listening port of the daemon
    #[arg(long, default_value_t = 3001)]
    daemon_listening_port: u16,

    /// Listening port for LN peers
    #[arg(long, default_value_t = 9735)]
    ldk_peer_listening_port: u16,

    /// Bitcoin network
    #[arg(long, default_value_t = Network::Testnet, value_parser = value_parser!(Network))]
    network: Network,

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
    pub(crate) bitcoind_rpc_username: String,
    pub(crate) bitcoind_rpc_password: String,
    pub(crate) bitcoind_rpc_port: u16,
    pub(crate) bitcoind_rpc_host: String,
    pub(crate) storage_dir_path: PathBuf,
    pub(crate) daemon_listening_port: u16,
    pub(crate) ldk_peer_listening_port: u16,
    pub(crate) ldk_announced_listen_addr: Vec<SocketAddress>,
    pub(crate) ldk_announced_node_name: [u8; 32],
    pub(crate) network: Network,
    pub(crate) max_media_upload_size_mb: u16,
}

pub(crate) fn parse_startup_args() -> Result<LdkUserInfo, AppError> {
    let args = Args::parse();

    let bitcoind_rpc_info = args.bitcoind_rpc_info;
    let bitcoind_rpc_info_parts: Vec<&str> = bitcoind_rpc_info.rsplitn(2, '@').collect();
    // Parse rpc auth after getting network for default .cookie location
    let bitcoind_rpc_path: Vec<&str> = bitcoind_rpc_info_parts[0].split(':').collect();
    if bitcoind_rpc_path.len() != 2 {
        return Err(AppError::InvalidBitcoinRPCInfo(s!("bad RPC path")));
    }
    let bitcoind_rpc_host = bitcoind_rpc_path[0].to_string();
    let bitcoind_rpc_port = bitcoind_rpc_path[1].parse::<u16>().unwrap();

    let network = args.network;
    if matches!(network, Network::Bitcoin) || matches!(network, Network::Signet) {
        return Err(AppError::UnsupportedBitcoinNetwork);
    }

    let (bitcoind_rpc_username, bitcoind_rpc_password) = if bitcoind_rpc_info_parts.len() == 1 {
        get_rpc_auth_from_env_vars()
            .or(get_rpc_auth_from_env_file(None))
            .or(get_rpc_auth_from_cookie(None, Some(network), None))
            .or({
                print_rpc_auth_help();
                Err(AppError::InvalidBitcoinRPCInfo(s!(
                    "unable to get bitcoind RPC username and password"
                )))
            })?
    } else if bitcoind_rpc_info_parts.len() == 2 {
        parse_rpc_auth(bitcoind_rpc_info_parts[1])?
    } else {
        return Err(AppError::InvalidBitcoinRPCInfo(s!(
            "bad bitcoind RPC URL provided"
        )));
    };

    let daemon_listening_port = args.daemon_listening_port;

    let ldk_peer_listening_port = args.ldk_peer_listening_port;

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
        bitcoind_rpc_username,
        bitcoind_rpc_password,
        bitcoind_rpc_host,
        bitcoind_rpc_port,
        storage_dir_path: args.storage_directory_path,
        daemon_listening_port,
        ldk_peer_listening_port,
        ldk_announced_listen_addr,
        ldk_announced_node_name,
        network,
        max_media_upload_size_mb: args.max_media_upload_size_mb,
    })
}

// Default datadir relative to home directory
#[cfg(target_os = "windows")]
const DEFAULT_BITCOIN_DATADIR: &str = "AppData/Roaming/Bitcoin";
#[cfg(target_os = "linux")]
const DEFAULT_BITCOIN_DATADIR: &str = ".bitcoin";
#[cfg(target_os = "macos")]
const DEFAULT_BITCOIN_DATADIR: &str = "Library/Application Support/Bitcoin";

// Environment variable/.env keys
const BITCOIND_RPC_USER_KEY: &str = "RPC_USER";
const BITCOIND_RPC_PASSWORD_KEY: &str = "RPC_PASSWORD";

fn print_rpc_auth_help() {
    // Get the default data directory
    let data_dir = home_dir()
        .expect("home is defined")
        .join(DEFAULT_BITCOIN_DATADIR);
    println!("To provide the bitcoind RPC username and password, you can either:");
    println!(
        "1. Provide the username and password as the first argument to this program in the format: \
        <bitcoind-rpc-username>:<bitcoind-rpc-password>@<bitcoind-rpc-host>:<bitcoind-rpc-port>"
    );
    println!("2. Provide <bitcoind-rpc-username>:<bitcoind-rpc-password> in a .cookie file in the default \
        bitcoind data directory (automatically created by bitcoind on startup): `{}`", data_dir.to_string_lossy());
    println!(
        "3. Set the {} and {} environment variables",
        BITCOIND_RPC_USER_KEY, BITCOIND_RPC_PASSWORD_KEY
    );
    println!(
        "4. Provide {} and {} fields in a .env file in the current directory",
        BITCOIND_RPC_USER_KEY, BITCOIND_RPC_PASSWORD_KEY
    );
}

fn parse_rpc_auth(rpc_auth: &str) -> Result<(String, String), AppError> {
    let rpc_auth_info: Vec<&str> = rpc_auth.split(':').collect();
    if rpc_auth_info.len() != 2 {
        return Err(AppError::InvalidBitcoinRPCInfo(s!(
            "bad bitcoind RPC username/password combo provided"
        )));
    }
    let rpc_username = rpc_auth_info[0].to_string();
    let rpc_password = rpc_auth_info[1].to_string();
    Ok((rpc_username, rpc_password))
}

fn get_cookie_path(
    data_dir: Option<(&str, bool)>,
    network: Option<Network>,
    cookie_file_name: Option<&str>,
) -> Result<PathBuf, AppError> {
    let data_dir_path = match data_dir {
        Some((dir, true)) => home_dir()
            .ok_or(AppError::InvalidBitcoinRPCInfo(s!(
                "cannot get home directory"
            )))?
            .join(dir),
        Some((dir, false)) => PathBuf::from(dir),
        None => home_dir()
            .ok_or(AppError::InvalidBitcoinRPCInfo(s!(
                "cannot get home directory"
            )))?
            .join(DEFAULT_BITCOIN_DATADIR),
    };

    let data_dir_path_with_net = match network {
        Some(Network::Testnet) => data_dir_path.join("testnet3"),
        Some(Network::Regtest) => data_dir_path.join("regtest"),
        Some(Network::Signet) => data_dir_path.join("signet"),
        _ => data_dir_path,
    };

    let cookie_path = data_dir_path_with_net.join(cookie_file_name.unwrap_or(".cookie"));

    Ok(cookie_path)
}

fn get_rpc_auth_from_cookie(
    data_dir: Option<(&str, bool)>,
    network: Option<Network>,
    cookie_file_name: Option<&str>,
) -> Result<(String, String), AppError> {
    let cookie_path = get_cookie_path(data_dir, network, cookie_file_name)?;
    let cookie_contents = fs::read_to_string(cookie_path).or(Err(
        AppError::InvalidBitcoinRPCInfo(s!("cannot read cookie file contents")),
    ))?;
    parse_rpc_auth(&cookie_contents)
}

fn get_rpc_auth_from_env_vars() -> Result<(String, String), ()> {
    if let (Ok(username), Ok(password)) = (
        env::var(BITCOIND_RPC_USER_KEY),
        env::var(BITCOIND_RPC_PASSWORD_KEY),
    ) {
        Ok((username, password))
    } else {
        Err(())
    }
}

fn get_rpc_auth_from_env_file(env_file_name: Option<&str>) -> Result<(String, String), ()> {
    let env_file_map = parse_env_file(env_file_name)?;
    if let (Some(username), Some(password)) = (
        env_file_map.get(BITCOIND_RPC_USER_KEY),
        env_file_map.get(BITCOIND_RPC_PASSWORD_KEY),
    ) {
        Ok((username.to_string(), password.to_string()))
    } else {
        Err(())
    }
}

fn parse_env_file(env_file_name: Option<&str>) -> Result<HashMap<String, String>, ()> {
    // Default .env file name is .env
    let env_file_name = env_file_name.unwrap_or(".env");

    // Read .env file
    let env_file_path = Path::new(env_file_name);
    let env_file_contents = fs::read_to_string(env_file_path).or(Err(()))?;

    // Collect key-value pairs from .env file into a map
    let mut env_file_map: HashMap<String, String> = HashMap::new();
    for line in env_file_contents.lines() {
        let line_parts: Vec<&str> = line.splitn(2, '=').collect();
        if line_parts.len() != 2 {
            eprintln!("ERROR: bad .env file format");
            return Err(());
        }
        env_file_map.insert(line_parts[0].to_string(), line_parts[1].to_string());
    }

    Ok(env_file_map)
}
