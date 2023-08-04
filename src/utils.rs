use amplify::s;
use bdk::{database::SqliteDatabase, Wallet};
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lightning::{chain::keysinterface::KeysManager, ln::PaymentHash};
use lightning::{
    onion_message::CustomOnionMessageContents,
    util::ser::{Writeable, Writer},
};
use reqwest::Client as RestClient;
use std::{
    collections::HashMap,
    fmt::Write,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crate::{
    disk::FilesystemLogger,
    error::APIError,
    ldk::{ChannelManager, NetworkGraph, OnionMessenger, PaymentInfo, PeerManager},
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) channel_manager: Arc<ChannelManager>,
    pub(crate) electrum_url: String,
    pub(crate) inbound_payments: Arc<Mutex<HashMap<PaymentHash, PaymentInfo>>>,
    pub(crate) keys_manager: Arc<KeysManager>,
    pub(crate) ldk_data_dir: String,
    pub(crate) logger: Arc<FilesystemLogger>,
    pub(crate) network: Network,
    pub(crate) network_graph: Arc<NetworkGraph>,
    pub(crate) onion_messenger: Arc<OnionMessenger>,
    pub(crate) outbound_payments: Arc<Mutex<HashMap<PaymentHash, PaymentInfo>>>,
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) proxy_client: Arc<RestClient>,
    pub(crate) proxy_endpoint: String,
    pub(crate) proxy_url: String,
    pub(crate) wallet: Arc<Mutex<Wallet<SqliteDatabase>>>,
}

impl AppState {
    pub(crate) fn get_inbound_payments(&self) -> MutexGuard<HashMap<PaymentHash, PaymentInfo>> {
        self.inbound_payments.lock().unwrap()
    }

    pub(crate) fn get_outbound_payments(&self) -> MutexGuard<HashMap<PaymentHash, PaymentInfo>> {
        self.outbound_payments.lock().unwrap()
    }

    pub(crate) fn get_wallet(&self) -> MutexGuard<Wallet<SqliteDatabase>> {
        self.wallet.lock().unwrap()
    }
}

pub(crate) struct UserOnionMessageContents {
    pub(crate) tlv_type: u64,
    pub(crate) data: Vec<u8>,
}

impl CustomOnionMessageContents for UserOnionMessageContents {
    fn tlv_type(&self) -> u64 {
        self.tlv_type
    }
}

impl Writeable for UserOnionMessageContents {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(&self.data)
    }
}

pub(crate) async fn connect_peer_if_necessary(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), APIError> {
    for (node_pubkey, _) in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(());
        }
    }
    do_connect_peer(pubkey, peer_addr, peer_manager).await?;
    Ok(())
}

pub(crate) async fn do_connect_peer(
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), APIError> {
    match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, peer_addr).await
    {
        Some(connection_closed_future) => {
            let mut connection_closed_future = Box::pin(connection_closed_future);
            loop {
                tokio::select! {
                    _ = &mut connection_closed_future => return Err(APIError::FailedPeerConnection),
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                };
                if peer_manager
                    .get_peer_node_ids()
                    .iter()
                    .any(|(id, _)| *id == pubkey)
                {
                    return Ok(());
                }
            }
        }
        None => Err(APIError::FailedPeerConnection),
    }
}

#[inline]
pub(crate) fn hex_str(value: &[u8]) -> String {
    let mut res = String::with_capacity(2 * value.len());
    for v in value {
        write!(&mut res, "{:02x}", v).expect("Unable to write");
    }
    res
}

pub(crate) fn hex_str_to_compressed_pubkey(hex: &str) -> Option<PublicKey> {
    if hex.len() != 33 * 2 {
        return None;
    }
    let data = match hex_str_to_vec(&hex[0..33 * 2]) {
        Some(bytes) => bytes,
        None => return None,
    };
    match PublicKey::from_slice(&data) {
        Ok(pk) => Some(pk),
        Err(_) => None,
    }
}

pub(crate) fn hex_str_to_vec(hex: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(hex.len() / 2);

    let mut b = 0;
    for (idx, c) in hex.as_bytes().iter().enumerate() {
        b <<= 4;
        match *c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return None,
        }
        if (idx & 1) == 1 {
            out.push(b);
            b = 0;
        }
    }

    Some(out)
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), APIError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next();
    let peer_addr_str = pubkey_and_addr.next();
    if peer_addr_str.is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`"
        )));
    }

    let peer_addr = peer_addr_str
        .unwrap()
        .to_socket_addrs()
        .map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "couldn't parse pubkey@host:port into a socket address"
        )));
    }

    let pubkey = hex_str_to_compressed_pubkey(pubkey.unwrap());
    if pubkey.is_none() {
        return Err(APIError::InvalidPeerInfo(s!(
            "unable to parse given pubkey for node"
        )));
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}
