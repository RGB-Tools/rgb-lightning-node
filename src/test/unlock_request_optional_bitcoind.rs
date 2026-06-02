use amplify::s;
use rgb_lib::BitcoinNetwork;

use crate::core_types::UnlockRequest as CoreUnlockRequest;
use crate::error::APIError;
use crate::ldk::{select_chain_backend, ChainBackendSelection};
use crate::routes::UnlockRequest;

#[test]
fn deserialize_without_bitcoind_fields() {
    let json = serde_json::json!({
        "password": "p",
        "indexer_url": "https://blockstream.info/testnet/api",
        "proxy_endpoint": "rpc://127.0.0.1:3000/json-rpc",
        "announce_addresses": [],
    });
    let req: UnlockRequest = serde_json::from_value(json).unwrap();
    assert!(req.bitcoind_rpc_username.is_none());
    assert!(req.bitcoind_rpc_password.is_none());
    assert!(req.bitcoind_rpc_host.is_none());
    assert!(req.bitcoind_rpc_port.is_none());
    assert_eq!(
        req.indexer_url.as_deref(),
        Some("https://blockstream.info/testnet/api")
    );
}

#[test]
fn deserialize_with_bitcoind_fields() {
    let json = serde_json::json!({
        "password": "p",
        "bitcoind_rpc_username": "user",
        "bitcoind_rpc_password": "password",
        "bitcoind_rpc_host": "localhost",
        "bitcoind_rpc_port": 18443,
        "announce_addresses": [],
    });
    let req: UnlockRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.bitcoind_rpc_username.as_deref(), Some("user"));
    assert_eq!(req.bitcoind_rpc_port, Some(18443));
}

fn req(bitcoind: bool, indexer: Option<&str>) -> CoreUnlockRequest {
    CoreUnlockRequest {
        bitcoind_rpc_username: bitcoind.then(|| s!("u")),
        bitcoind_rpc_password: bitcoind.then(|| s!("p")),
        bitcoind_rpc_host: bitcoind.then(|| s!("h")),
        bitcoind_rpc_port: bitcoind.then_some(18443),
        indexer_url: indexer.map(str::to_string),
        proxy_endpoint: None,
        announce_addresses: vec![],
        announce_alias: None,
        gossip_source: None,
    }
}

#[test]
fn select_bitcoind_only_returns_bitcoind() {
    let r = req(true, None);
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Regtest),
        Ok(ChainBackendSelection::Bitcoind { .. })
    ));
}

#[test]
#[ignore = "rgb-lib's check_indexer_url probes the URL; needs a reachable testnet esplora endpoint"]
fn select_esplora_only_returns_esplora() {
    let r = req(false, Some("https://blockstream.info/testnet/api"));
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Testnet),
        Ok(ChainBackendSelection::Esplora { .. })
    ));
}

#[test]
fn select_neither_errors() {
    let r = req(false, None);
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Regtest),
        Err(APIError::MissingChainBackend)
    ));
}

#[test]
#[ignore = "rgb-lib's check_indexer_url probes the URL; needs a reachable testnet esplora endpoint"]
fn select_both_esplora_errors() {
    let r = req(true, Some("https://blockstream.info/testnet/api"));
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Testnet),
        Err(APIError::AmbiguousChainBackend)
    ));
}

#[test]
fn select_both_electrum_allowed() {
    let r = req(true, Some("ssl://electrum.iriswallet.com:50013"));
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Testnet),
        Ok(ChainBackendSelection::Bitcoind { .. })
    ));
}

#[test]
fn select_electrum_only_returns_electrum() {
    let r = req(false, Some("ssl://electrum.iriswallet.com:50013"));
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Testnet),
        Ok(ChainBackendSelection::Electrum { .. })
    ));
}

#[test]
fn select_partial_bitcoind_errors() {
    let mut r = req(true, None);
    r.bitcoind_rpc_host = None;
    assert!(matches!(
        select_chain_backend(&r, BitcoinNetwork::Regtest),
        Err(APIError::InvalidIndexer(_))
    ));
}
