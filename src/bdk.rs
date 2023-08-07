use bdk::bitcoin::Network;
use bdk::blockchain::Blockchain;
use bdk::blockchain::{ConfigurableBlockchain, ElectrumBlockchain, ElectrumBlockchainConfig};
use bdk::database::MemoryDatabase;
use bdk::template::P2Wpkh;
use bdk::{SyncOptions, Wallet};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{PrivateKey, Transaction};

pub(crate) fn get_bdk_wallet_seckey(network: Network, seckey: SecretKey) -> Wallet<MemoryDatabase> {
    let priv_key = PrivateKey::new(seckey, network);
    Wallet::new(P2Wpkh(priv_key), None, network, MemoryDatabase::default())
        .expect("valid bdk wallet")
}

pub(crate) fn broadcast_tx(tx: &Transaction, electrum_url: String) {
    let config = ElectrumBlockchainConfig {
        url: electrum_url,
        socks5: None,
        retry: 3,
        timeout: Some(5),
        stop_gap: 2000,
        validate_domain: false,
    };
    let blockchain = ElectrumBlockchain::from_config(&config).expect("valid blockchain config");
    blockchain.broadcast(tx).expect("able to broadcast");
}

pub(crate) fn sync_wallet(wallet: &Wallet<MemoryDatabase>, electrum_url: String) {
    let config = ElectrumBlockchainConfig {
        url: electrum_url,
        socks5: None,
        retry: 3,
        timeout: Some(5),
        stop_gap: 20,
        validate_domain: false,
    };
    let blockchain = ElectrumBlockchain::from_config(&config).expect("valid blockchain config");
    wallet
        .sync(&blockchain, SyncOptions { progress: None })
        .expect("successful sync")
}
