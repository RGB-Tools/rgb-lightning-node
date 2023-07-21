use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use bdk::bitcoin::Network;
use bdk::blockchain::Blockchain;
use bdk::blockchain::{ConfigurableBlockchain, ElectrumBlockchain, ElectrumBlockchainConfig};
use bdk::database::any::SqliteDbConfiguration;
use bdk::database::{ConfigurableDatabase, SqliteDatabase};
use bdk::template::P2Wpkh;
use bdk::{SyncOptions, Wallet};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{PrivateKey, Transaction};

const DERIVATION_PATH_ACCOUNT: u32 = 0;
const BDK_DB_NAME: &str = "bdk_db";

pub(crate) fn calculate_descriptor_from_xprv(
    xprv: ExtendedPrivKey,
    network: Network,
    change: bool,
) -> String {
    let change_num = u8::from(change);
    let coin_type = i32::from(network != Network::Bitcoin);
    let hardened = "'";
    let child_number = "/*";
    let master = "";
    let derivation_path =
		format!("{master}/84{hardened}/{coin_type}{hardened}/{DERIVATION_PATH_ACCOUNT}{hardened}/{change_num}{child_number}");
    format!("wpkh({xprv}{derivation_path})")
}

pub(crate) fn get_bdk_wallet(
    ldk_data_dir: String,
    xprv: ExtendedPrivKey,
    network: Network,
) -> Wallet<SqliteDatabase> {
    let descriptor = calculate_descriptor_from_xprv(xprv, network, false);
    let change_descriptor = calculate_descriptor_from_xprv(xprv, network, true);

    let bdk_db = format!("{ldk_data_dir}/{BDK_DB_NAME}");
    let bdk_config = SqliteDbConfiguration { path: bdk_db };
    let bdk_database = SqliteDatabase::from_config(&bdk_config).expect("valid bdk config");

    Wallet::new(&descriptor, Some(&change_descriptor), network, bdk_database)
        .expect("valid bdk wallet")
}

pub(crate) fn get_bdk_wallet_seckey(
    ldk_data_dir: String,
    network: Network,
    seckey: SecretKey,
) -> Wallet<SqliteDatabase> {
    std::fs::create_dir_all(&ldk_data_dir).expect("successful dir creation");
    let bdk_db = format!("{ldk_data_dir}/{BDK_DB_NAME}");
    let bdk_config = SqliteDbConfiguration { path: bdk_db };
    let bdk_database = SqliteDatabase::from_config(&bdk_config).expect("valid bdk config");

    let priv_key = PrivateKey::new(seckey, network);
    Wallet::new(P2Wpkh(priv_key), None, network, bdk_database).expect("valid bdk wallet")
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

pub(crate) fn sync_wallet(wallet: &Wallet<SqliteDatabase>, electrum_url: String) {
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
