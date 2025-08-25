use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Network, OutPoint, Transaction, TxOut, WPubkeyHash};
use hex::DisplayHex;
use lightning::events::bump_transaction::{Utxo, WalletSource};
use lightning::ln::types::ChannelId;
use lightning::rgb_utils::{
    get_rgb_channel_info_path, is_channel_rgb, parse_rgb_channel_info, RgbInfo,
};
use lightning::sign::ChangeDestinationSource;
use rgb_lib::{
    bdk_wallet::SignOptions,
    bitcoin::psbt::Psbt as BitcoinPsbt,
    wallet::{
        rust_only::{check_proxy_url, ColoringInfo},
        AssetCFA, AssetNIA, AssetUDA, Assets, Balance, BtcBalance, Metadata, Online, ReceiveData,
        Recipient, RefreshResult, SendResult, Transaction as RgbLibTransaction, Transfer,
        TransportEndpoint, Unspent, WalletData,
    },
    AssetSchema, Assignment, BitcoinNetwork, Contract, ContractId, Error as RgbLibError,
    RgbTransfer, RgbTransport, RgbTxid, UpdateRes, Wallet as RgbLibWallet, WitnessOrd,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{error::APIError, utils::UnlockedAppState};

impl UnlockedAppState {
    pub(crate) fn rgb_blind_receive(
        &self,
        asset_id: Option<String>,
        duration_seconds: Option<u32>,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, RgbLibError> {
        self.rgb_wallet_wrapper.blind_receive(
            asset_id,
            duration_seconds,
            transport_endpoints,
            min_confirmations,
        )
    }

    pub(crate) fn rgb_create_utxos(
        &self,
        up_to: bool,
        num: u8,
        size: u32,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<u8, RgbLibError> {
        self.rgb_wallet_wrapper
            .create_utxos(up_to, num, size, fee_rate, skip_sync)
    }

    pub(crate) fn rgb_fail_transfers(
        &self,
        batch_transfer_idx: Option<i32>,
        no_asset_only: bool,
        skip_sync: bool,
    ) -> Result<bool, RgbLibError> {
        self.rgb_wallet_wrapper
            .fail_transfers(batch_transfer_idx, no_asset_only, skip_sync)
    }

    pub(crate) fn rgb_get_address(&self) -> Result<String, RgbLibError> {
        self.rgb_wallet_wrapper.get_address()
    }

    pub(crate) fn rgb_get_asset_balance(
        &self,
        contract_id: ContractId,
    ) -> Result<Balance, RgbLibError> {
        self.rgb_wallet_wrapper.get_asset_balance(contract_id)
    }

    pub(crate) fn rgb_get_asset_metadata(
        &self,
        contract_id: ContractId,
    ) -> Result<Metadata, RgbLibError> {
        self.rgb_wallet_wrapper.get_asset_metadata(contract_id)
    }

    pub(crate) fn rgb_get_asset_transfer_dir<P: AsRef<Path>>(
        &self,
        transfer_dir: P,
        asset_id: &str,
    ) -> PathBuf {
        self.rgb_wallet_wrapper
            .get_asset_transfer_dir(transfer_dir, asset_id)
    }

    pub(crate) fn rgb_get_btc_balance(&self, skip_sync: bool) -> Result<BtcBalance, RgbLibError> {
        self.rgb_wallet_wrapper.get_btc_balance(skip_sync)
    }

    pub(crate) fn rgb_get_fee_estimation(&self, blocks: u16) -> Result<f64, RgbLibError> {
        self.rgb_wallet_wrapper.get_fee_estimation(blocks)
    }

    pub(crate) fn rgb_get_media_dir(&self) -> PathBuf {
        self.rgb_wallet_wrapper.get_media_dir()
    }

    pub(crate) fn rgb_get_send_consignment_path<P: AsRef<Path>>(
        &self,
        asset_transfer_dir: P,
    ) -> PathBuf {
        self.rgb_wallet_wrapper
            .get_send_consignment_path(asset_transfer_dir)
    }

    pub(crate) fn rgb_get_transfer_dir(&self, transfer_id: &str) -> PathBuf {
        self.rgb_wallet_wrapper.get_transfer_dir(transfer_id)
    }

    pub(crate) fn rgb_get_wallet_data(&self) -> WalletData {
        self.rgb_wallet_wrapper.get_wallet_data()
    }

    pub(crate) fn rgb_issue_asset_cfa(
        &self,
        name: String,
        details: Option<String>,
        precision: u8,
        amounts: Vec<u64>,
        file_path: Option<String>,
    ) -> Result<AssetCFA, RgbLibError> {
        self.rgb_wallet_wrapper
            .issue_asset_cfa(name, details, precision, amounts, file_path)
    }

    pub(crate) fn rgb_issue_asset_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<AssetNIA, RgbLibError> {
        self.rgb_wallet_wrapper
            .issue_asset_nia(ticker, name, precision, amounts)
    }

    pub(crate) fn rgb_issue_asset_uda(
        &self,
        ticker: String,
        name: String,
        details: Option<String>,
        precision: u8,
        media_file_path: Option<String>,
        attachments_file_paths: Vec<String>,
    ) -> Result<AssetUDA, RgbLibError> {
        self.rgb_wallet_wrapper.issue_asset_uda(
            ticker,
            name,
            details,
            precision,
            media_file_path,
            attachments_file_paths,
        )
    }

    pub(crate) fn rgb_list_assets(
        &self,
        filter_asset_schemas: Vec<AssetSchema>,
    ) -> Result<Assets, RgbLibError> {
        self.rgb_wallet_wrapper.list_assets(filter_asset_schemas)
    }

    pub(crate) fn rgb_list_transactions(
        &self,
        skip_sync: bool,
    ) -> Result<Vec<RgbLibTransaction>, RgbLibError> {
        self.rgb_wallet_wrapper.list_transactions(skip_sync)
    }

    pub(crate) fn rgb_list_transfers(
        &self,
        asset_id: String,
    ) -> Result<Vec<Transfer>, RgbLibError> {
        self.rgb_wallet_wrapper.list_transfers(asset_id)
    }

    pub(crate) fn rgb_list_unspents(&self, skip_sync: bool) -> Result<Vec<Unspent>, RgbLibError> {
        self.rgb_wallet_wrapper.list_unspents(skip_sync)
    }

    pub(crate) fn rgb_post_consignment<P: AsRef<Path>>(
        &self,
        proxy_url: &str,
        recipient_id: String,
        consignment_path: P,
        txid: String,
        vout: Option<u32>,
    ) -> Result<(), RgbLibError> {
        self.rgb_wallet_wrapper.post_consignment(
            proxy_url,
            recipient_id,
            consignment_path,
            txid,
            vout,
        )
    }

    pub(crate) fn rgb_refresh(&self, skip_sync: bool) -> Result<RefreshResult, RgbLibError> {
        self.rgb_wallet_wrapper.refresh(skip_sync)
    }

    pub(crate) fn rgb_save_new_asset(
        &self,
        contract_id: ContractId,
        contract: Option<Contract>,
    ) -> Result<(), RgbLibError> {
        self.rgb_wallet_wrapper
            .save_new_asset(contract_id, contract)
    }

    pub(crate) fn rgb_send(
        &self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<SendResult, RgbLibError> {
        self.rgb_wallet_wrapper.send(
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            skip_sync,
        )
    }

    pub(crate) fn rgb_send_begin(
        &self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
    ) -> Result<String, RgbLibError> {
        self.rgb_wallet_wrapper
            .send_begin(recipient_map, donation, fee_rate, min_confirmations)
    }

    pub(crate) fn rgb_send_btc(
        &self,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<String, RgbLibError> {
        self.rgb_wallet_wrapper
            .send_btc(address, amount, fee_rate, skip_sync)
    }

    pub(crate) fn rgb_send_btc_begin(
        &self,
        address: String,
        amount: u64,
        fee_rate: u64,
    ) -> Result<String, RgbLibError> {
        self.rgb_wallet_wrapper
            .send_btc_begin(address, amount, fee_rate)
    }

    pub(crate) fn rgb_send_btc_end(&self, signed_psbt: String) -> Result<String, RgbLibError> {
        self.rgb_wallet_wrapper.send_btc_end(signed_psbt)
    }

    pub(crate) fn rgb_send_end(&self, signed_psbt: String) -> Result<SendResult, RgbLibError> {
        self.rgb_wallet_wrapper.send_end(signed_psbt)
    }

    pub(crate) fn rgb_sign_psbt(&self, unsigned_psbt: String) -> Result<String, RgbLibError> {
        self.rgb_wallet_wrapper.sign_psbt(unsigned_psbt)
    }

    pub(crate) fn rgb_sync(&self) -> Result<(), RgbLibError> {
        self.rgb_wallet_wrapper.sync()
    }

    pub(crate) fn rgb_upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), RgbLibError> {
        self.rgb_wallet_wrapper
            .upsert_witness(witness_id, witness_ord)
    }

    pub(crate) fn rgb_witness_receive(
        &self,
        asset_id: Option<String>,
        duration_seconds: Option<u32>,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, RgbLibError> {
        self.rgb_wallet_wrapper.witness_receive(
            asset_id,
            duration_seconds,
            transport_endpoints,
            min_confirmations,
        )
    }
}

pub(crate) struct RgbLibWalletWrapper {
    pub(crate) wallet: Arc<Mutex<RgbLibWallet>>,
    pub(crate) online: Online,
}

impl RgbLibWalletWrapper {
    pub(crate) fn new(wallet: Arc<Mutex<RgbLibWallet>>, online: Online) -> Self {
        RgbLibWalletWrapper { wallet, online }
    }

    pub(crate) fn get_rgb_wallet(&self) -> MutexGuard<'_, RgbLibWallet> {
        self.wallet.lock().unwrap()
    }

    pub(crate) fn bitcoin_network(&self) -> BitcoinNetwork {
        self.get_rgb_wallet().get_wallet_data().bitcoin_network
    }

    pub(crate) fn blind_receive(
        &self,
        asset_id: Option<String>,
        duration_seconds: Option<u32>,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, RgbLibError> {
        self.get_rgb_wallet().blind_receive(
            asset_id,
            Assignment::Any,
            duration_seconds,
            transport_endpoints,
            min_confirmations,
        )
    }

    pub(crate) fn color_psbt_and_consume(
        &self,
        psbt_to_color: &mut BitcoinPsbt,
        coloring_info: ColoringInfo,
    ) -> Result<Vec<RgbTransfer>, RgbLibError> {
        self.get_rgb_wallet()
            .color_psbt_and_consume(psbt_to_color, coloring_info)
    }

    pub(crate) fn create_utxos(
        &self,
        up_to: bool,
        num: u8,
        size: u32,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<u8, RgbLibError> {
        self.get_rgb_wallet().create_utxos(
            self.online.clone(),
            up_to,
            Some(num),
            Some(size),
            fee_rate,
            skip_sync,
        )
    }

    pub(crate) fn fail_transfers(
        &self,
        batch_transfer_idx: Option<i32>,
        no_asset_only: bool,
        skip_sync: bool,
    ) -> Result<bool, RgbLibError> {
        self.get_rgb_wallet().fail_transfers(
            self.online.clone(),
            batch_transfer_idx,
            no_asset_only,
            skip_sync,
        )
    }

    pub(crate) fn get_address(&self) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().get_address()
    }

    pub(crate) fn get_asset_balance(
        &self,
        contract_id: ContractId,
    ) -> Result<Balance, RgbLibError> {
        self.get_rgb_wallet()
            .get_asset_balance(contract_id.to_string())
    }

    pub(crate) fn get_asset_metadata(
        &self,
        contract_id: ContractId,
    ) -> Result<Metadata, RgbLibError> {
        self.get_rgb_wallet()
            .get_asset_metadata(contract_id.to_string())
    }

    pub(crate) fn get_asset_transfer_dir<P: AsRef<Path>>(
        &self,
        transfer_dir: P,
        asset_id: &str,
    ) -> PathBuf {
        self.get_rgb_wallet()
            .get_asset_transfer_dir(transfer_dir, asset_id)
    }

    pub(crate) fn get_btc_balance(&self, skip_sync: bool) -> Result<BtcBalance, RgbLibError> {
        let online = if skip_sync {
            None
        } else {
            Some(self.online.clone())
        };
        self.get_rgb_wallet().get_btc_balance(online, skip_sync)
    }

    pub(crate) fn get_fee_estimation(&self, blocks: u16) -> Result<f64, RgbLibError> {
        self.get_rgb_wallet()
            .get_fee_estimation(self.online.clone(), blocks)
    }

    pub(crate) fn get_media_dir(&self) -> PathBuf {
        self.get_rgb_wallet().get_media_dir()
    }

    pub(crate) fn get_send_consignment_path<P: AsRef<Path>>(
        &self,
        asset_transfer_dir: P,
    ) -> PathBuf {
        self.get_rgb_wallet()
            .get_send_consignment_path(asset_transfer_dir)
    }

    pub(crate) fn get_transfer_dir(&self, transfer_id: &str) -> PathBuf {
        self.get_rgb_wallet().get_transfer_dir(transfer_id)
    }

    pub(crate) fn get_tx_height(&self, txid: String) -> Result<Option<u32>, RgbLibError> {
        self.get_rgb_wallet().get_tx_height(txid)
    }

    pub(crate) fn get_wallet_data(&self) -> WalletData {
        self.get_rgb_wallet().get_wallet_data()
    }

    pub(crate) fn issue_asset_cfa(
        &self,
        name: String,
        details: Option<String>,
        precision: u8,
        amounts: Vec<u64>,
        file_path: Option<String>,
    ) -> Result<AssetCFA, RgbLibError> {
        self.get_rgb_wallet()
            .issue_asset_cfa(name, details, precision, amounts, file_path)
    }

    pub(crate) fn issue_asset_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<AssetNIA, RgbLibError> {
        self.get_rgb_wallet()
            .issue_asset_nia(ticker, name, precision, amounts)
    }

    pub(crate) fn issue_asset_uda(
        &self,
        ticker: String,
        name: String,
        details: Option<String>,
        precision: u8,
        media_file_path: Option<String>,
        attachments_file_paths: Vec<String>,
    ) -> Result<AssetUDA, RgbLibError> {
        self.get_rgb_wallet().issue_asset_uda(
            ticker,
            name,
            details,
            precision,
            media_file_path,
            attachments_file_paths,
        )
    }

    pub(crate) fn list_assets(
        &self,
        filter_asset_schemas: Vec<AssetSchema>,
    ) -> Result<Assets, RgbLibError> {
        self.get_rgb_wallet().list_assets(filter_asset_schemas)
    }

    pub(crate) fn list_transactions(
        &self,
        skip_sync: bool,
    ) -> Result<Vec<RgbLibTransaction>, RgbLibError> {
        let online = if skip_sync {
            None
        } else {
            Some(self.online.clone())
        };
        self.get_rgb_wallet().list_transactions(online, skip_sync)
    }

    pub(crate) fn list_transfers(&self, asset_id: String) -> Result<Vec<Transfer>, RgbLibError> {
        self.get_rgb_wallet().list_transfers(Some(asset_id))
    }

    pub(crate) fn list_unspents(&self, skip_sync: bool) -> Result<Vec<Unspent>, RgbLibError> {
        let online = if skip_sync {
            None
        } else {
            Some(self.online.clone())
        };
        self.get_rgb_wallet()
            .list_unspents(online, false, skip_sync)
    }

    pub(crate) fn post_consignment<P: AsRef<Path>>(
        &self,
        proxy_url: &str,
        recipient_id: String,
        consignment_path: P,
        txid: String,
        vout: Option<u32>,
    ) -> Result<(), RgbLibError> {
        self.get_rgb_wallet().post_consignment(
            proxy_url,
            recipient_id,
            consignment_path,
            txid,
            vout,
        )
    }

    pub(crate) fn refresh(&self, skip_sync: bool) -> Result<RefreshResult, RgbLibError> {
        self.get_rgb_wallet()
            .refresh(self.online.clone(), None, vec![], skip_sync)
    }

    pub(crate) fn save_new_asset(
        &self,
        contract_id: ContractId,
        contract: Option<Contract>,
    ) -> Result<(), RgbLibError> {
        self.get_rgb_wallet().save_new_asset(contract_id, contract)
    }

    pub(crate) fn send(
        &self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<SendResult, RgbLibError> {
        self.get_rgb_wallet().send(
            self.online.clone(),
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            skip_sync,
        )
    }

    pub(crate) fn send_begin(
        &self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().send_begin(
            self.online.clone(),
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
        )
    }

    pub(crate) fn send_btc(
        &self,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_btc(self.online.clone(), address, amount, fee_rate, skip_sync)
    }

    pub(crate) fn send_btc_begin(
        &self,
        address: String,
        amount: u64,
        fee_rate: u64,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_btc_begin(self.online.clone(), address, amount, fee_rate, false)
    }

    pub(crate) fn send_btc_end(&self, signed_psbt: String) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_btc_end(self.online.clone(), signed_psbt, false)
    }

    pub(crate) fn send_end(&self, signed_psbt: String) -> Result<SendResult, RgbLibError> {
        self.get_rgb_wallet()
            .send_end(self.online.clone(), signed_psbt, false)
    }

    pub(crate) fn sign_psbt(&self, unsigned_psbt: String) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().sign_psbt(unsigned_psbt, None)
    }

    pub(crate) fn sync(&self) -> Result<(), RgbLibError> {
        self.get_rgb_wallet().sync(self.online.clone())
    }

    pub(crate) fn update_witnesses(
        &self,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, RgbLibError> {
        self.get_rgb_wallet()
            .update_witnesses(after_height, force_witnesses)
    }

    pub(crate) fn upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), RgbLibError> {
        self.get_rgb_wallet()
            .upsert_witness(witness_id, witness_ord)
    }

    pub(crate) fn witness_receive(
        &self,
        asset_id: Option<String>,
        duration_seconds: Option<u32>,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, RgbLibError> {
        self.get_rgb_wallet().witness_receive(
            asset_id,
            Assignment::Any,
            duration_seconds,
            transport_endpoints,
            min_confirmations,
        )
    }
}

impl ChangeDestinationSource for RgbLibWalletWrapper {
    fn get_change_destination_script(&self) -> Result<ScriptBuf, ()> {
        Ok(Address::from_str(&self.get_address().unwrap())
            .unwrap()
            .assume_checked()
            .script_pubkey())
    }
}

impl WalletSource for RgbLibWalletWrapper {
    fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()> {
        let network =
            Network::from_str(&self.bitcoin_network().to_string().to_lowercase()).unwrap();
        let mut wallet = self.wallet.lock().unwrap();
        Ok(wallet.list_unspents_vanilla(self.online.clone(), 1, false).unwrap().iter().filter_map(|u| {
            let script = u.txout.script_pubkey.clone().into_boxed_script();
            let address = Address::from_script(&script, network).unwrap();
            let outpoint = OutPoint::from_str(&u.outpoint.to_string()).unwrap();
            let value = u.txout.value;
            match address.witness_program() {
                Some(prog) if prog.is_p2wpkh() => {
                    WPubkeyHash::from_slice(prog.program().as_bytes())
                        .map(|wpkh| Utxo::new_v0_p2wpkh(outpoint, value, &wpkh))
                        .ok()
                },
                Some(prog) if prog.is_p2tr() => {
                    // TODO: Add `Utxo::new_v1_p2tr` upstream.
                    XOnlyPublicKey::from_slice(prog.program().as_bytes())
                        .map(|_| Utxo {
                            outpoint,
                            output: TxOut {
                                value,
                                script_pubkey: ScriptBuf::new_witness_program(&prog),
                            },
                            #[allow(clippy::identity_op)]
                            satisfaction_weight: 1 /* empty script_sig */ * WITNESS_SCALE_FACTOR as u64 +
                                1 /* witness items */ + 1 /* schnorr sig len */ + 64, /* schnorr sig */
                        })
                        .ok()
                },
                _ => None,
            }
        })
        .collect())
    }

    fn get_change_script(&self) -> Result<ScriptBuf, ()> {
        Ok(
            Address::from_str(&self.wallet.lock().unwrap().get_address().unwrap())
                .unwrap()
                .assume_checked()
                .script_pubkey(),
        )
    }

    fn sign_psbt(&self, tx: Psbt) -> Result<Transaction, ()> {
        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let signed = self
            .wallet
            .lock()
            .unwrap()
            .sign_psbt(tx.to_string(), Some(sign_options))
            .unwrap();
        Ok(Psbt::from_str(&signed).unwrap().extract_tx().unwrap())
    }
}

pub(crate) async fn check_rgb_proxy_endpoint(proxy_endpoint: &str) -> Result<(), APIError> {
    let rgb_transport =
        RgbTransport::from_str(proxy_endpoint).map_err(|_| APIError::InvalidProxyEndpoint)?;
    let proxy_url = TransportEndpoint::try_from(rgb_transport)?.endpoint;
    tokio::task::spawn_blocking(move || check_proxy_url(&proxy_url))
        .await
        .unwrap()?;
    Ok(())
}

pub(crate) fn get_rgb_channel_info_optional(
    channel_id: &ChannelId,
    ldk_data_dir: &Path,
    pending: bool,
) -> Option<(RgbInfo, PathBuf)> {
    if !is_channel_rgb(channel_id, ldk_data_dir) {
        return None;
    }
    let info_file_path =
        get_rgb_channel_info_path(&channel_id.0.as_hex().to_string(), ldk_data_dir, pending);
    let rgb_info = parse_rgb_channel_info(&info_file_path);
    Some((rgb_info, info_file_path))
}
