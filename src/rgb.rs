use amplify::ByteArray;
use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::util::address::{Payload, WitnessVersion};
use bitcoin::{
    Address, Network, OutPoint, Script, Transaction, TxOut, WPubkeyHash, XOnlyPublicKey,
};
use bitcoin_30::hashes::Hash as Hash30;
use bitcoin_30::psbt::PartiallySignedTransaction as RgbPsbt;
use bp::seals::txout::blind::{BlindSeal, SingleBlindSeal};
use bp::seals::txout::{CloseMethod, TxPtr};
use bp::Outpoint as RgbOutpoint;
use lightning::events::bump_transaction::{Utxo, WalletSource};
use lightning::ln::ChannelId;
use lightning::rgb_utils::{
    get_rgb_channel_info_path, is_channel_rgb, parse_rgb_channel_info, RgbInfo, STATIC_BLINDING,
};
use rgb_core::Operation;
use rgb_lib::utils::RgbRuntime;
use rgb_lib::wallet::{
    AssetNIA, Assets, Balance, BtcBalance, Online, ReceiveData, Recipient,
    Transaction as RgbLibTransaction, Transfer, Unspent,
};
use rgb_lib::{
    AssetSchema, BitcoinNetwork, Error as RgbLibError, SignOptions, Wallet as RgbLibWallet,
};
use rgbstd::containers::{Bindle, BuilderSeal, Transfer as RgbTransfer};
use rgbstd::contract::{ContractId, GraphSeal};
use rgbstd::interface::{TransitionBuilder, TypedState};
use rgbstd::persistence::Inventory;
use rgbstd::Txid as RgbTxid;
use rgbwallet::psbt::opret::OutputOpret;
use rgbwallet::psbt::{PsbtDbc, RgbExt, RgbInExt};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::utils::UnlockedAppState;

pub(crate) fn update_transition_beneficiary(
    psbt: &PartiallySignedTransaction,
    beneficiaries: &mut Vec<BuilderSeal<BlindSeal<TxPtr>>>,
    mut asset_transition_builder: TransitionBuilder,
    assignment_id: u16,
    amt_rgb: u64,
) -> (u32, TransitionBuilder) {
    let mut seal_vout = 0;
    if let Some((index, _)) = psbt
        .clone()
        .unsigned_tx
        .output
        .iter_mut()
        .enumerate()
        .find(|(_, o)| o.script_pubkey.is_op_return())
    {
        seal_vout = index as u32 ^ 1;
    }
    let seal = BuilderSeal::Revealed(GraphSeal::with_vout(
        CloseMethod::OpretFirst,
        seal_vout,
        STATIC_BLINDING,
    ));
    beneficiaries.push(seal);
    asset_transition_builder = asset_transition_builder
        .add_raw_state(assignment_id, seal, TypedState::Amount(amt_rgb))
        .expect("ok");
    (seal_vout, asset_transition_builder)
}

// TODO: remove after updating to bitcoin 0.30
pub(crate) fn get_bitcoin_network(network: &Network) -> BitcoinNetwork {
    BitcoinNetwork::from_str(&network.to_string()).unwrap()
}

impl UnlockedAppState {
    pub(crate) fn rgb_blind_receive(
        &self,
        asset_id: Option<String>,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, RgbLibError> {
        self.get_rgb_wallet().blind_receive(
            asset_id,
            None,
            None,
            transport_endpoints,
            min_confirmations,
        )
    }

    pub(crate) fn rgb_create_utxos(
        &self,
        up_to: bool,
        num: u8,
        size: u32,
        fee_rate: f32,
    ) -> Result<u8, RgbLibError> {
        self.get_rgb_wallet().create_utxos(
            self.rgb_online.clone(),
            up_to,
            Some(num),
            Some(size),
            fee_rate,
        )
    }

    pub(crate) fn rgb_get_address(&self) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().get_address()
    }

    pub(crate) fn rgb_get_asset_balance(
        &self,
        contract_id: ContractId,
    ) -> Result<Balance, RgbLibError> {
        self.get_rgb_wallet()
            .get_asset_balance(contract_id.to_string())
    }

    pub(crate) fn rgb_get_btc_balance(&self) -> Result<BtcBalance, RgbLibError> {
        self.get_rgb_wallet()
            .get_btc_balance(self.rgb_online.clone())
    }

    pub(crate) fn rgb_get_wallet_dir(&self) -> PathBuf {
        self.get_rgb_wallet().get_wallet_dir()
    }

    pub(crate) fn rgb_issue_asset_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<AssetNIA, RgbLibError> {
        self.get_rgb_wallet().issue_asset_nia(
            self.rgb_online.clone(),
            ticker,
            name,
            precision,
            amounts,
        )
    }

    pub(crate) fn rgb_list_assets(&self) -> Result<Assets, RgbLibError> {
        self.get_rgb_wallet().list_assets(vec![])
    }

    pub(crate) fn rgb_list_transactions(&self) -> Result<Vec<RgbLibTransaction>, RgbLibError> {
        self.get_rgb_wallet()
            .list_transactions(Some(self.rgb_online.clone()))
    }

    pub(crate) fn rgb_list_transfers(
        &self,
        asset_id: String,
    ) -> Result<Vec<Transfer>, RgbLibError> {
        self.get_rgb_wallet().list_transfers(Some(asset_id))
    }

    pub(crate) fn rgb_list_unspents(&self) -> Result<Vec<Unspent>, RgbLibError> {
        self.get_rgb_wallet()
            .list_unspents(Some(self.rgb_online.clone()), false)
    }

    pub(crate) fn rgb_refresh(&self) -> Result<bool, RgbLibError> {
        self.get_rgb_wallet()
            .refresh(self.rgb_online.clone(), None, vec![])
    }

    pub(crate) fn rgb_save_new_asset(
        &self,
        runtime: &mut RgbRuntime,
        asset_schema: &AssetSchema,
        contract_id: ContractId,
    ) -> Result<(), RgbLibError> {
        self.get_rgb_wallet()
            .save_new_asset(runtime, asset_schema, contract_id)
    }

    pub(crate) fn rgb_send(
        &self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: f32,
        min_confirmations: u8,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().send(
            self.rgb_online.clone(),
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
        )
    }

    pub(crate) fn rgb_send_begin(
        &self,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: f32,
        min_confirmations: u8,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().send_begin(
            self.rgb_online.clone(),
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
        )
    }

    pub(crate) fn rgb_send_btc(
        &self,
        address: String,
        amount: u64,
        fee_rate: f32,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_btc(self.rgb_online.clone(), address, amount, fee_rate)
    }

    pub(crate) fn rgb_send_btc_begin(
        &self,
        address: String,
        amount: u64,
        fee_rate: f32,
    ) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_btc_begin(self.rgb_online.clone(), address, amount, fee_rate)
    }

    pub(crate) fn rgb_send_btc_end(&self, signed_psbt: String) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_btc_end(self.rgb_online.clone(), signed_psbt)
    }

    pub(crate) fn rgb_send_end(&self, signed_psbt: String) -> Result<String, RgbLibError> {
        self.get_rgb_wallet()
            .send_end(self.rgb_online.clone(), signed_psbt)
    }

    pub(crate) fn rgb_sign_psbt(&self, unsigned_psbt: String) -> Result<String, RgbLibError> {
        self.get_rgb_wallet().sign_psbt(unsigned_psbt, None)
    }

    pub(crate) fn rgb_witness_receive(
        &self,
        transport_endpoints: Vec<String>,
    ) -> Result<ReceiveData, RgbLibError> {
        self.get_rgb_wallet()
            .witness_receive(None, None, None, transport_endpoints, 0)
    }
}

pub(crate) trait RgbUtilities {
    fn send_rgb(
        &mut self,
        contract_id: ContractId,
        psbt: PartiallySignedTransaction,
        asset_transition_builder: TransitionBuilder,
        beneficiaries: Vec<BuilderSeal<GraphSeal>>,
    ) -> (PartiallySignedTransaction, Bindle<RgbTransfer>);
}

impl RgbUtilities for RgbRuntime {
    fn send_rgb(
        &mut self,
        contract_id: ContractId,
        psbt: PartiallySignedTransaction,
        asset_transition_builder: TransitionBuilder,
        beneficiaries: Vec<BuilderSeal<GraphSeal>>,
    ) -> (PartiallySignedTransaction, Bindle<RgbTransfer>) {
        let mut psbt = RgbPsbt::from_str(&psbt.to_string()).unwrap();
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .map(|outpoint| RgbOutpoint::new(outpoint.txid.to_byte_array().into(), outpoint.vout))
            .collect::<Vec<_>>();
        let mut asset_transition_builder = asset_transition_builder;
        for (opout, _state) in self
            .runtime
            .state_for_outpoints(contract_id, prev_outputs.iter().copied())
            .expect("ok")
        {
            asset_transition_builder = asset_transition_builder
                .add_input(opout)
                .expect("valid input");
        }
        let transition = asset_transition_builder
            .complete_transition(contract_id)
            .expect("should complete transition");
        let mut contract_inputs = HashMap::<ContractId, Vec<RgbOutpoint>>::new();
        for outpoint in prev_outputs {
            for id in self.runtime.contracts_by_outpoints([outpoint]).expect("ok") {
                contract_inputs.entry(id).or_default().push(outpoint);
            }
        }
        let inputs = contract_inputs.remove(&contract_id).unwrap_or_default();
        for (input, txin) in psbt.inputs.iter_mut().zip(&psbt.unsigned_tx.input) {
            let prevout = txin.previous_output;
            let outpoint = RgbOutpoint::new(prevout.txid.to_byte_array().into(), prevout.vout);
            if inputs.contains(&outpoint) {
                input
                    .set_rgb_consumer(contract_id, transition.id())
                    .expect("ok");
            }
        }
        psbt.push_rgb_transition(transition).expect("ok");
        let bundles = psbt.rgb_bundles().expect("able to get bundles");
        let (opreturn_index, _) = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .expect("psbt should have an op_return output");
        let (_, opreturn_output) = psbt
            .outputs
            .iter_mut()
            .enumerate()
            .find(|(i, _)| i == &opreturn_index)
            .unwrap();
        opreturn_output
            .set_opret_host()
            .expect("cannot set opret host");
        psbt.rgb_bundle_to_lnpbp4().expect("ok");
        let anchor = psbt
            .dbc_conclude(CloseMethod::OpretFirst)
            .expect("should conclude");
        let witness_txid = psbt.unsigned_tx.txid();
        self.runtime
            .consume_anchor(anchor)
            .expect("should consume anchor");
        for (id, bundle) in bundles {
            self.runtime
                .consume_bundle(id, bundle, witness_txid.to_byte_array().into())
                .expect("should consume bundle");
        }
        let beneficiaries: Vec<BuilderSeal<SingleBlindSeal>> = beneficiaries
            .into_iter()
            .map(|b| match b {
                BuilderSeal::Revealed(graph_seal) => BuilderSeal::Revealed(
                    graph_seal.resolve(RgbTxid::from_byte_array(witness_txid.to_byte_array())),
                ),
                BuilderSeal::Concealed(seal) => BuilderSeal::Concealed(seal),
            })
            .collect();
        let transfer = self
            .runtime
            .transfer(contract_id, beneficiaries)
            .expect("valid transfer");

        let psbt = PartiallySignedTransaction::from_str(&psbt.to_string()).unwrap();

        (psbt, transfer)
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
}

impl WalletSource for RgbLibWalletWrapper {
    fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()> {
        let wallet = self.wallet.lock().unwrap();
        let network = Network::from_str(
            &wallet
                .get_wallet_data()
                .bitcoin_network
                .to_string()
                .to_lowercase(),
        )
        .unwrap();
        Ok(wallet.list_unspents_vanilla(self.online.clone(), 1).unwrap().iter().filter_map(|u| {
            let script = Script::from_hex(&u.txout.script_pubkey.to_hex()).unwrap();
            let address = Address::from_script(&script, network).unwrap();
            let outpoint = OutPoint::from_str(&u.outpoint.to_string()).unwrap();
            match address.payload {
                Payload::WitnessProgram { version, ref program } => match version {
                    WitnessVersion::V0 => WPubkeyHash::from_slice(program)
                        .map(|wpkh| Utxo::new_v0_p2wpkh(outpoint, u.txout.value, &wpkh))
                        .ok(),
                    // TODO: Add `Utxo::new_v1_p2tr` upstream.
                    WitnessVersion::V1 => XOnlyPublicKey::from_slice(program)
                        .map(|_| Utxo {
                            outpoint,
                            output: TxOut {
                                value: u.txout.value,
                                script_pubkey: Script::new_witness_program(version, program),
                            },
                            satisfaction_weight: WITNESS_SCALE_FACTOR as u64 +
                                1 /* witness items */ + 1 /* schnorr sig len */ + 64, /* schnorr sig */
                        })
                        .ok(),
                    _ => None,
                },
                _ => None,
            }
        })
        .collect())
    }

    fn get_change_script(&self) -> Result<Script, ()> {
        Ok(
            Address::from_str(&self.wallet.lock().unwrap().get_address().unwrap())
                .unwrap()
                .script_pubkey(),
        )
    }

    fn sign_tx(&self, tx: Transaction) -> Result<Transaction, ()> {
        let psbt = RgbPsbt::from_str(&Psbt::from_unsigned_tx(tx).unwrap().to_string()).unwrap();
        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let signed = self
            .wallet
            .lock()
            .unwrap()
            .sign_psbt(psbt.to_string(), Some(sign_options))
            .unwrap();
        Ok(Psbt::from_str(&signed).unwrap().extract_tx())
    }
}

pub fn get_rgb_channel_info_optional(
    channel_id: &ChannelId,
    ldk_data_dir: &Path,
    pending: bool,
) -> Option<(RgbInfo, PathBuf)> {
    if !is_channel_rgb(channel_id, ldk_data_dir) {
        return None;
    }
    let info_file_path = get_rgb_channel_info_path(&channel_id.to_hex(), ldk_data_dir, pending);
    let rgb_info = parse_rgb_channel_info(&info_file_path);
    Some((rgb_info, info_file_path))
}
