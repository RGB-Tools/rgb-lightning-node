use amplify::RawArray;
use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bdk::bitcoin::OutPoint;
use bdk::database::SqliteDatabase;
use bdk::Wallet;
use bitcoin_30::hashes::Hash;
use bitcoin_30::psbt::PartiallySignedTransaction as RgbPsbt;
use bp::seals::txout::blind::SingleBlindSeal;
use bp::seals::txout::CloseMethod;
use bp::Outpoint as RgbOutpoint;
use lightning::rgb_utils::{RgbUtxo, RgbUtxos, STATIC_BLINDING};
use rgb::Runtime;
use rgb_core::{Operation, Opout};
use rgb_schemata::{nia_rgb20, nia_schema};
use rgbstd::containers::{Bindle, BuilderSeal, Transfer as RgbTransfer};
use rgbstd::contract::{ContractId, GenesisSeal, GraphSeal};
use rgbstd::interface::{rgb20, ContractBuilder, TransitionBuilder, TypedState};
use rgbstd::persistence::Inventory;
use rgbstd::stl::{
    Amount, AssetNaming, ContractData, DivisibleAssetSpec, Name, Precision, RicardianContract,
    Ticker, Timestamp,
};
use rgbstd::Txid as RgbTxid;
use rgbwallet::psbt::opret::OutputOpret;
use rgbwallet::psbt::{PsbtDbc, RgbExt, RgbInExt};
use seals::txout::blind::BlindSeal;
use seals::txout::{ExplicitSeal, TxPtr};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fs;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::bdk::sync_wallet;
use crate::error::APIError;

#[derive(Deserialize, Serialize)]
pub(crate) struct BlindedInfo {
    pub(crate) contract_id: Option<ContractId>,
    pub(crate) seal: BlindSeal<TxPtr>,
    pub(crate) consumed: bool,
}

pub(crate) async fn check_uncolored_utxos(ldk_data_dir: &str) -> Result<(), APIError> {
    let rgb_utxos_path = format!("{}/rgb_utxos", ldk_data_dir);
    let serialized_utxos = fs::read_to_string(rgb_utxos_path).expect("able to read rgb utxos file");
    let rgb_utxos: RgbUtxos = serde_json::from_str(&serialized_utxos).expect("valid rgb utxos");
    let utxo = rgb_utxos.utxos.iter().find(|u| !u.colored);
    match utxo {
        Some(_) => Ok(()),
        None => Err(APIError::NoAvailableUtxos),
    }
}

pub(crate) async fn get_utxo(ldk_data_dir: &str) -> RgbUtxo {
    let rgb_utxos_path = format!("{}/rgb_utxos", ldk_data_dir);
    let serialized_utxos = fs::read_to_string(rgb_utxos_path).expect("able to read rgb utxos file");
    let rgb_utxos: RgbUtxos = serde_json::from_str(&serialized_utxos).expect("valid rgb utxos");
    rgb_utxos
        .utxos
        .into_iter()
        .find(|u| !u.colored)
        .expect("at least one unlocked UTXO")
}

pub(crate) fn get_rgb_total_amount(
    contract_id: ContractId,
    runtime: &Runtime,
    wallet_arc: Arc<Mutex<Wallet<SqliteDatabase>>>,
    electrum_url: String,
) -> Result<u64, APIError> {
    let asset_owned_values =
        get_asset_owned_values(contract_id, runtime, wallet_arc, electrum_url)?;
    Ok(asset_owned_values.iter().map(|(_, (_, amt))| amt).sum())
}

pub(crate) fn get_asset_owned_values(
    contract_id: ContractId,
    runtime: &Runtime,
    wallet_arc: Arc<Mutex<Wallet<SqliteDatabase>>>,
    electrum_url: String,
) -> Result<BTreeMap<Opout, (RgbOutpoint, u64)>, APIError> {
    let wallet = wallet_arc.lock().unwrap();
    sync_wallet(&wallet, electrum_url);
    let unspents_outpoints: Vec<OutPoint> = wallet
        .list_unspent()
        .expect("valid unspent list")
        .iter()
        .map(|u| u.outpoint)
        .collect();
    let outpoints: Vec<RgbOutpoint> = unspents_outpoints
        .iter()
        .map(|o| RgbOutpoint::new(RgbTxid::from_str(&o.txid.to_string()).unwrap(), o.vout))
        .collect();
    let history = runtime
        .debug_history()
        .get(&contract_id)
        .ok_or(APIError::UnknownContractId)?;
    let mut contract_state = BTreeMap::new();
    for output in history.fungibles() {
        if outpoints.contains(&output.seal) {
            contract_state.insert(output.opout, (output.seal, output.state.value.as_u64()));
        }
    }
    Ok(contract_state)
}

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
        .add_raw_state_static(assignment_id, seal, TypedState::Amount(amt_rgb))
        .expect("ok");
    (seal_vout, asset_transition_builder)
}

pub(crate) trait RgbUtilities {
    fn issue_contract(
        &mut self,
        amount: u64,
        outpoint: OutPoint,
        ticker: String,
        name: String,
        precision: u8,
    ) -> ContractId;

    fn send_rgb(
        &mut self,
        contract_id: ContractId,
        psbt: PartiallySignedTransaction,
        asset_transition_builder: TransitionBuilder,
        beneficiaries: Vec<BuilderSeal<GraphSeal>>,
    ) -> (PartiallySignedTransaction, Bindle<RgbTransfer>);
}

impl RgbUtilities for Runtime {
    fn issue_contract(
        &mut self,
        amount: u64,
        outpoint: OutPoint,
        ticker: String,
        name: String,
        precision: u8,
    ) -> ContractId {
        let spec = DivisibleAssetSpec {
            naming: AssetNaming {
                ticker: Ticker::try_from(ticker).expect("valid ticker"),
                name: Name::try_from(name).expect("valid name"),
                details: None,
            },
            precision: Precision::try_from(precision).expect("valid precision"),
        };
        let terms = RicardianContract::default();
        let contract_data = ContractData { terms, media: None };
        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let created = Timestamp::from(i32::try_from(created_at).unwrap());
        let seal = ExplicitSeal::<RgbTxid>::from_str(&format!("opret1st:{outpoint}")).unwrap();
        let seal = GenesisSeal::from(seal);

        let builder = ContractBuilder::with(rgb20(), nia_schema(), nia_rgb20())
            .expect("valid contract builder")
            .set_chain(self.chain())
            .add_global_state("spec", spec)
            .expect("invalid spec")
            .add_global_state("data", contract_data)
            .expect("invalid data")
            .add_global_state("issuedSupply", Amount::from(amount))
            .expect("invalid issuedSupply")
            .add_global_state("created", created)
            .expect("invalid created")
            .add_fungible_state("assetOwner", seal, amount)
            .expect("invalid global state data");
        let contract = builder.issue_contract().expect("failure issuing contract");
        let contract_id = contract.contract_id();
        let validated_contract = contract
            .validate(self.resolver())
            .expect("internal error: failed validating self-issued contract");
        self.import_contract(validated_contract)
            .expect("failure importing issued contract");
        contract_id
    }

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
            for id in self.contracts_by_outpoints([outpoint]).expect("ok") {
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
            .dbc_conclude_static(CloseMethod::OpretFirst)
            .expect("should conclude");
        let witness_txid = psbt.unsigned_tx.txid();
        self.consume_anchor(anchor).expect("should consume anchor");
        for (id, bundle) in bundles {
            self.consume_bundle(id, bundle, witness_txid.to_byte_array().into())
                .expect("should consume bundle");
        }
        let beneficiaries: Vec<BuilderSeal<SingleBlindSeal>> = beneficiaries
            .into_iter()
            .map(|b| match b {
                BuilderSeal::Revealed(graph_seal) => BuilderSeal::Revealed(
                    graph_seal.resolve(RgbTxid::from_raw_array(witness_txid.to_byte_array())),
                ),
                BuilderSeal::Concealed(seal) => BuilderSeal::Concealed(seal),
            })
            .collect();
        let transfer = self
            .transfer(contract_id, beneficiaries)
            .expect("valid transfer");

        let psbt = PartiallySignedTransaction::from_str(&psbt.to_string()).unwrap();

        (psbt, transfer)
    }
}
