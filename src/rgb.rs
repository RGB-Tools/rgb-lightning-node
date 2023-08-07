use amplify::RawArray;
use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bitcoin_30::hashes::Hash;
use bitcoin_30::psbt::PartiallySignedTransaction as RgbPsbt;
use bp::seals::txout::blind::{BlindSeal, SingleBlindSeal};
use bp::seals::txout::{CloseMethod, TxPtr};
use bp::Outpoint as RgbOutpoint;
use lightning::rgb_utils::STATIC_BLINDING;
use rgb_core::Operation;
use rgb_lib::utils::RgbRuntime;
use rgbstd::containers::{Bindle, BuilderSeal, Transfer as RgbTransfer};
use rgbstd::contract::{ContractId, GraphSeal};
use rgbstd::interface::{TransitionBuilder, TypedState};
use rgbstd::persistence::Inventory;
use rgbstd::Txid as RgbTxid;
use rgbwallet::psbt::opret::OutputOpret;
use rgbwallet::psbt::{PsbtDbc, RgbExt, RgbInExt};
use std::collections::HashMap;
use std::str::FromStr;

use crate::error::APIError;

pub(crate) fn match_rgb_lib_error(error: &rgb_lib::Error, default: APIError) -> APIError {
    tracing::error!("ERR from rgb-lib: {error:?}");
    match error {
        rgb_lib::Error::AssetNotFound { .. } => APIError::UnknownContractId,
        rgb_lib::Error::BlindedUTXOAlreadyUsed => APIError::BlindedUTXOAlreadyUsed,
        rgb_lib::Error::InsufficientAllocationSlots => APIError::NoAvailableUtxos,
        rgb_lib::Error::InsufficientBitcoins { needed, available } => {
            APIError::InsufficientFunds(needed - available)
        }
        rgb_lib::Error::InvalidBlindedUTXO { details } => {
            APIError::InvalidBlindedUTXO(details.clone())
        }
        rgb_lib::Error::InvalidName { details } => APIError::InvalidName(details.clone()),
        rgb_lib::Error::InvalidPrecision { details } => APIError::InvalidPrecision(details.clone()),
        rgb_lib::Error::InvalidTicker { details } => APIError::InvalidTicker(details.clone()),
        rgb_lib::Error::InvalidAssetID { asset_id } => APIError::InvalidAssetID(asset_id.clone()),
        _ => default,
    }
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
        .add_raw_state(assignment_id, seal, TypedState::Amount(amt_rgb))
        .expect("ok");
    (seal_vout, asset_transition_builder)
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
                    graph_seal.resolve(RgbTxid::from_raw_array(witness_txid.to_byte_array())),
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
