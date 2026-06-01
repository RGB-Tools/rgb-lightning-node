use super::types::{
    ChannelPublicKeys, ExternalChannelHtlc, ExternalChannelOp, ExternalChannelRequest,
    ExternalSignerRequest, ExternalSignerResponse, RlnSignerError,
};
use super::vls_adapter::ExternalSignerBackend;
use super::RlnChannelSigner;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::DisplayHex;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Transaction;
use bitcoin::Txid;
use lightning::ln::chan_utils::{
    ChannelPublicKeys as LdkChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction,
    CommitmentTransaction, HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::rgb_utils::{
    holder_validate_install_psbt_output_witness_scripts_hex,
    holder_validate_take_psbt_output_witness_scripts_hex, is_tx_colored,
};
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::{ChannelSigner, HTLCDescriptor};
use lightning::types::features::ChannelTypeFeatures;
use lightning::types::payment::PaymentPreimage;
use lightning::util::ser::Writeable;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const INITIAL_COMMITMENT_NUMBER: u64 = (1u64 << 48) - 1;

#[derive(Clone)]
pub(crate) struct ExternalChannelSigner {
    backend: Arc<dyn ExternalSignerBackend>,
    channel_keys_id_hex: String,
    channel_pubkeys: ChannelPublicKeys,
    setup_complete: Arc<AtomicBool>,
    deferred_initial_holder_validation: Arc<Mutex<Option<DeferredInitialHolderValidation>>>,
}

#[derive(Clone)]
struct DeferredInitialHolderValidation {
    commitment_number: u64,
    to_broadcaster_value_sat: u64,
    to_countersignatory_value_sat: u64,
    feerate_per_kw: u32,
    nondust_htlcs: Vec<HTLCOutputInCommitment>,
    counterparty_sig: Signature,
    counterparty_htlc_sigs: Vec<Signature>,
    commitment_unsigned_tx_hex: Option<String>,
    commitment_psbt_output_witness_scripts_hex: Option<Vec<String>>,
}

impl ExternalChannelSigner {
    fn derive_initial_push_value_msat(
        &self,
        channel_parameters: &ChannelTransactionParameters,
    ) -> Option<u64> {
        let pending = self
            .deferred_initial_holder_validation
            .lock()
            .ok()?
            .clone()?;
        if pending.commitment_number != 0 || !pending.nondust_htlcs.is_empty() {
            return None;
        }
        let pushed_sat = if channel_parameters.is_outbound_from_holder {
            pending.to_countersignatory_value_sat
        } else {
            pending.to_broadcaster_value_sat
        };
        pushed_sat.checked_mul(1000)
    }

    fn channel_type_kind(features: &ChannelTypeFeatures) -> u8 {
        if features.supports_anchors_zero_fee_htlc_tx() {
            2
        } else if features.supports_anchors_nonzero_fee_htlc_tx() {
            1
        } else {
            0
        }
    }

    fn to_external_channel_pubkeys(pubkeys: &LdkChannelPublicKeys) -> ChannelPublicKeys {
        ChannelPublicKeys {
            funding_pubkey_hex: pubkeys.funding_pubkey.serialize().to_lower_hex_string(),
            revocation_basepoint_hex: pubkeys
                .revocation_basepoint
                .0
                .serialize()
                .to_lower_hex_string(),
            payment_point_hex: pubkeys.payment_point.serialize().to_lower_hex_string(),
            delayed_payment_basepoint_hex: pubkeys
                .delayed_payment_basepoint
                .0
                .serialize()
                .to_lower_hex_string(),
            htlc_basepoint_hex: pubkeys.htlc_basepoint.0.serialize().to_lower_hex_string(),
        }
    }

    fn setup_channel(
        &self,
        channel_parameters: &ChannelTransactionParameters,
    ) -> Result<(), RlnSignerError> {
        let Some(counterparty) = channel_parameters.counterparty_parameters.as_ref() else {
            return Err(RlnSignerError::Protocol(
                "missing counterparty channel parameters for external signer setup".to_string(),
            ));
        };
        let Some(funding_outpoint) = channel_parameters.funding_outpoint.as_ref() else {
            return Err(RlnSignerError::Protocol(
                "missing funding outpoint for external signer setup".to_string(),
            ));
        };
        tracing::debug!(
            channel_keys_id = %self.channel_keys_id_hex,
            funding_txid = %funding_outpoint.txid,
            funding_vout = funding_outpoint.index,
            derived_push_value_msat = ?self.derive_initial_push_value_msat(channel_parameters),
            "external signer setup_channel request"
        );
        let push_value_msat = self
            .derive_initial_push_value_msat(channel_parameters)
            .unwrap_or(0);
        let resp =
            self.backend
                .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                    channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                    op: ExternalChannelOp::SetupChannel {
                        is_outbound: channel_parameters.is_outbound_from_holder,
                        channel_value_satoshis: channel_parameters.channel_value_satoshis,
                        push_value_msat,
                        funding_txid_hex: funding_outpoint.txid.to_string(),
                        funding_vout: funding_outpoint.index,
                        holder_selected_contest_delay: channel_parameters
                            .holder_selected_contest_delay,
                        counterparty_pubkeys: Self::to_external_channel_pubkeys(
                            &counterparty.pubkeys,
                        ),
                        counterparty_selected_contest_delay: counterparty.selected_contest_delay,
                        channel_type_kind: Self::channel_type_kind(
                            &channel_parameters.channel_type_features,
                        ),
                    },
                }))?;
        tracing::debug!(
            channel_keys_id = %self.channel_keys_id_hex,
            response = ?resp,
            "external signer setup_channel response"
        );
        match resp {
            ExternalSignerResponse::Channel(
                super::types::ExternalChannelResponse::SetupComplete,
            ) => {
                self.setup_complete.store(true, Ordering::Release);
                Ok(())
            }
            other => Err(RlnSignerError::Protocol(format!(
                "unexpected response for setup_channel: {other:?}"
            ))),
        }
    }

    fn to_external_htlcs(
        htlcs: &[HTLCOutputInCommitment],
        is_remote: bool,
    ) -> Vec<ExternalChannelHtlc> {
        htlcs
            .iter()
            .map(|h| ExternalChannelHtlc {
                side: if h.offered != is_remote { 0 } else { 1 },
                amount_msat: h.amount_msat,
                payment_hash_hex: h.payment_hash.0.to_lower_hex_string(),
                cltv_expiry: h.cltv_expiry,
            })
            .collect()
    }

    pub(crate) fn new(
        backend: Arc<dyn ExternalSignerBackend>,
        channel_keys_id_hex: String,
        _channel_signer_state_hex: String,
        channel_pubkeys: ChannelPublicKeys,
    ) -> Self {
        Self {
            backend,
            channel_keys_id_hex,
            channel_pubkeys,
            setup_complete: Arc::new(AtomicBool::new(false)),
            deferred_initial_holder_validation: Arc::new(Mutex::new(None)),
        }
    }

    fn replay_deferred_initial_holder_validation(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<(), ()> {
        let pending = self
            .deferred_initial_holder_validation
            .lock()
            .map_err(|_| ())?
            .clone();
        let Some(pending) = pending else {
            return Ok(());
        };
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::ValidateHolderCommitment {
                    commitment_number: INITIAL_COMMITMENT_NUMBER
                        .saturating_sub(pending.commitment_number),
                    feerate_sat_per_kw: pending.feerate_per_kw,
                    to_local_value_sat: pending.to_broadcaster_value_sat,
                    to_remote_value_sat: pending.to_countersignatory_value_sat,
                    htlcs: Self::to_external_htlcs(&pending.nondust_htlcs, false),
                    counterparty_signature_hex: pending
                        .counterparty_sig
                        .serialize_compact()
                        .to_lower_hex_string(),
                    counterparty_htlc_signatures_hex: pending
                        .counterparty_htlc_sigs
                        .iter()
                        .map(|sig| sig.serialize_compact().to_lower_hex_string())
                        .collect(),
                    commitment_unsigned_tx_hex: pending.commitment_unsigned_tx_hex.clone(),
                    commitment_psbt_output_witness_scripts_hex: pending
                        .commitment_psbt_output_witness_scripts_hex
                        .clone(),
                },
            }))
            .map_err(|e| {
                tracing::warn!(
                    channel_keys_id = %self.channel_keys_id_hex,
                    commitment_number = pending.commitment_number,
                    error = %e,
                    "external signer deferred validate_holder_commitment transport/protocol failed"
                );
            })?;
        match resp {
            ExternalSignerResponse::Channel(
                super::types::ExternalChannelResponse::ValidationComplete,
            ) => {}
            _ => return Err(()),
        }
        let mut guard = self
            .deferred_initial_holder_validation
            .lock()
            .map_err(|_| ())?;
        *guard = None;
        Ok(())
    }

    pub(crate) fn get_per_commitment_point(&self, idx: u64) -> Result<String, RlnSignerError> {
        match self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::GetPerCommitmentPoint { idx },
            })) {
            Ok(ExternalSignerResponse::Channel(
                super::types::ExternalChannelResponse::PerCommitmentPoint { point_hex },
            )) => Ok(point_hex),
            Ok(other) => Err(RlnSignerError::Protocol(format!(
                "unexpected response for get_per_commitment_point: {other:?}"
            ))),
            Err(err) => {
                if !self.setup_complete.load(Ordering::Acquire) && idx < INITIAL_COMMITMENT_NUMBER {
                    let fallback_idx = idx.saturating_add(1);
                    tracing::warn!(
                        channel_keys_id = %self.channel_keys_id_hex,
                        idx,
                        fallback_idx,
                        error = %err,
                        "falling back to pre-setup commitment point"
                    );
                    match self.backend.call(ExternalSignerRequest::Channel(
                        ExternalChannelRequest::Op {
                            channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                            op: ExternalChannelOp::GetPerCommitmentPoint { idx: fallback_idx },
                        },
                    ))? {
                        ExternalSignerResponse::Channel(
                            super::types::ExternalChannelResponse::PerCommitmentPoint { point_hex },
                        ) => Ok(point_hex),
                        other => Err(RlnSignerError::Protocol(format!(
                            "unexpected fallback response for get_per_commitment_point: {other:?}"
                        ))),
                    }
                } else {
                    Err(err)
                }
            }
        }
    }

    pub(crate) fn release_commitment_secret(&self, idx: u64) -> Result<String, RlnSignerError> {
        match self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::ReleaseCommitmentSecret { idx },
            }))? {
            ExternalSignerResponse::Channel(
                super::types::ExternalChannelResponse::CommitmentSecret { secret_hex },
            ) => Ok(secret_hex),
            other => Err(RlnSignerError::Protocol(format!(
                "unexpected response for release_commitment_secret: {other:?}"
            ))),
        }
    }

    fn validate_holder_commitment_with_backend(
        &self,
        holder_tx: &HolderCommitmentTransaction,
    ) -> Result<(), ()> {
        let built = &holder_tx.trust().built_transaction().transaction;
        let commitment_psbt_output_witness_scripts_hex =
            holder_validate_take_psbt_output_witness_scripts_hex();
        let needs_wire_validation =
            is_tx_colored(built) || commitment_psbt_output_witness_scripts_hex.is_some();
        let commitment_unsigned_tx_hex = needs_wire_validation.then(|| serialize_hex(built));
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::ValidateHolderCommitment {
                    commitment_number: INITIAL_COMMITMENT_NUMBER
                        .saturating_sub(holder_tx.commitment_number()),
                    feerate_sat_per_kw: holder_tx.negotiated_feerate_per_kw(),
                    to_local_value_sat: holder_tx.to_broadcaster_value_sat(),
                    to_remote_value_sat: holder_tx.to_countersignatory_value_sat(),
                    htlcs: Self::to_external_htlcs(holder_tx.nondust_htlcs(), false),
                    counterparty_signature_hex: holder_tx
                        .counterparty_sig
                        .serialize_compact()
                        .to_lower_hex_string(),
                    counterparty_htlc_signatures_hex: holder_tx
                        .counterparty_htlc_sigs
                        .iter()
                        .map(|sig| sig.serialize_compact().to_lower_hex_string())
                        .collect(),
                    commitment_unsigned_tx_hex,
                    commitment_psbt_output_witness_scripts_hex,
                },
            }))
            .map_err(|e| {
                tracing::warn!(
                    channel_keys_id = %self.channel_keys_id_hex,
                    commitment_number = holder_tx.commitment_number(),
                    wire_validation = needs_wire_validation,
                    error = %e,
                    "external signer validate_holder_commitment transport/protocol failed"
                );
            })?;
        match resp {
            ExternalSignerResponse::Channel(
                super::types::ExternalChannelResponse::ValidationComplete,
            ) => Ok(()),
            _ => Err(()),
        }
    }

    fn parse_signature(signature_hex: &str) -> Result<Signature, ()> {
        let bytes = Vec::<u8>::from_hex(signature_hex).map_err(|_| ())?;
        Signature::from_der(&bytes)
            .or_else(|_| Signature::from_compact(&bytes))
            .map_err(|_| ())
    }

    fn ldk_pubkeys(&self) -> Option<LdkChannelPublicKeys> {
        let funding = PublicKey::from_slice(
            &Vec::<u8>::from_hex(&self.channel_pubkeys.funding_pubkey_hex).ok()?,
        )
        .ok()?;
        let revocation = PublicKey::from_slice(
            &Vec::<u8>::from_hex(&self.channel_pubkeys.revocation_basepoint_hex).ok()?,
        )
        .ok()?;
        let payment = PublicKey::from_slice(
            &Vec::<u8>::from_hex(&self.channel_pubkeys.payment_point_hex).ok()?,
        )
        .ok()?;
        let delayed = PublicKey::from_slice(
            &Vec::<u8>::from_hex(&self.channel_pubkeys.delayed_payment_basepoint_hex).ok()?,
        )
        .ok()?;
        let htlc = PublicKey::from_slice(
            &Vec::<u8>::from_hex(&self.channel_pubkeys.htlc_basepoint_hex).ok()?,
        )
        .ok()?;
        Some(LdkChannelPublicKeys {
            funding_pubkey: funding,
            revocation_basepoint: RevocationBasepoint(revocation),
            payment_point: payment,
            delayed_payment_basepoint: DelayedPaymentBasepoint(delayed),
            htlc_basepoint: HtlcBasepoint(htlc),
        })
    }
}

impl ChannelSigner for ExternalChannelSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<PublicKey, ()> {
        let point_hex = self.get_per_commitment_point(idx).map_err(|_| ())?;
        let point = Vec::<u8>::from_hex(&point_hex).map_err(|_| ())?;
        PublicKey::from_slice(&point).map_err(|_| ())
    }

    fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
        let secret_hex = self.release_commitment_secret(idx).map_err(|_| ())?;
        let secret = Vec::<u8>::from_hex(&secret_hex).map_err(|_| ())?;
        secret.try_into().map_err(|_| ())
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        _outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        if !self.setup_complete.load(Ordering::Acquire) {
            let built = &holder_tx.trust().built_transaction().transaction;
            let commitment_psbt_output_witness_scripts_hex =
                holder_validate_take_psbt_output_witness_scripts_hex();
            let needs_wire_validation =
                is_tx_colored(built) || commitment_psbt_output_witness_scripts_hex.is_some();
            let commitment_unsigned_tx_hex = needs_wire_validation.then(|| serialize_hex(built));
            let mut guard = self
                .deferred_initial_holder_validation
                .lock()
                .map_err(|_| ())?;
            *guard = Some(DeferredInitialHolderValidation {
                commitment_number: holder_tx.commitment_number(),
                to_broadcaster_value_sat: holder_tx.to_broadcaster_value_sat(),
                to_countersignatory_value_sat: holder_tx.to_countersignatory_value_sat(),
                feerate_per_kw: holder_tx.negotiated_feerate_per_kw(),
                nondust_htlcs: holder_tx.nondust_htlcs().clone(),
                counterparty_sig: holder_tx.counterparty_sig,
                counterparty_htlc_sigs: holder_tx.counterparty_htlc_sigs.clone(),
                commitment_unsigned_tx_hex,
                commitment_psbt_output_witness_scripts_hex,
            });
            tracing::debug!(
                channel_keys_id = %self.channel_keys_id_hex,
                commitment_number = holder_tx.commitment_number(),
                "deferring external validate_holder_commitment until setup_channel completes"
            );
            return Ok(());
        }
        self.validate_holder_commitment_with_backend(holder_tx)
    }

    fn validate_counterparty_revocation(&self, _idx: u64, _secret: &SecretKey) -> Result<(), ()> {
        Ok(())
    }

    fn pubkeys(&self, _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>) -> LdkChannelPublicKeys {
        self.ldk_pubkeys().unwrap_or_else(|| {
            let fallback = PublicKey::from_slice(&[2u8; 33]).expect("fallback key");
            LdkChannelPublicKeys {
                funding_pubkey: fallback,
                revocation_basepoint: RevocationBasepoint(fallback),
                payment_point: fallback,
                delayed_payment_basepoint: DelayedPaymentBasepoint(fallback),
                htlc_basepoint: HtlcBasepoint(fallback),
            }
        })
    }

    fn new_funding_pubkey(
        &self,
        _splice_parent_funding_txid: Txid,
        secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> PublicKey {
        self.pubkeys(secp_ctx).funding_pubkey
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        let bytes =
            Vec::<u8>::from_hex(&self.channel_keys_id_hex).unwrap_or_else(|_| vec![0u8; 32]);
        let mut out = [0u8; 32];
        if bytes.len() >= 32 {
            out.copy_from_slice(&bytes[..32]);
        }
        out
    }
}

impl EcdsaChannelSigner for ExternalChannelSigner {
    fn sign_counterparty_commitment(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &CommitmentTransaction,
        inbound_htlc_preimages: Vec<PaymentPreimage>,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        if let Err(e) = self.setup_channel(_channel_parameters) {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                "external signer setup_channel before sign_counterparty_commitment failed: {e}"
            );
            return Err(());
        }
        if let Err(()) =
            self.replay_deferred_initial_holder_validation(_channel_parameters, _secp_ctx)
        {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                "external signer deferred initial holder validation replay failed"
            );
            return Err(());
        }
        let mut preimages_hex: Vec<String> = inbound_htlc_preimages
            .into_iter()
            .map(|p| p.0.to_lower_hex_string())
            .collect();
        preimages_hex.extend(
            outbound_htlc_preimages
                .into_iter()
                .map(|p| p.0.to_lower_hex_string()),
        );
        let commitment_psbt_output_witness_scripts_hex = if is_tx_colored(
            &commitment_tx.trust().built_transaction().transaction,
        ) {
            let directed = _channel_parameters.as_counterparty_broadcastable();
            match commitment_tx.output_witness_scripts_for_vls_validate(&directed) {
                Ok(wits) => Some(
                    wits.iter()
                        .map(|s| s.as_bytes().to_lower_hex_string())
                        .collect(),
                ),
                Err(_) => {
                    tracing::error!(
                        channel_keys_id = %self.channel_keys_id_hex,
                        commitment_number = commitment_tx.trust().commitment_number(),
                        "external signer failed to derive counterparty commitment witness scripts"
                    );
                    return Err(());
                }
            }
        } else {
            None
        };
        let resp =
            match self
                .backend
                .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                    channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                    op: ExternalChannelOp::SignCounterpartyCommitment {
                        tx_hex: serialize_hex(
                            &commitment_tx.trust().built_transaction().transaction,
                        ),
                        remote_per_commitment_point_hex: commitment_tx
                            .trust()
                            .keys()
                            .per_commitment_point
                            .serialize()
                            .to_lower_hex_string(),
                        commitment_number: INITIAL_COMMITMENT_NUMBER
                            .saturating_sub(commitment_tx.trust().commitment_number()),
                        feerate_sat_per_kw: commitment_tx.negotiated_feerate_per_kw(),
                        to_local_value_sat: commitment_tx.trust().to_countersignatory_value_sat(),
                        to_remote_value_sat: commitment_tx.trust().to_broadcaster_value_sat(),
                        htlcs: Self::to_external_htlcs(commitment_tx.nondust_htlcs(), true),
                        preimages_hex,
                        commitment_psbt_output_witness_scripts_hex,
                    },
                })) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!(
                        channel_keys_id = %self.channel_keys_id_hex,
                        commitment_number = commitment_tx.trust().commitment_number(),
                        "external signer sign_counterparty_commitment failed: {e}"
                    );
                    return Err(());
                }
            };
        let ExternalSignerResponse::Channel(
            super::types::ExternalChannelResponse::SignatureWithHtlcs {
                signature_hex,
                htlc_signatures_hex,
            },
        ) = resp
        else {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                "external signer sign_counterparty_commitment returned unexpected response: {:?}",
                resp
            );
            return Err(());
        };
        let sig = match Self::parse_signature(&signature_hex) {
            Ok(sig) => sig,
            Err(_) => {
                tracing::error!(
                    channel_keys_id = %self.channel_keys_id_hex,
                    signature_hex = %signature_hex,
                    "external signer sign_counterparty_commitment returned unparsable signature"
                );
                return Err(());
            }
        };
        let htlc_sigs = htlc_signatures_hex
            .iter()
            .map(|s| {
                Self::parse_signature(s).map_err(|_| {
                    tracing::error!(
                        channel_keys_id = %self.channel_keys_id_hex,
                        signature_hex = %s,
                        "external signer sign_counterparty_commitment returned unparsable HTLC signature"
                    );
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        Ok((sig, htlc_sigs))
    }

    fn sign_holder_commitment(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        if let Err(e) = self.setup_channel(_channel_parameters) {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                "external signer setup_channel before sign_holder_commitment failed: {e}"
            );
            return Err(());
        }
        if is_tx_colored(&commitment_tx.trust().built_transaction().transaction) {
            let directed = _channel_parameters.as_holder_broadcastable();
            if let Ok(wits) = commitment_tx.output_witness_scripts_for_vls_validate(&directed) {
                let hex_scripts: Vec<String> = wits
                    .iter()
                    .map(|s| s.as_bytes().to_lower_hex_string())
                    .collect();
                holder_validate_install_psbt_output_witness_scripts_hex(hex_scripts);
            }
        }
        if let Err(e) = self.validate_holder_commitment_with_backend(commitment_tx) {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                commitment_number = commitment_tx.commitment_number(),
                "external signer validate_holder_commitment before sign_holder_commitment failed: {:?}",
                e
            );
            return Err(());
        }
        let resp =
            match self
                .backend
                .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                    channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                    op: ExternalChannelOp::SignHolderCommitment {
                        tx_hex: serialize_hex(
                            &commitment_tx.trust().built_transaction().transaction,
                        ),
                        commitment_number: INITIAL_COMMITMENT_NUMBER
                            .saturating_sub(commitment_tx.commitment_number()),
                    },
                })) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!(
                        channel_keys_id = %self.channel_keys_id_hex,
                        commitment_number = commitment_tx.commitment_number(),
                        "external signer sign_holder_commitment failed: {e}"
                    );
                    return Err(());
                }
            };
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                "external signer sign_holder_commitment returned unexpected response: {:?}",
                resp
            );
            return Err(());
        };
        Self::parse_signature(&signature_hex).map_err(|_| {
            tracing::error!(
                channel_keys_id = %self.channel_keys_id_hex,
                signature_hex = %signature_hex,
                "external signer sign_holder_commitment returned unparsable signature"
            );
        })
    }

    fn sign_justice_revoked_output(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignJusticeRevokedOutput {
                    tx_hex: serialize_hex(justice_tx),
                    input: input as u32,
                    amount_sat: amount,
                    per_commitment_key_hex: per_commitment_key.secret_bytes().to_lower_hex_string(),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_justice_revoked_htlc(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        _htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignJusticeRevokedHtlc {
                    tx_hex: serialize_hex(justice_tx),
                    input: input as u32,
                    amount_sat: amount,
                    per_commitment_key_hex: per_commitment_key.secret_bytes().to_lower_hex_string(),
                    htlc_hex: String::new(),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        _htlc_descriptor: &HTLCDescriptor,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignHolderHtlcTransaction {
                    tx_hex: serialize_hex(htlc_tx),
                    input: input as u32,
                    htlc_descriptor_hex: String::new(),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        _htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignCounterpartyHtlcTransaction {
                    tx_hex: serialize_hex(htlc_tx),
                    input: input as u32,
                    amount_sat: amount,
                    per_commitment_point_hex: per_commitment_point
                        .serialize()
                        .to_lower_hex_string(),
                    htlc_descriptor_hex: String::new(),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_closing_transaction(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        closing_tx: &ClosingTransaction,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignClosingTransaction {
                    tx_hex: serialize_hex(&closing_tx.trust().built_transaction()),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_holder_keyed_anchor_input(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        anchor_tx: &Transaction,
        input: usize,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignHolderAnchorInput {
                    tx_hex: serialize_hex(anchor_tx),
                    input: input as u32,
                    descriptor_hex: String::new(),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<Signature, ()> {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignChannelAnnouncementWithFundingKey {
                    msg_hex: msg.encode().to_lower_hex_string(),
                },
            }))
            .map_err(|_| ())?;
        let ExternalSignerResponse::Channel(super::types::ExternalChannelResponse::Signature {
            signature_hex,
        }) = resp
        else {
            return Err(());
        };
        Self::parse_signature(&signature_hex)
    }

    fn sign_splice_shared_input(
        &self,
        _channel_parameters: &ChannelTransactionParameters,
        tx: &Transaction,
        input_index: usize,
        _secp_ctx: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Signature {
        let resp = self
            .backend
            .call(ExternalSignerRequest::Channel(ExternalChannelRequest::Op {
                channel_keys_id_hex: self.channel_keys_id_hex.clone(),
                op: ExternalChannelOp::SignSplicingFundingInput {
                    tx_hex: serialize_hex(tx),
                    input: input_index as u32,
                    txin_descriptor_hex: String::new(),
                },
            }));
        match resp {
            Ok(ExternalSignerResponse::Channel(
                super::types::ExternalChannelResponse::Signature { signature_hex },
            )) => Self::parse_signature(&signature_hex)
                .unwrap_or_else(|_| Signature::from_compact(&[1u8; 64]).expect("signature")),
            _ => Signature::from_compact(&[1u8; 64]).expect("signature"),
        }
    }
}

impl RlnChannelSigner for ExternalChannelSigner {}
