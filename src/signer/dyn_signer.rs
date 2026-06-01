use std::sync::Arc;

use bitcoin::hex::FromHex;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{Transaction, TxOut, Txid};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::msgs::{
    DecodeError, FinalOnionHopData, UnsignedChannelAnnouncement, UnsignedGossipMessage,
};
use lightning::ln::script::ShutdownScript;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::{
    ChannelSigner, EntropySource, HTLCDescriptor, InMemorySigner, NodeSigner, OutputSpender,
    PeerStorageKey, ReceiveAuthKey, Recipient, SignerProvider, SpendableOutputDescriptor,
};
use lightning::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::util::errors::APIError;
use lightning_invoice::RawBolt11Invoice;

use super::{ExternalSigner, RlnChannelSigner, RlnKeysInterface, RlnSignerError};

#[derive(Clone)]
pub(crate) struct DynRlnChannelSigner {
    inner: Arc<dyn RlnChannelSigner>,
}

impl DynRlnChannelSigner {
    pub(crate) fn new(inner: Arc<dyn RlnChannelSigner>) -> Self {
        Self { inner }
    }
}

impl ChannelSigner for DynRlnChannelSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<PublicKey, ()> {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
        self.inner.release_commitment_secret(idx)
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        self.inner
            .validate_holder_commitment(holder_tx, outbound_htlc_preimages)
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        self.inner.validate_counterparty_revocation(idx, secret)
    }

    fn pubkeys(&self, secp_ctx: &Secp256k1<All>) -> ChannelPublicKeys {
        self.inner.pubkeys(secp_ctx)
    }

    fn new_funding_pubkey(
        &self,
        splice_parent_funding_txid: Txid,
        secp_ctx: &Secp256k1<All>,
    ) -> PublicKey {
        self.inner
            .new_funding_pubkey(splice_parent_funding_txid, secp_ctx)
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.inner.channel_keys_id()
    }
}

impl EcdsaChannelSigner for DynRlnChannelSigner {
    fn sign_counterparty_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &CommitmentTransaction,
        inbound_htlc_preimages: Vec<PaymentPreimage>,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner.sign_counterparty_commitment(
            channel_parameters,
            commitment_tx,
            inbound_htlc_preimages,
            outbound_htlc_preimages,
            secp_ctx,
        )
    }

    fn sign_holder_commitment(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner
            .sign_holder_commitment(channel_parameters, commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_output(
            channel_parameters,
            justice_tx,
            input,
            amount,
            per_commitment_key,
            secp_ctx,
        )
    }

    fn sign_justice_revoked_htlc(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_htlc(
            channel_parameters,
            justice_tx,
            input,
            amount,
            per_commitment_key,
            htlc,
            secp_ctx,
        )
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        htlc_descriptor: &HTLCDescriptor,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner
            .sign_holder_htlc_transaction(htlc_tx, input, htlc_descriptor, secp_ctx)
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(
            channel_parameters,
            htlc_tx,
            input,
            amount,
            per_commitment_point,
            htlc,
            secp_ctx,
        )
    }

    fn sign_closing_transaction(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        closing_tx: &ClosingTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner
            .sign_closing_transaction(channel_parameters, closing_tx, secp_ctx)
    }

    fn sign_holder_keyed_anchor_input(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        anchor_tx: &Transaction,
        input: usize,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner
            .sign_holder_keyed_anchor_input(channel_parameters, anchor_tx, input, secp_ctx)
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        msg: &UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner
            .sign_channel_announcement_with_funding_key(channel_parameters, msg, secp_ctx)
    }

    fn sign_splice_shared_input(
        &self,
        channel_parameters: &ChannelTransactionParameters,
        tx: &Transaction,
        input_index: usize,
        secp_ctx: &Secp256k1<All>,
    ) -> Signature {
        self.inner
            .sign_splice_shared_input(channel_parameters, tx, input_index, secp_ctx)
    }
}

#[derive(Clone)]
pub(crate) enum DynRlnSigner {
    Internal(Arc<lightning::sign::KeysManager>),
    External(Arc<ExternalSigner>),
}

impl DynRlnSigner {
    pub(crate) fn from_internal(inner: Arc<lightning::sign::KeysManager>) -> Self {
        Self::Internal(inner)
    }

    pub(crate) fn from_external(inner: Arc<ExternalSigner>) -> Self {
        Self::External(inner)
    }
}

impl EntropySource for DynRlnSigner {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        match self {
            Self::Internal(km) => km.get_secure_random_bytes(),
            // External matches `ExternalSigner` policy: LDK trait entropy is system-only (see
            // `crate::ldk::start_ldk` / `UnlockedAppState::entropy_source`).
            Self::External(es) => es.get_secure_random_bytes(),
        }
    }
}

impl NodeSigner for DynRlnSigner {
    fn get_expanded_key(&self) -> ExpandedKey {
        match self {
            Self::Internal(km) => km.get_expanded_key(),
            Self::External(es) => es.get_expanded_key(),
        }
    }

    fn crypt_for_offer(
        &self,
        payment_id: [u8; 32],
        nonce: lightning::offers::nonce::Nonce,
    ) -> [u8; 32] {
        match self {
            Self::Internal(km) => km.crypt_for_offer(payment_id, nonce),
            Self::External(es) => es.crypt_for_offer(payment_id, nonce),
        }
    }

    fn hmac_for_offer(&self) -> bitcoin::hashes::hmac::HmacEngine<bitcoin::hashes::sha256::Hash> {
        match self {
            Self::Internal(km) => km.hmac_for_offer(),
            Self::External(es) => es.hmac_for_offer(),
        }
    }

    fn create_inbound_payment(
        &self,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        random_bytes: [u8; 32],
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    ) -> Result<(PaymentHash, PaymentSecret), ()> {
        match self {
            Self::Internal(km) => km.create_inbound_payment(
                min_value_msat,
                invoice_expiry_delta_secs,
                random_bytes,
                current_time,
                min_final_cltv_expiry_delta,
            ),
            Self::External(es) => es.create_inbound_payment(
                min_value_msat,
                invoice_expiry_delta_secs,
                random_bytes,
                current_time,
                min_final_cltv_expiry_delta,
            ),
        }
    }

    fn create_inbound_payment_for_hash(
        &self,
        payment_hash: PaymentHash,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    ) -> Result<PaymentSecret, ()> {
        match self {
            Self::Internal(km) => km.create_inbound_payment_for_hash(
                payment_hash,
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            ),
            Self::External(es) => es.create_inbound_payment_for_hash(
                payment_hash,
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            ),
        }
    }

    fn create_spontaneous_payment_secret(
        &self,
        min_value_msat: Option<u64>,
        invoice_expiry_delta_secs: u32,
        current_time: u64,
        min_final_cltv_expiry_delta: Option<u16>,
    ) -> Result<PaymentSecret, ()> {
        match self {
            Self::Internal(km) => km.create_spontaneous_payment_secret(
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            ),
            Self::External(es) => es.create_spontaneous_payment_secret(
                min_value_msat,
                invoice_expiry_delta_secs,
                current_time,
                min_final_cltv_expiry_delta,
            ),
        }
    }

    fn verify_inbound_payment(
        &self,
        payment_hash: PaymentHash,
        payment_data: &FinalOnionHopData,
        highest_seen_timestamp: u64,
    ) -> Result<(Option<PaymentPreimage>, Option<u16>), ()> {
        match self {
            Self::Internal(km) => {
                km.verify_inbound_payment(payment_hash, payment_data, highest_seen_timestamp)
            }
            Self::External(es) => {
                es.verify_inbound_payment(payment_hash, payment_data, highest_seen_timestamp)
            }
        }
    }

    fn get_payment_preimage(
        &self,
        payment_hash: PaymentHash,
        payment_secret: PaymentSecret,
    ) -> Result<PaymentPreimage, APIError> {
        match self {
            Self::Internal(km) => km.get_payment_preimage(payment_hash, payment_secret),
            Self::External(es) => es.get_payment_preimage(payment_hash, payment_secret),
        }
    }

    fn get_peer_storage_key(&self) -> PeerStorageKey {
        match self {
            Self::Internal(km) => km.get_peer_storage_key(),
            Self::External(es) => es.get_peer_storage_key(),
        }
    }

    fn encrypt_peer_storage_payload(&self, plaintext: Vec<u8>, random_bytes: [u8; 32]) -> Vec<u8> {
        match self {
            Self::Internal(km) => km.encrypt_peer_storage_payload(plaintext, random_bytes),
            Self::External(es) => es.encrypt_peer_storage_payload(plaintext, random_bytes),
        }
    }

    fn decrypt_peer_storage_payload(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, ()> {
        match self {
            Self::Internal(km) => km.decrypt_peer_storage_payload(ciphertext),
            Self::External(es) => es.decrypt_peer_storage_payload(ciphertext),
        }
    }

    fn get_receive_auth_key(&self) -> ReceiveAuthKey {
        match self {
            Self::Internal(km) => km.get_receive_auth_key(),
            Self::External(es) => es.get_receive_auth_key(),
        }
    }

    fn encrypt_blinded_message_payload(&self, plaintext: Vec<u8>, rho: [u8; 32]) -> Vec<u8> {
        match self {
            Self::Internal(km) => km.encrypt_blinded_message_payload(plaintext, rho),
            Self::External(es) => es.encrypt_blinded_message_payload(plaintext, rho),
        }
    }

    fn decrypt_blinded_message_payload(
        &self,
        ciphertext: &[u8],
        rho: [u8; 32],
    ) -> Result<(Vec<u8>, bool), DecodeError> {
        match self {
            Self::Internal(km) => km.decrypt_blinded_message_payload(ciphertext, rho),
            Self::External(es) => es.decrypt_blinded_message_payload(ciphertext, rho),
        }
    }

    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        match self {
            Self::Internal(km) => km.get_node_id(recipient),
            Self::External(es) => es.get_node_id(recipient),
        }
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        match self {
            Self::Internal(km) => km.ecdh(recipient, other_key, tweak),
            Self::External(es) => es.ecdh(recipient, other_key, tweak),
        }
    }

    fn sign_invoice(
        &self,
        invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match self {
            Self::Internal(km) => km.sign_invoice(invoice, recipient),
            Self::External(es) => es.sign_invoice(invoice, recipient),
        }
    }

    fn sign_bolt12_invoice(
        &self,
        invoice: &UnsignedBolt12Invoice,
    ) -> Result<schnorr::Signature, ()> {
        match self {
            Self::Internal(km) => km.sign_bolt12_invoice(invoice),
            Self::External(es) => es.sign_bolt12_invoice(invoice),
        }
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        match self {
            Self::Internal(km) => km.sign_gossip_message(msg),
            Self::External(es) => es.sign_gossip_message(msg),
        }
    }

    fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
        match self {
            Self::Internal(km) => km.sign_message(msg),
            Self::External(es) => es.sign_message(msg),
        }
    }
}

impl SignerProvider for DynRlnSigner {
    type EcdsaSigner = DynRlnChannelSigner;

    fn generate_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32] {
        match self {
            Self::Internal(km) => km.generate_channel_keys_id(inbound, user_channel_id),
            Self::External(es) => {
                let hex_id = es.generate_channel_keys_id(inbound, 0, user_channel_id).unwrap_or_else(|e| {
                    panic!(
                        "external signer generate_channel_keys_id failed: inbound={inbound} user_channel_id={user_channel_id} error={e}"
                    )
                });
                let bytes = Vec::<u8>::from_hex(&hex_id).unwrap_or_else(|e| {
                    panic!(
                        "external signer generate_channel_keys_id returned invalid hex: inbound={inbound} user_channel_id={user_channel_id} hex={hex_id} error={e}"
                    )
                });
                if bytes.len() < 32 {
                    panic!(
                        "external signer generate_channel_keys_id returned too few bytes: inbound={inbound} user_channel_id={user_channel_id} len={} hex={hex_id}",
                        bytes.len()
                    );
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes[..32]);
                out
            }
        }
    }

    fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
        match self {
            Self::Internal(km) => {
                let s: InMemorySigner = km.derive_channel_signer(channel_keys_id);
                DynRlnChannelSigner::new(Arc::new(s))
            }
            Self::External(es) => {
                let s = <ExternalSigner as SignerProvider>::derive_channel_signer(
                    es.as_ref(),
                    channel_keys_id,
                );
                DynRlnChannelSigner::new(Arc::new(s))
            }
        }
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        match self {
            Self::Internal(km) => km.get_destination_script(channel_keys_id),
            Self::External(es) => es.get_destination_script(channel_keys_id),
        }
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        match self {
            Self::Internal(km) => km.get_shutdown_scriptpubkey(),
            Self::External(es) => es.get_shutdown_scriptpubkey(),
        }
    }
}

impl OutputSpender for DynRlnSigner {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        locktime: Option<LockTime>,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Transaction, ()> {
        match self {
            Self::Internal(km) => km.spend_spendable_outputs(
                descriptors,
                outputs,
                change_destination_script,
                feerate_sat_per_1000_weight,
                locktime,
                secp_ctx,
            ),
            Self::External(es) => es.spend_spendable_outputs(
                descriptors,
                outputs,
                change_destination_script,
                feerate_sat_per_1000_weight,
                locktime,
                secp_ctx,
            ),
        }
    }
}

impl RlnKeysInterface for DynRlnSigner {
    fn sign_spendable_outputs_psbt(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        psbt: Psbt,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Psbt, ()> {
        match self {
            Self::Internal(km) => km.sign_spendable_outputs_psbt(descriptors, psbt, secp_ctx),
            Self::External(es) => es.sign_spendable_outputs_psbt(descriptors, psbt, secp_ctx),
        }
    }

    fn sign_rgb_psbt(
        &self,
        descriptors: Vec<String>,
        psbt: String,
    ) -> Result<String, RlnSignerError> {
        match self {
            Self::Internal(km) => km.sign_rgb_psbt(descriptors, psbt),
            Self::External(es) => es.sign_rgb_psbt(descriptors, psbt),
        }
    }
}
