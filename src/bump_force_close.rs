//! Persisted status for anchor CPFP fee bumps of local force-close commitments.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::hex::DisplayHex;
use bitcoin::Transaction;
use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::ClaimId;
use lightning::ln::types::ChannelId;
use lightning::util::persist::KVStoreSync;
use serde::{Deserialize, Serialize};

use crate::ldk_chain_backend::{BroadcastFailure, DynBroadcaster};
use crate::utils::get_current_timestamp;

pub(crate) const PRIMARY_NAMESPACE: &str = "channel_close_bumps";

/// Observable outcome of an anchor CPFP attempt.
///
/// LDK never reports confirmation for a closed channel; `Confirmed` comes from the backend
/// confirmation poll. `Superseded` stays unobservable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ChannelCloseBumpStatus {
    /// The close event was received and the handler is still running.
    Pending,
    /// The commitment already pays the target feerate; no anchor child is needed.
    NotRequired,
    /// The commitment and its anchor child were handed to the broadcaster. This does not prove
    /// that the chain backend accepted them; see `retryable_failure`.
    Broadcast,
    /// No anchor child was broadcast. Usually no confirmed vanilla sponsor UTXO, but any handler
    /// failure that produced no broadcast looks the same; the node log has the real error.
    InsufficientFunds,
    /// The bump wallet failed to sign the anchor child.
    SignerFailure,
    /// No acceptable package reached the mempool: either nothing was broadcast while a child was
    /// required, or the chain backend rejected the last attempt. LDK retries the event.
    RetryableFailure,
    /// The force-close commitment is confirmed on-chain (set by the backend confirmation poll).
    Confirmed,
}

impl ChannelCloseBumpStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::NotRequired => "not_required",
            Self::Broadcast => "broadcast",
            Self::InsufficientFunds => "insufficient_funds",
            Self::SignerFailure => "signer_failure",
            Self::RetryableFailure => "retryable_failure",
            Self::Confirmed => "confirmed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChannelCloseBumpRecord {
    pub(crate) channel_id: String,
    pub(crate) claim_id: String,
    pub(crate) commitment_txid: String,
    pub(crate) child_txid: Option<String>,
    /// LDK's package target, in sat per 1000 weight units.
    pub(crate) target_fee_rate_sat_per_kw: u32,
    pub(crate) status: ChannelCloseBumpStatus,
    pub(crate) updated_at: u64,
    pub(crate) message: Option<String>,
}

impl ChannelCloseBumpRecord {
    pub(crate) fn new(
        channel_id: ChannelId,
        claim_id: ClaimId,
        commitment_txid: bitcoin::Txid,
        target_fee_rate_sat_per_kw: u32,
    ) -> Self {
        Self {
            channel_id: channel_id.to_string(),
            claim_id: claim_id.0.as_hex().to_string(),
            commitment_txid: commitment_txid.to_string(),
            child_txid: None,
            target_fee_rate_sat_per_kw,
            status: ChannelCloseBumpStatus::Pending,
            updated_at: get_current_timestamp(),
            message: None,
        }
    }

    pub(crate) fn persist(&self, store: &impl KVStoreSync) -> Result<(), String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        store
            .write(PRIMARY_NAMESPACE, "", &self.channel_id, bytes)
            .map_err(|e| {
                format!(
                    "cannot persist {PRIMARY_NAMESPACE} record {}: {e}",
                    self.channel_id
                )
            })
    }

    pub(crate) fn read(store: &impl KVStoreSync, channel_id: &str) -> Result<Option<Self>, String> {
        match store.read(PRIMARY_NAMESPACE, "", channel_id) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("invalid {PRIMARY_NAMESPACE} record {channel_id}: {e}")),
            Err(e) if e.kind() == bitcoin::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!(
                "cannot read {PRIMARY_NAMESPACE} record {channel_id}: {e}"
            )),
        }
    }

    /// Marks the record terminal once the backend reports the commitment confirmed.
    #[cfg(any(test, feature = "block-sync"))]
    pub(crate) fn mark_confirmed(&mut self) {
        self.status = ChannelCloseBumpStatus::Confirmed;
        self.message = None;
        self.updated_at = get_current_timestamp();
    }
}

/// Records the transaction ids the bump handler asked to broadcast, without changing the
/// broadcaster behaviour.
pub(crate) struct BumpBroadcastRecorder {
    inner: Arc<DynBroadcaster>,
    last: Mutex<Vec<bitcoin::Txid>>,
}

impl BumpBroadcastRecorder {
    pub(crate) fn new(inner: Arc<DynBroadcaster>) -> Self {
        Self {
            inner,
            last: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn reset(&self) {
        self.last.lock().unwrap().clear();
    }

    pub(crate) fn take(&self) -> Vec<bitcoin::Txid> {
        std::mem::take(&mut *self.last.lock().unwrap())
    }
}

impl BroadcasterInterface for BumpBroadcastRecorder {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        self.last
            .lock()
            .unwrap()
            .extend(txs.iter().map(|tx| tx.compute_txid()));
        self.inner.broadcast_transactions(txs);
    }
}

/// Shared bump instrumentation: package recorder, the signer-failure flag set by
/// [`crate::rgb::RgbBumpWalletSource`], and the backend rejection reported by the chain client.
pub(crate) struct BumpTracker {
    recorder: Arc<BumpBroadcastRecorder>,
    signer_failed: Arc<AtomicBool>,
    broadcast_failure: BroadcastFailure,
    previous_rejection: Mutex<Option<String>>,
}

impl BumpTracker {
    pub(crate) fn new(inner: Arc<DynBroadcaster>, broadcast_failure: BroadcastFailure) -> Self {
        Self {
            recorder: Arc::new(BumpBroadcastRecorder::new(inner)),
            signer_failed: Arc::new(AtomicBool::new(false)),
            broadcast_failure,
            previous_rejection: Mutex::new(None),
        }
    }

    pub(crate) fn recorder(&self) -> Arc<BumpBroadcastRecorder> {
        Arc::clone(&self.recorder)
    }

    pub(crate) fn signer_failed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.signer_failed)
    }

    pub(crate) fn begin(&self) {
        self.signer_failed.store(false, Ordering::SeqCst);
        self.recorder.reset();
        // The backend reports its verdict in a spawned task, so this attempt cannot read its own
        // result. Carry the rejection recorded since the last attempt into the next classification.
        // shortcut: a rejection is reported one retry late (~30s) and is not matched to a txid,
        // upgrade when LDK reports broadcaster results.
        let rejection = self.broadcast_failure.lock().unwrap().take();
        *self.previous_rejection.lock().unwrap() = rejection;
    }

    pub(crate) fn signer_failed(&self) -> bool {
        self.signer_failed.load(Ordering::SeqCst)
    }

    pub(crate) fn broadcast(&self) -> Vec<bitcoin::Txid> {
        self.recorder.take()
    }

    /// Fills in the outcome fields from what the handler did, keeping the record as `Pending`
    /// until the caller has finished.
    pub(crate) fn apply_outcome(
        &self,
        record: &mut ChannelCloseBumpRecord,
        commitment_txid: bitcoin::Txid,
        commitment_feerate_sat_per_kw: u64,
        broadcast: &[bitcoin::Txid],
    ) {
        let previous_rejection = self.previous_rejection.lock().unwrap().take();
        let (status, child_txid, message) = classify(
            commitment_feerate_sat_per_kw,
            record.target_fee_rate_sat_per_kw,
            broadcast,
            commitment_txid,
            self.signer_failed(),
            previous_rejection.as_deref(),
        );
        record.status = status;
        record.child_txid = child_txid.map(|txid| txid.to_string());
        record.message = message;
        record.updated_at = get_current_timestamp();
    }
}

pub(crate) fn commitment_feerate_sat_per_kw(commitment_tx: &Transaction, fee_sat: u64) -> u64 {
    fee_sat.saturating_mul(1000) / commitment_tx.weight().to_wu().max(1)
}

/// Maps what the bump handler did into an observable status. `broadcast` holds the txids handed
/// to the broadcaster during this attempt; `previous_rejection` carries an earlier rejection.
fn classify(
    commitment_feerate_sat_per_kw: u64,
    target_feerate_sat_per_kw: u32,
    broadcast: &[bitcoin::Txid],
    commitment_txid: bitcoin::Txid,
    signer_failed: bool,
    previous_rejection: Option<&str>,
) -> (
    ChannelCloseBumpStatus,
    Option<bitcoin::Txid>,
    Option<String>,
) {
    if commitment_feerate_sat_per_kw >= u64::from(target_feerate_sat_per_kw) {
        return (ChannelCloseBumpStatus::NotRequired, None, None);
    }
    if let Some(child) = broadcast.iter().find(|txid| **txid != commitment_txid) {
        if let Some(rejection) = previous_rejection {
            return (
                ChannelCloseBumpStatus::RetryableFailure,
                Some(*child),
                Some(format!("previous broadcast was rejected: {rejection}")),
            );
        }
        return (ChannelCloseBumpStatus::Broadcast, Some(*child), None);
    }
    if broadcast.contains(&commitment_txid) {
        return (
            ChannelCloseBumpStatus::RetryableFailure,
            None,
            Some("commitment broadcast without the required anchor child".to_string()),
        );
    }
    if signer_failed {
        return (
            ChannelCloseBumpStatus::SignerFailure,
            None,
            Some("bump wallet failed to sign the anchor child".to_string()),
        );
    }
    (
        ChannelCloseBumpStatus::InsufficientFunds,
        None,
        Some(
            "no anchor child broadcast: no confirmed vanilla sponsor UTXO or another wallet failure; check the node log"
                .to_string(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

    use super::*;
    use lightning_persister::fs_store::FilesystemStore;

    fn tx(txid_seed: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([txid_seed; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    struct NoopBroadcaster;

    impl BroadcasterInterface for NoopBroadcaster {
        fn broadcast_transactions(&self, _txs: &[&Transaction]) {}
    }

    #[test]
    fn record_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rln-bump-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = FilesystemStore::new(dir.clone());
        let channel_id = ChannelId([7; 32]);
        let record =
            ChannelCloseBumpRecord::new(channel_id, ClaimId([9; 32]), tx(1).compute_txid(), 5000);

        assert!(
            ChannelCloseBumpRecord::read(&store, &channel_id.to_string())
                .unwrap()
                .is_none()
        );
        record.persist(&store).unwrap();

        let read = ChannelCloseBumpRecord::read(&store, &channel_id.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(read, record);
        assert_eq!(read.status, ChannelCloseBumpStatus::Pending);
        assert_eq!(read.claim_id, [9u8; 32].as_hex().to_string());

        let mut confirmed = read;
        confirmed.mark_confirmed();
        assert_eq!(confirmed.status.as_str(), "confirmed");
        assert_eq!(confirmed.message, None);
        confirmed.persist(&store).unwrap();
        let confirmed_read = ChannelCloseBumpRecord::read(&store, &channel_id.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(confirmed_read, confirmed);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recorder_captures_and_delegates() {
        let recorder = BumpBroadcastRecorder::new(Arc::new(NoopBroadcaster));
        let first = tx(1);
        let second = tx(2);
        recorder.broadcast_transactions(&[&first]);
        recorder.broadcast_transactions(&[&second]);
        assert_eq!(
            recorder.take(),
            vec![first.compute_txid(), second.compute_txid()]
        );
        assert!(recorder.take().is_empty());
    }

    #[test]
    fn classify_observable_outcomes() {
        let commitment = tx(1).compute_txid();
        let child = tx(2).compute_txid();

        assert_eq!(
            classify(253, 253, &[commitment], commitment, false, None),
            (ChannelCloseBumpStatus::NotRequired, None, None)
        );
        assert_eq!(
            classify(253, 5000, &[commitment, child], commitment, false, None),
            (ChannelCloseBumpStatus::Broadcast, Some(child), None)
        );
        let (status, txid, message) = classify(
            253,
            5000,
            &[commitment, child],
            commitment,
            false,
            Some("mempool-script-verify-flag-failed"),
        );
        assert_eq!(status, ChannelCloseBumpStatus::RetryableFailure);
        assert_eq!(txid, Some(child));
        assert!(message
            .unwrap()
            .contains("mempool-script-verify-flag-failed"));
        assert_eq!(
            classify(253, 5000, &[commitment], commitment, false, None).0,
            ChannelCloseBumpStatus::RetryableFailure
        );
        assert_eq!(
            classify(253, 5000, &[], commitment, true, None).0,
            ChannelCloseBumpStatus::SignerFailure
        );
        assert_eq!(
            classify(253, 5000, &[], commitment, false, None).0,
            ChannelCloseBumpStatus::InsufficientFunds
        );
    }
}
