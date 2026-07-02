#[cfg(feature = "block-sync")]
pub(crate) mod block_sync;
#[cfg(feature = "transaction-sync")]
pub(crate) mod transaction_sync;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use lightning::chain::chaininterface::ConfirmationTarget;
#[cfg(feature = "transaction-sync")]
use lightning::chain::Confirm;
use lightning::chain::{BestBlock, Filter};

// the chain backends are used as trait objects so a single set of LDK type aliases works
// regardless of the selected sync mode
pub(crate) type DynFeeEstimator = dyn lightning::chain::chaininterface::FeeEstimator + Send + Sync;
pub(crate) type DynBroadcaster =
    dyn lightning::chain::chaininterface::BroadcasterInterface + Send + Sync;

pub(crate) const MIN_FEERATE: u32 = 253;

pub(crate) enum ChainBackend {
    #[cfg(feature = "block-sync")]
    BlockSync {
        client: Arc<block_sync::BitcoindClient>,
        polled_chain_tip: lightning_block_sync::poll::ValidatedBlockHeader,
    },
    #[cfg(feature = "transaction-sync")]
    TransactionSync {
        client: Arc<transaction_sync::IndexerClient>,
        tx_sync: Arc<transaction_sync::IndexerSyncClient>,
    },
}

pub(crate) struct ChainSetup {
    pub(crate) backend: ChainBackend,
    pub(crate) fee_estimator: Arc<DynFeeEstimator>,
    pub(crate) broadcaster: Arc<DynBroadcaster>,
    pub(crate) chain_filter: Option<Arc<dyn Filter + Send + Sync>>,
    pub(crate) initial_best_block: BestBlock,
}

#[cfg(feature = "transaction-sync")]
pub(crate) async fn sync_chain_data(
    tx_sync: Arc<transaction_sync::IndexerSyncClient>,
    confirmables: Vec<Arc<dyn Confirm + Send + Sync>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::task::spawn_blocking(move || tx_sync.sync(confirmables))
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
}

fn default_fee_buckets() -> HashMap<ConfirmationTarget, AtomicU32> {
    let mut fees = HashMap::new();
    fees.insert(
        ConfirmationTarget::MaximumFeeEstimate,
        AtomicU32::new(50000),
    );
    fees.insert(ConfirmationTarget::UrgentOnChainSweep, AtomicU32::new(5000));
    fees.insert(
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
        AtomicU32::new(MIN_FEERATE),
    );
    fees.insert(
        ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
        AtomicU32::new(MIN_FEERATE),
    );
    fees.insert(
        ConfirmationTarget::AnchorChannelFee,
        AtomicU32::new(MIN_FEERATE),
    );
    fees.insert(
        ConfirmationTarget::NonAnchorChannelFee,
        AtomicU32::new(2000),
    );
    fees.insert(
        ConfirmationTarget::ChannelCloseMinimum,
        AtomicU32::new(MIN_FEERATE),
    );
    fees.insert(
        ConfirmationTarget::OutputSpendingFee,
        AtomicU32::new(MIN_FEERATE),
    );
    fees
}

fn fee_from_bucket(
    fees: &HashMap<ConfirmationTarget, AtomicU32>,
    confirmation_target: ConfirmationTarget,
) -> u32 {
    let fee = fees
        .get(&confirmation_target)
        .unwrap()
        .load(Ordering::Acquire);
    #[cfg(all(test, feature = "electrum", feature = "block-sync"))]
    let fee = crate::test::mock_fee(fee);
    fee
}

// both backends map their four priority estimates onto the confirmation targets the same way,
// they differ only in the value used for `MinAllowedAnchorChannelRemoteFee`
fn store_fee_estimates(
    fees: &HashMap<ConfirmationTarget, AtomicU32>,
    background: u32,
    normal: u32,
    high_prio: u32,
    very_high_prio: u32,
    min_allowed_anchor: u32,
) {
    let set = |target: ConfirmationTarget, value: u32| {
        fees.get(&target).unwrap().store(value, Ordering::Release);
    };
    set(ConfirmationTarget::MaximumFeeEstimate, very_high_prio);
    set(ConfirmationTarget::UrgentOnChainSweep, high_prio);
    set(
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
        min_allowed_anchor,
    );
    set(
        ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
        background.saturating_sub(250),
    );
    set(ConfirmationTarget::AnchorChannelFee, background);
    set(ConfirmationTarget::NonAnchorChannelFee, normal);
    set(ConfirmationTarget::ChannelCloseMinimum, background);
    set(ConfirmationTarget::OutputSpendingFee, background);
}
