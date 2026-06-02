use std::sync::Arc;

use bitcoin::blockdata::transaction::Transaction;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};

use crate::bitcoind::BitcoindClient;
use crate::indexer::{ElectrumIndexerClient, EsploraIndexerClient};

pub(crate) enum ChainBackend {
    Bitcoind(Arc<BitcoindClient>),
    Esplora(Arc<EsploraIndexerClient>),
    Electrum(Arc<ElectrumIndexerClient>),
}

impl FeeEstimator for ChainBackend {
    fn get_est_sat_per_1000_weight(&self, target: ConfirmationTarget) -> u32 {
        match self {
            ChainBackend::Bitcoind(c) => c.get_est_sat_per_1000_weight(target),
            ChainBackend::Esplora(c) => c.get_est_sat_per_1000_weight(target),
            ChainBackend::Electrum(c) => c.get_est_sat_per_1000_weight(target),
        }
    }
}

impl BroadcasterInterface for ChainBackend {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        match self {
            ChainBackend::Bitcoind(c) => c.broadcast_transactions(txs),
            ChainBackend::Esplora(c) => c.broadcast_transactions(txs),
            ChainBackend::Electrum(c) => c.broadcast_transactions(txs),
        }
    }
}
