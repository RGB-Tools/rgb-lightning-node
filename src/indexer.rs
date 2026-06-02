use std::collections::{BTreeMap, HashMap};
use std::io;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::constants::ChainHash;
use bitcoin::{Network, TxOut, Txid};
use electrum_client::{Client as ElectrumClient, ElectrumApi, Param};
use esplora_client::blocking::BlockingClient as EsploraBlockingClient;
use esplora_client::Builder as EsploraBuilder;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::log_warn;
use lightning::routing::utxo::{UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::util::logger::Logger;

use crate::disk::FilesystemLogger;
#[cfg(test)]
use crate::fee_mock::mock_fee;

pub(crate) const MIN_FEERATE: u32 = 253;

pub(crate) fn default_fee_buckets() -> HashMap<ConfirmationTarget, AtomicU32> {
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

pub(crate) struct EsploraIndexerClient {
    pub(crate) client: Arc<EsploraBlockingClient>,
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    network: Network,
    pub(crate) handle: tokio::runtime::Handle,
    logger: Arc<FilesystemLogger>,
}

impl EsploraIndexerClient {
    pub(crate) fn new(
        server_url: String,
        network: Network,
        handle: tokio::runtime::Handle,
        logger: Arc<FilesystemLogger>,
    ) -> io::Result<Self> {
        // Bounded socket timeout so a hung endpoint doesn't block runtime shutdown.
        let client = Arc::new(
            EsploraBuilder::new(&server_url)
                .timeout(10)
                .build_blocking(),
        );
        client
            .get_tip_hash()
            .map_err(|e| io::Error::other(format!("failed to connect to esplora server: {e}")))?;
        client
            .get_height()
            .map_err(|e| io::Error::other(format!("failed to query esplora tip height: {e}")))?;
        let fees = Arc::new(default_fee_buckets());
        poll_esplora_fee_estimates(fees.clone(), client.clone(), logger.clone(), handle.clone());
        Ok(Self {
            client,
            fees,
            network,
            handle,
            logger,
        })
    }
}

fn poll_esplora_fee_estimates(
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    client: Arc<EsploraBlockingClient>,
    logger: Arc<FilesystemLogger>,
    handle: tokio::runtime::Handle,
) {
    handle.spawn(async move {
        loop {
            let res = tokio::task::spawn_blocking({
                let client = client.clone();
                move || client.get_fee_estimates()
            })
            .await;

            match res {
                Ok(Ok(estimate_map)) => {
                    let background_estimate =
                        estimate_fee_rate_sat_per_kw(&estimate_map, 144, MIN_FEERATE);
                    let normal_estimate = estimate_fee_rate_sat_per_kw(&estimate_map, 18, 2000);
                    let high_prio_estimate = estimate_fee_rate_sat_per_kw(&estimate_map, 6, 5000);
                    let very_high_prio_estimate =
                        estimate_fee_rate_sat_per_kw(&estimate_map, 2, 50000);

                    fees.get(&ConfirmationTarget::MaximumFeeEstimate)
                        .unwrap()
                        .store(very_high_prio_estimate, Ordering::Release);
                    fees.get(&ConfirmationTarget::UrgentOnChainSweep)
                        .unwrap()
                        .store(high_prio_estimate, Ordering::Release);
                    fees.get(&ConfirmationTarget::MinAllowedAnchorChannelRemoteFee)
                        .unwrap()
                        .store(MIN_FEERATE, Ordering::Release);
                    fees.get(&ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee)
                        .unwrap()
                        .store(background_estimate.saturating_sub(250), Ordering::Release);
                    fees.get(&ConfirmationTarget::AnchorChannelFee)
                        .unwrap()
                        .store(background_estimate, Ordering::Release);
                    fees.get(&ConfirmationTarget::NonAnchorChannelFee)
                        .unwrap()
                        .store(normal_estimate, Ordering::Release);
                    fees.get(&ConfirmationTarget::ChannelCloseMinimum)
                        .unwrap()
                        .store(background_estimate, Ordering::Release);
                    fees.get(&ConfirmationTarget::OutputSpendingFee)
                        .unwrap()
                        .store(background_estimate, Ordering::Release);
                }
                Ok(Err(e)) => {
                    log_warn!(logger, "Error getting fee estimate from esplora: {}", e)
                }
                Err(e) => log_warn!(logger, "Error polling esplora fee estimates: {}", e),
            }

            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

pub(crate) fn estimate_fee_rate_sat_per_kw(
    fee_estimates: &HashMap<u16, f64>,
    blocks: u16,
    default: u32,
) -> u32 {
    let Some(sat_per_vb) = interpolate_fee_rate(fee_estimates, blocks) else {
        return default;
    };
    std::cmp::max((sat_per_vb * 250.0).round() as u32, MIN_FEERATE)
}

pub(crate) fn interpolate_fee_rate(fee_estimates: &HashMap<u16, f64>, blocks: u16) -> Option<f64> {
    if blocks == 0 || fee_estimates.is_empty() {
        return None;
    }

    let estimate_map = BTreeMap::from_iter(fee_estimates.iter().map(|(k, v)| (*k, *v)));
    if let Some(estimate) = estimate_map.get(&blocks) {
        return Some(*estimate);
    }

    let lower_key = estimate_map.range(..blocks).next_back().map(|(k, _)| *k);
    let upper_key = estimate_map.range(blocks..).next().map(|(k, _)| *k);

    match (lower_key, upper_key) {
        (Some(x1), Some(x2)) if x1 != x2 => {
            let y1 = estimate_map[&x1];
            let y2 = estimate_map[&x2];
            Some(y1 + (blocks as f64 - x1 as f64) / (x2 as f64 - x1 as f64) * (y2 - y1))
        }
        (Some(x), _) | (_, Some(x)) => estimate_map.get(&x).copied(),
        _ => None,
    }
}

impl FeeEstimator for EsploraIndexerClient {
    fn get_est_sat_per_1000_weight(&self, target: ConfirmationTarget) -> u32 {
        let fee = self.fees.get(&target).unwrap().load(Ordering::Acquire);
        #[cfg(test)]
        let fee = mock_fee(fee);
        fee
    }
}

impl BroadcasterInterface for EsploraIndexerClient {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let txs = txs.iter().map(|tx| (*tx).clone()).collect::<Vec<_>>();
        let client = self.client.clone();
        let logger = self.logger.clone();
        self.handle.spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut last_error = None;
                for tx in txs {
                    if let Err(e) = client.broadcast(&tx) {
                        last_error = Some(e.to_string());
                    }
                }
                last_error.map_or(Ok(()), Err)
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => log_warn!(logger, "esplora broadcast failed: {}", e),
                Err(e) => log_warn!(logger, "esplora broadcast task spawn failed: {}", e),
            }
        });
    }
}

impl EsploraIndexerClient {
    pub(crate) fn lookup_utxo(
        &self,
        chain_hash: ChainHash,
        short_channel_id: u64,
    ) -> Result<TxOut, UtxoLookupError> {
        if chain_hash != ChainHash::using_genesis_block(self.network) {
            return Err(UtxoLookupError::UnknownChain);
        }
        let height = (short_channel_id >> 40) as u32;
        let tx_index = ((short_channel_id >> 16) & 0x00ff_ffff) as usize;
        let vout = (short_channel_id & 0xffff) as usize;
        let txout = self
            .client
            .get_block_hash(height)
            .and_then(|block_hash| self.client.get_txid_at_block_index(&block_hash, tx_index))
            .and_then(|txid| match txid {
                Some(txid) => self.client.get_tx_no_opt(&txid).map(Some),
                None => Ok(None),
            })
            .ok()
            .flatten()
            .and_then(|tx| tx.output.get(vout).cloned());
        txout.ok_or(UtxoLookupError::UnknownTx)
    }
}

impl UtxoLookup for EsploraIndexerClient {
    fn get_utxo(&self, chain_hash: &ChainHash, short_channel_id: u64) -> UtxoResult {
        UtxoResult::Sync(self.lookup_utxo(*chain_hash, short_channel_id))
    }
}

pub(crate) struct ElectrumIndexerClient {
    pub(crate) client: Arc<ElectrumClient>,
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    network: Network,
    pub(crate) handle: tokio::runtime::Handle,
    logger: Arc<FilesystemLogger>,
}

impl ElectrumIndexerClient {
    pub(crate) fn new(
        server_url: String,
        network: Network,
        handle: tokio::runtime::Handle,
        logger: Arc<FilesystemLogger>,
    ) -> io::Result<Self> {
        let client =
            Arc::new(ElectrumClient::new(&server_url).map_err(|e| {
                io::Error::other(format!("failed to connect to electrum server: {e}"))
            })?);
        client.server_features().map_err(|e| {
            io::Error::other(format!("failed to query electrum server features: {e}"))
        })?;
        let fees = Arc::new(default_fee_buckets());
        poll_electrum_fee_estimates(fees.clone(), client.clone(), logger.clone(), handle.clone());
        Ok(Self {
            client,
            fees,
            network,
            handle,
            logger,
        })
    }

    pub(crate) fn lookup_utxo(
        &self,
        chain_hash: ChainHash,
        short_channel_id: u64,
    ) -> Result<TxOut, UtxoLookupError> {
        if chain_hash != ChainHash::using_genesis_block(self.network) {
            return Err(UtxoLookupError::UnknownChain);
        }
        let height = (short_channel_id >> 40) as usize;
        let tx_index = ((short_channel_id >> 16) & 0x00ff_ffff) as usize;
        let vout = (short_channel_id & 0xffff) as usize;
        let txout = electrum_txid_from_pos(&self.client, height, tx_index)
            .and_then(|txid| self.client.transaction_get(&txid))
            .ok()
            .and_then(|tx| tx.output.get(vout).cloned());
        txout.ok_or(UtxoLookupError::UnknownTx)
    }
}

impl FeeEstimator for ElectrumIndexerClient {
    fn get_est_sat_per_1000_weight(&self, target: ConfirmationTarget) -> u32 {
        let fee = self.fees.get(&target).unwrap().load(Ordering::Acquire);
        #[cfg(test)]
        let fee = mock_fee(fee);
        fee
    }
}

impl BroadcasterInterface for ElectrumIndexerClient {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let txs = txs
            .iter()
            .map(|tx| encode::serialize(*tx))
            .collect::<Vec<_>>();
        let client = self.client.clone();
        let logger = self.logger.clone();
        self.handle.spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut last_error = None;
                for tx in txs {
                    if let Err(e) = client.transaction_broadcast_raw(&tx) {
                        last_error = Some(e.to_string());
                    }
                }
                last_error.map_or(Ok(()), Err)
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => log_warn!(logger, "electrum broadcast failed: {}", e),
                Err(e) => log_warn!(logger, "electrum broadcast task spawn failed: {}", e),
            }
        });
    }
}

impl UtxoLookup for ElectrumIndexerClient {
    fn get_utxo(&self, chain_hash: &ChainHash, short_channel_id: u64) -> UtxoResult {
        UtxoResult::Sync(self.lookup_utxo(*chain_hash, short_channel_id))
    }
}

fn electrum_txid_from_pos(
    client: &ElectrumClient,
    height: usize,
    tx_pos: usize,
) -> Result<Txid, electrum_client::Error> {
    let value = client.raw_call(
        "blockchain.transaction.id_from_pos",
        [
            Param::Usize(height),
            Param::Usize(tx_pos),
            Param::Bool(true),
        ],
    )?;
    let txid = value
        .as_str()
        .or_else(|| value.get("tx_hash").and_then(serde_json::Value::as_str))
        .or_else(|| value.get("txid").and_then(serde_json::Value::as_str))
        .or_else(|| value.get("tx_id").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .ok_or_else(|| electrum_client::Error::InvalidResponse(value.clone()))?;
    Txid::from_str(&txid).map_err(|_| electrum_client::Error::InvalidResponse(value))
}

fn poll_electrum_fee_estimates(
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    client: Arc<ElectrumClient>,
    logger: Arc<FilesystemLogger>,
    handle: tokio::runtime::Handle,
) {
    handle.spawn(async move {
        loop {
            let res = tokio::task::spawn_blocking({
                let client = client.clone();
                move || {
                    Ok::<_, electrum_client::Error>((
                        client.estimate_fee(144)?,
                        client.estimate_fee(18)?,
                        client.estimate_fee(6)?,
                        client.estimate_fee(2)?,
                    ))
                }
            })
            .await;
            match res {
                Ok(Ok((bg, normal, high, very_high))) => {
                    let bg_e = fee_rate_from_btc_per_kb(bg, MIN_FEERATE).unwrap_or(MIN_FEERATE);
                    let normal_e = fee_rate_from_btc_per_kb(normal, 2000).unwrap_or(2000);
                    let high_e = fee_rate_from_btc_per_kb(high, 5000).unwrap_or(5000);
                    let vhigh_e = fee_rate_from_btc_per_kb(very_high, 50000).unwrap_or(50000);
                    fees.get(&ConfirmationTarget::MaximumFeeEstimate)
                        .unwrap()
                        .store(vhigh_e, Ordering::Release);
                    fees.get(&ConfirmationTarget::UrgentOnChainSweep)
                        .unwrap()
                        .store(high_e, Ordering::Release);
                    fees.get(&ConfirmationTarget::MinAllowedAnchorChannelRemoteFee)
                        .unwrap()
                        .store(MIN_FEERATE, Ordering::Release);
                    fees.get(&ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee)
                        .unwrap()
                        .store(bg_e.saturating_sub(250), Ordering::Release);
                    fees.get(&ConfirmationTarget::AnchorChannelFee)
                        .unwrap()
                        .store(bg_e, Ordering::Release);
                    fees.get(&ConfirmationTarget::NonAnchorChannelFee)
                        .unwrap()
                        .store(normal_e, Ordering::Release);
                    fees.get(&ConfirmationTarget::ChannelCloseMinimum)
                        .unwrap()
                        .store(bg_e, Ordering::Release);
                    fees.get(&ConfirmationTarget::OutputSpendingFee)
                        .unwrap()
                        .store(bg_e, Ordering::Release);
                }
                Ok(Err(e)) => log_warn!(logger, "Error getting fee estimate from electrum: {}", e),
                Err(e) => log_warn!(logger, "Error polling electrum fee estimates: {}", e),
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

fn fee_rate_from_btc_per_kb(feerate_btc_per_kb: f64, default: u32) -> Option<u32> {
    if !feerate_btc_per_kb.is_finite() || feerate_btc_per_kb.is_sign_negative() {
        return Some(default);
    }
    Some(std::cmp::max(
        (feerate_btc_per_kb * 100_000_000.0 / 4.0).round() as u32,
        MIN_FEERATE,
    ))
}
