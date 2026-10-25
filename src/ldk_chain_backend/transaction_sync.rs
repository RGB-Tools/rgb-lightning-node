use bitcoin::blockdata::transaction::Transaction;
use bitcoin::constants::ChainHash;
use bitcoin::{Script, TxOut, Txid};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::{BestBlock, Confirm, Filter, WatchedOutput};
use lightning::log_warn;
use lightning::routing::utxo::{UtxoFuture, UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::util::logger::Logger;
use rgb_lib::wallet::rust_only::IndexerProtocol as RgbLibIndexerProtocol;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "electrum")]
use {
    bitcoin::consensus::encode,
    electrum_client::{Client as ElectrumClient, ElectrumApi, Param},
    lightning_transaction_sync::ElectrumSyncClient,
    std::str::FromStr,
};

#[cfg(feature = "esplora")]
use {
    esplora_client::blocking::BlockingClient as EsploraBlockingClient,
    esplora_client::Builder as EsploraBuilder, lightning_transaction_sync::EsploraSyncClient,
    std::collections::BTreeMap,
};

use crate::disk::FilesystemLogger;
use crate::ldk::PeerGossipSync;

use super::{default_fee_buckets, fee_from_bucket, store_fee_estimates, MIN_FEERATE};

type Confirmable = Arc<dyn Confirm + Send + Sync>;

enum IndexerBackend {
    #[cfg(feature = "electrum")]
    Electrum(Arc<ElectrumClient>),
    #[cfg(feature = "esplora")]
    Esplora(Arc<EsploraBlockingClient>),
}

pub(crate) struct IndexerClient {
    backend: IndexerBackend,
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    handle: tokio::runtime::Handle,
    logger: Arc<FilesystemLogger>,
}

pub(crate) struct IndexerGossipVerifier {
    client: Arc<IndexerClient>,
    gossiper: Arc<PeerGossipSync>,
    peer_manager_wake: Arc<dyn Fn() + Send + Sync>,
}

pub(crate) enum IndexerSyncClient {
    #[cfg(feature = "electrum")]
    Electrum(ElectrumSyncClient<Arc<FilesystemLogger>>),
    #[cfg(feature = "esplora")]
    Esplora(EsploraSyncClient<Arc<FilesystemLogger>>),
}

// `check_indexer_url` only ever returns a protocol whose feature is enabled, so this is just a
// safety net for the single-protocol builds
#[cfg(not(all(feature = "electrum", feature = "esplora")))]
fn unsupported_protocol(protocol: RgbLibIndexerProtocol) -> io::Error {
    io::Error::other(format!("{protocol} support is not enabled"))
}

impl IndexerClient {
    pub(crate) fn new(
        server_url: String,
        protocol: RgbLibIndexerProtocol,
        handle: tokio::runtime::Handle,
        logger: Arc<FilesystemLogger>,
        fee_refresh_interval_secs: u64,
    ) -> io::Result<Self> {
        let fees = Arc::new(default_fee_buckets());
        let backend = match protocol {
            #[cfg(feature = "electrum")]
            RgbLibIndexerProtocol::Electrum => {
                let client = Arc::new(ElectrumClient::new(&server_url).map_err(|e| {
                    io::Error::other(format!("failed to connect to electrum server: {e}"))
                })?);
                client.server_features().map_err(|e| {
                    io::Error::other(format!("failed to query electrum server features: {e}"))
                })?;
                poll_electrum_fee_estimates(
                    fees.clone(),
                    client.clone(),
                    logger.clone(),
                    handle.clone(),
                    fee_refresh_interval_secs,
                );
                IndexerBackend::Electrum(client)
            }
            #[cfg(feature = "esplora")]
            RgbLibIndexerProtocol::Esplora => {
                let client = Arc::new(EsploraBuilder::new(&server_url).build_blocking());
                client.get_tip_hash().map_err(|e| {
                    io::Error::other(format!("failed to connect to esplora server: {e}"))
                })?;
                poll_esplora_fee_estimates(
                    fees.clone(),
                    client.clone(),
                    logger.clone(),
                    handle.clone(),
                    fee_refresh_interval_secs,
                );
                IndexerBackend::Esplora(client)
            }
            #[cfg(not(all(feature = "electrum", feature = "esplora")))]
            protocol => return Err(unsupported_protocol(protocol)),
        };

        Ok(Self {
            backend,
            fees,
            handle,
            logger,
        })
    }

    pub(crate) fn get_best_block(&self) -> io::Result<BestBlock> {
        match &self.backend {
            #[cfg(feature = "electrum")]
            IndexerBackend::Electrum(client) => {
                let tip = client.block_headers_subscribe().map_err(|e| {
                    io::Error::other(format!("failed to fetch electrum tip header: {e}"))
                })?;
                Ok(BestBlock::new(tip.header.block_hash(), tip.height as u32))
            }
            #[cfg(feature = "esplora")]
            IndexerBackend::Esplora(client) => {
                let tip_hash = client.get_tip_hash().map_err(|e| {
                    io::Error::other(format!("failed to fetch esplora tip hash: {e}"))
                })?;
                let tip_height = client
                    .get_block_status(&tip_hash)
                    .map_err(|e| {
                        io::Error::other(format!("failed to fetch esplora tip status: {e}"))
                    })?
                    .height
                    .ok_or_else(|| io::Error::other("esplora tip block has no height"))?;
                Ok(BestBlock::new(tip_hash, tip_height))
            }
        }
    }

    fn tip_height(&self) -> io::Result<u32> {
        Ok(self.get_best_block()?.height)
    }

    // whether `txid`'s output at `vout` has not been spent yet. electrum has no way to query an
    // outpoint directly, so its unspent set is queried by script and filtered down to the outpoint
    fn is_output_unspent(&self, txid: &Txid, vout: usize, txout: &TxOut) -> io::Result<bool> {
        match &self.backend {
            #[cfg(feature = "electrum")]
            IndexerBackend::Electrum(client) => {
                let unspents = client
                    .script_list_unspent(&txout.script_pubkey)
                    .map_err(|e| {
                        io::Error::other(format!("failed to fetch electrum unspents: {e}"))
                    })?;
                Ok(unspents
                    .iter()
                    .any(|unspent| unspent.tx_hash == *txid && unspent.tx_pos == vout))
            }
            #[cfg(feature = "esplora")]
            IndexerBackend::Esplora(client) => {
                // esplora queries the outpoint directly, so the output itself is not needed
                let _ = txout;
                let status = client.get_output_status(txid, vout as u64).map_err(|e| {
                    io::Error::other(format!("failed to fetch esplora output status: {e}"))
                })?;
                // an unknown output is treated as spent, so an announcement is never resolved
                // against an output the indexer cannot vouch for
                Ok(status.is_some_and(|status| !status.spent))
            }
        }
    }
}

impl IndexerGossipVerifier {
    pub(crate) fn new(
        client: Arc<IndexerClient>,
        gossiper: Arc<PeerGossipSync>,
        peer_manager_wake: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            client,
            gossiper,
            peer_manager_wake,
        }
    }
}

impl UtxoLookup for IndexerGossipVerifier {
    fn get_utxo(&self, _chain_hash: &ChainHash, short_channel_id: u64) -> UtxoResult {
        let result = UtxoFuture::new();
        let future = result.clone();
        let client = self.client.clone();
        let gossiper = self.gossiper.clone();
        let peer_manager_wake = self.peer_manager_wake.clone();
        self.client.handle.spawn(async move {
            let lookup = tokio::task::spawn_blocking(move || {
                let height = (short_channel_id >> 40) as u32;
                let tx_index = ((short_channel_id >> 16) & 0x00ff_ffff) as usize;
                let vout = (short_channel_id & 0xffff) as usize;

                // like the block-sync gossip verifier, require the funding output to be buried by
                // at least six confirmations (with one block of headroom) before resolving it
                let tip_height = client
                    .tip_height()
                    .map_err(|_| UtxoLookupError::UnknownTx)?;
                if height + 5 > tip_height {
                    return Err(UtxoLookupError::UnknownTx);
                }

                let funding = match &client.backend {
                    #[cfg(feature = "electrum")]
                    IndexerBackend::Electrum(c) => {
                        match electrum_txid_from_pos(c, height as usize, tx_index)
                            .and_then(|txid| Ok((txid, c.transaction_get(&txid)?)))
                        {
                            Ok((txid, tx)) => {
                                tx.output.get(vout).cloned().map(|txout| (txid, txout))
                            }
                            Err(_) => None,
                        }
                    }
                    #[cfg(feature = "esplora")]
                    IndexerBackend::Esplora(c) => c
                        .get_block_hash(height)
                        .and_then(|block_hash| c.get_txid_at_block_index(&block_hash, tx_index))
                        .and_then(|txid| match txid {
                            Some(txid) => c.get_tx_no_opt(&txid).map(|tx| Some((txid, tx))),
                            None => Ok(None),
                        })
                        .ok()
                        .flatten()
                        .and_then(|(txid, tx)| {
                            tx.output.get(vout).cloned().map(|txout| (txid, txout))
                        }),
                };

                let (txid, txout) = funding.ok_or(UtxoLookupError::UnknownTx)?;

                // like the block-sync gossip verifier, only resolve the announcement if the
                // funding output is still unspent, so closed channels don't enter the graph
                if !client
                    .is_output_unspent(&txid, vout, &txout)
                    .map_err(|_| UtxoLookupError::UnknownTx)?
                {
                    return Err(UtxoLookupError::UnknownTx);
                }

                Ok(txout)
            })
            .await
            .unwrap_or(Err(UtxoLookupError::UnknownTx));
            future.resolve(gossiper.network_graph(), &*gossiper, lookup);
            peer_manager_wake();
        });
        UtxoResult::Async(result)
    }
}

#[cfg(feature = "electrum")]
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

impl IndexerSyncClient {
    pub(crate) fn new(
        server_url: String,
        protocol: RgbLibIndexerProtocol,
        logger: Arc<FilesystemLogger>,
    ) -> io::Result<Self> {
        match protocol {
            #[cfg(feature = "electrum")]
            RgbLibIndexerProtocol::Electrum => {
                let client = ElectrumSyncClient::new(server_url, logger).map_err(|e| {
                    io::Error::other(format!("failed to initialize electrum sync client: {e}"))
                })?;
                Ok(Self::Electrum(client))
            }
            #[cfg(feature = "esplora")]
            RgbLibIndexerProtocol::Esplora => {
                Ok(Self::Esplora(EsploraSyncClient::new(server_url, logger)))
            }
            #[cfg(not(all(feature = "electrum", feature = "esplora")))]
            protocol => Err(unsupported_protocol(protocol)),
        }
    }

    pub(crate) fn sync(
        &self,
        confirmables: Vec<Confirmable>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            #[cfg(feature = "electrum")]
            Self::Electrum(client) => client
                .sync(confirmables)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) }),
            #[cfg(feature = "esplora")]
            Self::Esplora(client) => client
                .sync(confirmables)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) }),
        }
    }
}

impl Filter for IndexerSyncClient {
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        match self {
            #[cfg(feature = "electrum")]
            Self::Electrum(client) => client.register_tx(txid, script_pubkey),
            #[cfg(feature = "esplora")]
            Self::Esplora(client) => client.register_tx(txid, script_pubkey),
        }
    }

    fn register_output(&self, output: WatchedOutput) {
        match self {
            #[cfg(feature = "electrum")]
            Self::Electrum(client) => client.register_output(output),
            #[cfg(feature = "esplora")]
            Self::Esplora(client) => client.register_output(output),
        }
    }
}

impl FeeEstimator for IndexerClient {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        fee_from_bucket(&self.fees, confirmation_target)
    }
}

impl BroadcasterInterface for IndexerClient {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        match &self.backend {
            #[cfg(feature = "electrum")]
            IndexerBackend::Electrum(client) => {
                let txs = txs
                    .iter()
                    .map(|tx| encode::serialize(*tx))
                    .collect::<Vec<_>>();
                let client = client.clone();
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
                        Ok(Err(e)) => {
                            log_warn!(
                                logger,
                                "Warning, failed to broadcast transaction(s) via electrum: {}",
                                e
                            );
                        }
                        Err(e) => {
                            log_warn!(
                                logger,
                                "Warning, failed to spawn electrum broadcaster task: {}",
                                e
                            );
                        }
                    }
                });
            }
            #[cfg(feature = "esplora")]
            IndexerBackend::Esplora(client) => {
                let txs = txs.iter().map(|tx| (*tx).clone()).collect::<Vec<_>>();
                let client = client.clone();
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
                        Ok(Err(e)) => {
                            log_warn!(
                                logger,
                                "Warning, failed to broadcast transaction(s) via esplora: {}",
                                e
                            );
                        }
                        Err(e) => {
                            log_warn!(
                                logger,
                                "Warning, failed to spawn esplora broadcaster task: {}",
                                e
                            );
                        }
                    }
                });
            }
        }
    }
}

#[cfg(feature = "electrum")]
fn poll_electrum_fee_estimates(
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    client: Arc<ElectrumClient>,
    logger: Arc<FilesystemLogger>,
    handle: tokio::runtime::Handle,
    fee_refresh_interval_secs: u64,
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
                Ok(Ok((background, normal, high_prio, very_high_prio))) => {
                    let background_estimate = fee_rate_from_btc_per_kb(background, MIN_FEERATE);
                    let normal_estimate = fee_rate_from_btc_per_kb(normal, 2000);
                    let high_prio_estimate = fee_rate_from_btc_per_kb(high_prio, 5000);
                    let very_high_prio_estimate = fee_rate_from_btc_per_kb(very_high_prio, 50000);

                    store_fee_estimates(
                        &fees,
                        background_estimate,
                        normal_estimate,
                        high_prio_estimate,
                        very_high_prio_estimate,
                        MIN_FEERATE,
                    );
                }
                Ok(Err(e)) => {
                    log_warn!(logger, "Error getting fee estimate from electrum: {}", e);
                }
                Err(e) => {
                    log_warn!(logger, "Error polling electrum fee estimates: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(fee_refresh_interval_secs)).await;
        }
    });
}

#[cfg(feature = "esplora")]
fn poll_esplora_fee_estimates(
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    client: Arc<EsploraBlockingClient>,
    logger: Arc<FilesystemLogger>,
    handle: tokio::runtime::Handle,
    fee_refresh_interval_secs: u64,
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
                    let estimate_map =
                        BTreeMap::from_iter(estimate_map.iter().map(|(k, v)| (*k, *v)));
                    let background_estimate =
                        estimate_fee_rate_sat_per_kw(&estimate_map, 144, MIN_FEERATE);
                    let normal_estimate = estimate_fee_rate_sat_per_kw(&estimate_map, 18, 2000);
                    let high_prio_estimate = estimate_fee_rate_sat_per_kw(&estimate_map, 6, 5000);
                    let very_high_prio_estimate =
                        estimate_fee_rate_sat_per_kw(&estimate_map, 2, 50000);

                    store_fee_estimates(
                        &fees,
                        background_estimate,
                        normal_estimate,
                        high_prio_estimate,
                        very_high_prio_estimate,
                        MIN_FEERATE,
                    );
                }
                Ok(Err(e)) => {
                    log_warn!(logger, "Error getting fee estimate from esplora: {}", e)
                }
                Err(e) => log_warn!(logger, "Error polling esplora fee estimates: {}", e),
            }

            tokio::time::sleep(Duration::from_secs(fee_refresh_interval_secs)).await;
        }
    });
}

#[cfg(feature = "esplora")]
fn estimate_fee_rate_sat_per_kw(
    estimate_map: &BTreeMap<u16, f64>,
    blocks: u16,
    default: u32,
) -> u32 {
    let Some(sat_per_vb) = interpolate_fee_rate(estimate_map, blocks) else {
        return default;
    };
    std::cmp::max((sat_per_vb * 250.0).round() as u32, MIN_FEERATE)
}

#[cfg(feature = "esplora")]
fn interpolate_fee_rate(estimate_map: &BTreeMap<u16, f64>, blocks: u16) -> Option<f64> {
    if blocks == 0 || estimate_map.is_empty() {
        return None;
    }

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

#[cfg(feature = "electrum")]
// electrum reports a negative feerate when it has no estimate available
fn fee_rate_from_btc_per_kb(feerate_btc_per_kb: f64, default: u32) -> u32 {
    if !feerate_btc_per_kb.is_finite() || feerate_btc_per_kb.is_sign_negative() {
        return default;
    }
    std::cmp::max(
        (feerate_btc_per_kb * 100_000_000.0 / 4.0).round() as u32,
        MIN_FEERATE,
    )
}
