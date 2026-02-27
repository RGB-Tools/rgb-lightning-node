use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use chrono::Utc;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringDecayParameters};
use lightning::util::hash_tables::new_hash_map;
use lightning::util::logger::{Logger, Record};
use lightning::util::ser::{Readable, ReadableArgs, Writer};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::APIError;
use crate::ldk::{
    ChannelIdsMap, ClaimablePaymentStorage, InboundPaymentInfoStorage, InvoiceMetadataStorage,
    NetworkGraph, OutboundPaymentInfoStorage, OutputSpenderTxes, SwapMap,
};
use crate::utils::{parse_peer_info, LOGS_DIR};

pub(crate) const LDK_LOGS_FILE: &str = "logs.txt";

pub(crate) const INBOUND_PAYMENTS_FNAME: &str = "inbound_payments";
pub(crate) const OUTBOUND_PAYMENTS_FNAME: &str = "outbound_payments";
pub(crate) const INVOICE_METADATA_FNAME: &str = "invoice_metadata";
pub(crate) const CLAIMABLE_HTLCS_FNAME: &str = "claimable_htlcs";

pub(crate) const CHANNEL_PEER_DATA: &str = "channel_peer_data";

pub(crate) const OUTPUT_SPENDER_TXES: &str = "output_spender_txes";

pub(crate) const CHANNEL_IDS_FNAME: &str = "channel_ids";

pub(crate) const MAKER_SWAPS_FNAME: &str = "maker_swaps";
pub(crate) const TAKER_SWAPS_FNAME: &str = "taker_swaps";

pub(crate) struct FilesystemLogger {
    data_dir: PathBuf,
}

impl FilesystemLogger {
    pub(crate) fn new(data_dir: PathBuf) -> Self {
        let logs_path = data_dir.join(LOGS_DIR);
        fs::create_dir_all(logs_path.clone()).unwrap();
        Self {
            data_dir: logs_path,
        }
    }
}

impl Logger for FilesystemLogger {
    fn log(&self, record: Record) {
        let raw_log = record.args.to_string();
        let log = format!(
            "{} {:<5} [{}:{}] {}\n",
            // Note that a "real" lightning node almost certainly does *not* want subsecond
            // precision for message-receipt information as it makes log entries a target for
            // deanonymization attacks. For testing, however, its quite useful.
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level.to_string(),
            record.module_path,
            record.line,
            raw_log
        );
        let logs_file_path = self.data_dir.join(LDK_LOGS_FILE);
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs_file_path)
            .unwrap()
            .write_all(log.as_bytes())
            .unwrap();
    }
}

pub(crate) fn persist_channel_peer(
    path: &Path,
    pubkey: &PublicKey,
    address: &SocketAddr,
) -> Result<(), APIError> {
    let pubkey = pubkey.to_string();
    let peer_info = if path.exists() {
        let mut updated_peer_info = fs::read_to_string(path)?
            .lines()
            .filter(|&line| !line.trim().starts_with(&pubkey))
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join("\n");
        updated_peer_info += format!(
            "{}{pubkey}@{address}",
            if updated_peer_info.is_empty() {
                ""
            } else {
                "\n"
            }
        )
        .as_str();
        updated_peer_info
    } else {
        format!("{pubkey}@{address}")
    };
    let mut tmp_path = path.to_path_buf();
    tmp_path.set_extension("ptmp");
    fs::write(&tmp_path, peer_info.to_string().as_bytes())?;
    fs::rename(tmp_path, path)?;
    tracing::info!("persisted peer (pubkey: {pubkey}, addr: {address})");
    Ok(())
}

pub(crate) fn delete_channel_peer(path: &Path, pubkey: String) -> Result<(), APIError> {
    if path.exists() {
        let updated_peer_info = fs::read_to_string(path)?
            .lines()
            .filter(|&line| !line.trim().starts_with(&pubkey))
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join("\n");
        let mut tmp_path = path.to_path_buf();
        tmp_path.set_extension("dtmp");
        fs::write(&tmp_path, updated_peer_info.to_string().as_bytes())?;
        fs::rename(tmp_path, path)?;
    }
    Ok(())
}

pub(crate) fn read_channel_peer_data(
    path: &Path,
) -> Result<HashMap<PublicKey, SocketAddr>, APIError> {
    let mut peer_data = HashMap::new();
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        match parse_peer_info(line.unwrap()) {
            Ok((pubkey, socket_addr)) => {
                peer_data.insert(pubkey, socket_addr.expect("saved info with address"));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(peer_data)
}

pub(crate) fn read_network(
    path: &Path,
    network: Network,
    logger: Arc<FilesystemLogger>,
) -> NetworkGraph {
    if let Ok(file) = File::open(path) {
        if let Ok(graph) = NetworkGraph::read(&mut BufReader::new(file), logger.clone()) {
            return graph;
        }
    }
    NetworkGraph::new(network, logger)
}

pub(crate) fn read_inbound_payment_info(path: &Path) -> InboundPaymentInfoStorage {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = InboundPaymentInfoStorage::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    InboundPaymentInfoStorage {
        payments: new_hash_map(),
    }
}

pub(crate) fn read_outbound_payment_info(path: &Path) -> OutboundPaymentInfoStorage {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = OutboundPaymentInfoStorage::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    OutboundPaymentInfoStorage {
        payments: new_hash_map(),
    }
}

pub(crate) fn read_invoice_metadata(path: &Path) -> InvoiceMetadataStorage {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = InvoiceMetadataStorage::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    InvoiceMetadataStorage {
        invoices: new_hash_map(),
    }
}

pub(crate) fn read_claimable_htlcs(path: &Path) -> ClaimablePaymentStorage {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = ClaimablePaymentStorage::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    ClaimablePaymentStorage {
        payments: new_hash_map(),
    }
}

pub(crate) fn read_output_spender_txes(path: &Path) -> OutputSpenderTxes {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = OutputSpenderTxes::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    new_hash_map()
}

pub(crate) fn read_swaps_info(path: &Path) -> SwapMap {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = SwapMap::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    SwapMap {
        swaps: new_hash_map(),
    }
}

pub(crate) fn read_scorer(
    path: &Path,
    graph: Arc<NetworkGraph>,
    logger: Arc<FilesystemLogger>,
) -> ProbabilisticScorer<Arc<NetworkGraph>, Arc<FilesystemLogger>> {
    let params = ProbabilisticScoringDecayParameters::default();
    if let Ok(file) = File::open(path) {
        let args = (params, Arc::clone(&graph), Arc::clone(&logger));
        if let Ok(scorer) = ProbabilisticScorer::read(&mut BufReader::new(file), args) {
            return scorer;
        }
    }
    ProbabilisticScorer::new(params, graph, logger)
}

pub(crate) fn read_channel_ids_info(path: &Path) -> ChannelIdsMap {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = ChannelIdsMap::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    ChannelIdsMap {
        channel_ids: new_hash_map(),
    }
}
