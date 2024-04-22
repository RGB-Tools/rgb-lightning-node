use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use chrono::Utc;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringDecayParameters};
use lightning::util::logger::{Logger, Record};
use lightning::util::ser::{Readable, ReadableArgs, Writer};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::error::APIError;
use crate::ldk::{InboundPaymentInfoStorage, NetworkGraph, OutboundPaymentInfoStorage, TradeMap};
use crate::utils::{parse_peer_info, LOGS_DIR};

pub(crate) const LDK_LOGS_FILE: &str = "logs.txt";

pub(crate) const INBOUND_PAYMENTS_FNAME: &str = "inbound_payments";
pub(crate) const OUTBOUND_PAYMENTS_FNAME: &str = "outbound_payments";

pub(crate) const MAKER_TRADES_FNAME: &str = "maker_trades";
pub(crate) const TAKER_TRADES_FNAME: &str = "taker_trades";

pub(crate) const PENDING_SPENDABLE_OUTPUT_DIR: &str = "pending_spendable_outputs";

pub(crate) struct FilesystemLogger {
    data_dir: String,
}
impl FilesystemLogger {
    pub(crate) fn new(data_dir: String) -> Self {
        let logs_path = format!("{}/{}", data_dir, LOGS_DIR);
        fs::create_dir_all(logs_path.clone()).unwrap();
        Self {
            data_dir: logs_path,
        }
    }
}
impl Logger for FilesystemLogger {
    fn log(&self, record: &Record) {
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
        let logs_file_path = format!("{}/{LDK_LOGS_FILE}", self.data_dir.clone());
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs_file_path)
            .unwrap()
            .write_all(log.as_bytes())
            .unwrap();
    }
}
pub(crate) fn persist_channel_peer(path: &Path, peer_info: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(format!("{}\n", peer_info).as_bytes())
}

pub(crate) fn read_channel_peer_data(
    path: &Path,
) -> Result<HashMap<PublicKey, SocketAddr>, APIError> {
    let mut peer_data = HashMap::new();
    if !Path::new(&path).exists() {
        return Ok(HashMap::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        match parse_peer_info(line.unwrap()) {
            Ok((pubkey, socket_addr)) => {
                peer_data.insert(pubkey, socket_addr);
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
        payments: HashMap::new(),
    }
}

pub(crate) fn read_outbound_payment_info(path: &Path) -> OutboundPaymentInfoStorage {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = OutboundPaymentInfoStorage::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    OutboundPaymentInfoStorage {
        payments: HashMap::new(),
    }
}

pub(crate) fn read_trades_info(path: &Path) -> TradeMap {
    if let Ok(file) = File::open(path) {
        if let Ok(info) = TradeMap::read(&mut BufReader::new(file)) {
            return info;
        }
    }
    TradeMap {
        trades: HashMap::new(),
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
