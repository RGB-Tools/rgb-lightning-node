use bitcoin::Network;
use chrono::Utc;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringDecayParameters};
use lightning::util::logger::{Logger, Record};
use lightning::util::ser::{ReadableArgs, Writer};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ldk::NetworkGraph;
use crate::utils::LOGS_DIR;

pub(crate) const LDK_LOGS_FILE: &str = "logs.txt";

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
