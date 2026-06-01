use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use amplify::s;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::disk::FilesystemLogger;
use crate::ldk::{GossipVerifier, NetworkGraph, P2PGossipSync, RapidGossipSync};

pub(crate) const RGS_SYNC_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub(crate) const RGS_SNAPSHOT_MAX_SIZE: usize = 15 * 1024 * 1024;
pub(crate) const RGS_CONNECT_TIMEOUT_SECS: u64 = 5;
pub(crate) const RGS_SYNC_TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum GossipSourceConfig {
    #[default]
    #[serde(rename = "p2p")]
    P2PNetwork,
    #[serde(rename = "rgs")]
    RapidGossipSync { server_url: String },
}

pub(crate) enum GossipSource {
    P2PNetwork {
        gossip_sync: Arc<P2PGossipSync>,
    },
    RapidGossipSync {
        gossip_sync: Arc<RapidGossipSync>,
        server_url: String,
        latest_sync_timestamp: AtomicU32,
    },
}

impl GossipSource {
    pub(crate) fn new_p2p(
        network_graph: Arc<NetworkGraph>,
        utxo_lookup: Option<Arc<GossipVerifier>>,
        logger: Arc<FilesystemLogger>,
    ) -> Self {
        let gossip_sync = Arc::new(P2PGossipSync::new(network_graph, utxo_lookup, logger));
        Self::P2PNetwork { gossip_sync }
    }

    pub(crate) fn new_rgs(
        server_url: String,
        latest_sync_timestamp: u32,
        network_graph: Arc<NetworkGraph>,
        logger: Arc<FilesystemLogger>,
    ) -> Self {
        let gossip_sync = Arc::new(RapidGossipSync::new(network_graph, logger));
        Self::RapidGossipSync {
            gossip_sync,
            server_url,
            latest_sync_timestamp: AtomicU32::new(latest_sync_timestamp),
        }
    }

    pub(crate) fn is_rgs(&self) -> bool {
        matches!(self, Self::RapidGossipSync { .. })
    }

    pub(crate) fn as_gossip_sync(&self) -> crate::ldk::GossipSync {
        use lightning_background_processor::GossipSync as Lbp;
        match self {
            Self::RapidGossipSync { gossip_sync, .. } => Lbp::Rapid(Arc::clone(gossip_sync)),
            Self::P2PNetwork { gossip_sync } => Lbp::P2P(Arc::clone(gossip_sync)),
        }
    }

    pub(crate) async fn update_rgs_snapshot(&self) -> Result<u32, crate::error::APIError> {
        let (gossip_sync, server_url, latest_sync_timestamp) = match self {
            Self::P2PNetwork { .. } => return Ok(0),
            Self::RapidGossipSync {
                gossip_sync,
                server_url,
                latest_sync_timestamp,
                ..
            } => (gossip_sync, server_url, latest_sync_timestamp),
        };

        let ts = latest_sync_timestamp.load(Ordering::Acquire);
        let url = snapshot_url(server_url, ts)?;

        // Fail fast on unreachable servers but allow a 15 MiB body to land
        // on slow links — the two timeouts have different jobs.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(RGS_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(RGS_SYNC_TIMEOUT_SECS))
            .build()
            .map_err(|e| crate::error::APIError::GossipUpdateFailed(e.to_string()))?;

        let response = client.get(url).send().await.map_err(|e| {
            if e.is_timeout() {
                crate::error::APIError::GossipUpdateTimeout
            } else {
                crate::error::APIError::GossipUpdateFailed(e.to_string())
            }
        })?;

        if !response.status().is_success() {
            return Err(crate::error::APIError::GossipUpdateFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        // Refuse to buffer an oversized body. Check Content-Length first so a
        // hostile or buggy server can't OOM us with a single huge response,
        // then enforce the same cap per-chunk for responses without a
        // Content-Length (or with a truthful one that exceeds the cap).
        if let Some(advertised) = response.content_length() {
            if advertised > RGS_SNAPSHOT_MAX_SIZE as u64 {
                return Err(crate::error::APIError::GossipUpdateFailed(format!(
                    "snapshot too large: {advertised} bytes"
                )));
            }
        }

        let cap_hint = response
            .content_length()
            .map(|n| (n as usize).min(RGS_SNAPSHOT_MAX_SIZE))
            .unwrap_or(0);
        let mut buf: Vec<u8> = Vec::with_capacity(cap_hint);
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            if e.is_timeout() {
                crate::error::APIError::GossipUpdateTimeout
            } else {
                crate::error::APIError::GossipUpdateFailed(e.to_string())
            }
        })? {
            if buf.len() + chunk.len() > RGS_SNAPSHOT_MAX_SIZE {
                return Err(crate::error::APIError::GossipUpdateFailed(format!(
                    "snapshot too large: {} bytes",
                    buf.len() + chunk.len()
                )));
            }
            buf.extend_from_slice(&chunk);
        }

        let new_timestamp = gossip_sync
            .update_network_graph(&buf)
            .map_err(|e| crate::error::APIError::GossipUpdateFailed(format!("{e:?}")))?;

        latest_sync_timestamp.store(new_timestamp, Ordering::Release);
        tracing::info!("RGS snapshot applied, new timestamp: {new_timestamp}");
        Ok(new_timestamp)
    }
}

fn snapshot_url(server_url: &str, ts: u32) -> Result<reqwest::Url, crate::error::APIError> {
    let mut url = reqwest::Url::parse(server_url).map_err(|e| {
        crate::error::APIError::GossipUpdateFailed(format!("invalid RGS server URL: {e}"))
    })?;
    url.path_segments_mut()
        .map_err(|_| {
            crate::error::APIError::GossipUpdateFailed(s!("RGS server URL cannot be a base"))
        })?
        .pop_if_empty()
        .push(&ts.to_string());
    Ok(url)
}

pub(crate) async fn run_rgs_sync_loop(
    gossip_source: Arc<GossipSource>,
    shutdown: Arc<Notify>,
    interval_duration: Duration,
) {
    let mut interval = tokio::time::interval(interval_duration);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => return,
            _ = interval.tick() => {}
        }
        let started = std::time::Instant::now();
        match gossip_source.update_rgs_snapshot().await {
            Ok(_) => tracing::info!("RGS sync finished in {}ms", started.elapsed().as_millis()),
            Err(e) => tracing::error!("RGS sync failed: {e:?}"),
        }
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn p2p_config_roundtrip() {
        let cfg = GossipSourceConfig::P2PNetwork;
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, r#"{"type":"p2p"}"#);
        let back: GossipSourceConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, GossipSourceConfig::P2PNetwork));
    }

    #[test]
    fn rgs_config_roundtrip() {
        let cfg = GossipSourceConfig::RapidGossipSync {
            server_url: "https://example.invalid/snapshot".into(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(
            json,
            r#"{"type":"rgs","server_url":"https://example.invalid/snapshot"}"#
        );
        let back: GossipSourceConfig = serde_json::from_str(&json).unwrap();
        match back {
            GossipSourceConfig::RapidGossipSync { server_url } => {
                assert_eq!(server_url, "https://example.invalid/snapshot");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn default_is_p2p() {
        assert!(matches!(
            GossipSourceConfig::default(),
            GossipSourceConfig::P2PNetwork
        ));
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn appends_timestamp_segment() {
        let url = snapshot_url("https://example.com/snapshot", 12345).unwrap();
        assert_eq!(url.as_str(), "https://example.com/snapshot/12345");
    }

    #[test]
    fn collapses_trailing_slash() {
        let url = snapshot_url("https://example.com/snapshot/", 12345).unwrap();
        assert_eq!(url.as_str(), "https://example.com/snapshot/12345");
    }

    #[test]
    fn preserves_query_string() {
        let url = snapshot_url("https://example.com/snapshot?key=foo", 42).unwrap();
        assert_eq!(url.as_str(), "https://example.com/snapshot/42?key=foo");
    }

    #[test]
    fn rejects_invalid_url() {
        let err = snapshot_url("not-a-url", 0).unwrap_err();
        assert!(matches!(err, crate::error::APIError::GossipUpdateFailed(_)));
    }

    #[test]
    fn rejects_cannot_be_a_base() {
        let err = snapshot_url("data:hello", 0).unwrap_err();
        assert!(matches!(err, crate::error::APIError::GossipUpdateFailed(_)));
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use crate::disk::FilesystemLogger;
    use crate::ldk::NetworkGraph;
    use bitcoin::Network;
    use std::sync::Arc;

    fn test_logger() -> Arc<FilesystemLogger> {
        Arc::new(FilesystemLogger::new(tempfile::tempdir().unwrap().keep()))
    }

    fn test_graph(logger: Arc<FilesystemLogger>) -> Arc<NetworkGraph> {
        Arc::new(NetworkGraph::new(Network::Regtest, logger))
    }

    #[tokio::test]
    async fn update_rgs_snapshot_returns_zero_for_p2p() {
        let logger = test_logger();
        let graph = test_graph(Arc::clone(&logger));
        let source = GossipSource::new_p2p(graph, None, logger);
        assert_eq!(source.update_rgs_snapshot().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn update_rgs_snapshot_fails_on_http_500() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let logger = test_logger();
        let graph = test_graph(Arc::clone(&logger));
        let source = GossipSource::new_rgs(format!("http://{addr}/snapshot"), 0, graph, logger);
        match source.update_rgs_snapshot().await {
            Err(crate::error::APIError::GossipUpdateFailed(_)) => {}
            other => panic!("expected GossipUpdateFailed, got {other:?}"),
        }
    }

    // The cap exists to bound memory. A server that advertises an oversized
    // body must be rejected before the body is read.
    #[tokio::test]
    async fn update_rgs_snapshot_rejects_oversized_content_length_before_reading_body() {
        use std::time::Instant;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body_len = (RGS_SNAPSHOT_MAX_SIZE * 10) as u64;
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        let logger = test_logger();
        let graph = test_graph(Arc::clone(&logger));
        let source = GossipSource::new_rgs(format!("http://{addr}/snapshot"), 0, graph, logger);

        let started = Instant::now();
        let result = source.update_rgs_snapshot().await;
        let elapsed = started.elapsed();
        server.abort();

        match result {
            Err(crate::error::APIError::GossipUpdateFailed(msg)) => {
                assert!(msg.contains("too large"), "expected size error, got {msg}");
            }
            other => panic!("expected GossipUpdateFailed(too large), got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "rejection took {elapsed:?} — body was likely buffered"
        );
    }

    // For servers that omit Content-Length, the cap must be enforced
    // chunk-by-chunk so we abort before the full body lands in memory.
    #[tokio::test]
    async fn update_rgs_snapshot_rejects_mid_stream_when_body_exceeds_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes_written = Arc::new(AtomicUsize::new(0));
        let bytes_written_clone = Arc::clone(&bytes_written);
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                if sock
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let chunk_size = 1024 * 1024usize;
                let payload = vec![0u8; chunk_size];
                for _ in 0..(RGS_SNAPSHOT_MAX_SIZE / chunk_size + 50) {
                    let header = format!("{chunk_size:x}\r\n");
                    if sock.write_all(header.as_bytes()).await.is_err() {
                        break;
                    }
                    if sock.write_all(&payload).await.is_err() {
                        break;
                    }
                    if sock.write_all(b"\r\n").await.is_err() {
                        break;
                    }
                    bytes_written_clone.fetch_add(chunk_size, Ordering::Relaxed);
                }
            }
        });

        let logger = test_logger();
        let graph = test_graph(Arc::clone(&logger));
        let source = GossipSource::new_rgs(format!("http://{addr}/snapshot"), 0, graph, logger);

        let result = source.update_rgs_snapshot().await;
        let _ = server.await;
        let total = bytes_written.load(Ordering::Relaxed);

        match result {
            Err(crate::error::APIError::GossipUpdateFailed(msg)) => {
                assert!(msg.contains("too large"), "expected size error, got {msg}");
            }
            other => panic!("expected GossipUpdateFailed, got {other:?}"),
        }
        // Server may write a few extra MB into kernel buffers after the client
        // hangs up — but it must not write the full payload.
        let cap_with_slack = RGS_SNAPSHOT_MAX_SIZE + 8 * 1024 * 1024;
        assert!(
            total <= cap_with_slack,
            "server wrote {total} bytes — client should have aborted near the {RGS_SNAPSHOT_MAX_SIZE}-byte cap"
        );
    }

    // Shutdown must interrupt the long inter-tick sleep, not wait for the
    // next interval (potentially up to an hour). notify_one stores a permit
    // so the signal works even if the loop is busy in update_rgs_snapshot.
    #[tokio::test]
    async fn run_rgs_sync_loop_exits_promptly_on_shutdown() {
        let logger = test_logger();
        let graph = test_graph(Arc::clone(&logger));
        let source = Arc::new(GossipSource::new_rgs(
            "http://127.0.0.1:1".into(),
            0,
            graph,
            logger,
        ));
        let shutdown = Arc::new(Notify::new());
        shutdown.notify_one();
        let handle = tokio::spawn(run_rgs_sync_loop(
            Arc::clone(&source),
            Arc::clone(&shutdown),
            Duration::from_secs(3600),
        ));

        match tokio::time::timeout(Duration::from_secs(2), handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("loop task failed: {e}"),
            Err(_) => panic!("loop did not exit within 2s after shutdown signal"),
        }
    }

    // A body under the cap must reach update_network_graph. We use a bogus
    // payload so we can confirm the cap path passed (the decode error is
    // not a "too large" error).
    #[tokio::test]
    async fn update_rgs_snapshot_accepts_body_under_cap() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body = b"not-a-valid-rgs-snapshot";
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = sock.write_all(body).await;
            }
        });

        let logger = test_logger();
        let graph = test_graph(Arc::clone(&logger));
        let source = GossipSource::new_rgs(format!("http://{addr}/snapshot"), 0, graph, logger);

        let result = source.update_rgs_snapshot().await;
        let _ = server.await;

        match result {
            Err(crate::error::APIError::GossipUpdateFailed(msg)) => {
                assert!(
                    !msg.contains("too large"),
                    "small body wrongly rejected by cap: {msg}"
                );
            }
            Ok(_) => panic!("update_network_graph should fail on bogus payload"),
            other => panic!("expected GossipUpdateFailed(decode), got {other:?}"),
        }
    }
}
