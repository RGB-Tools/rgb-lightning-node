use super::*;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[derive(Debug, PartialEq)]
struct ChannelBalances {
    outbound_msat: u64,
    inbound_msat: u64,
}

/// A stock ldk-node fixture, driven over its stdin/stdout with one line per command.
///
/// It is a separate Cargo crate so RLN's Cargo patches cannot replace the stock LDK dependencies
/// it is built against. It only reports state, so that mining stays under the test's control.
struct StockLdkNode {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    node_id: String,
}

impl StockLdkNode {
    fn start(test_dir: &str, listening_port: u16) -> (Self, String) {
        if Path::new(test_dir).exists() {
            std::fs::remove_dir_all(test_dir).unwrap();
        }
        std::fs::create_dir_all(test_dir).unwrap();

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/test/interoperability/ldk-node/Cargo.toml");
        let target_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("target/interoperability/ldk-node");
        // the fixture is built and run outside of the instrumentation of the test run, so that its
        // dependencies don't end up in the coverage report
        let status = Command::new(env!("CARGO"))
            .args(["build", "--manifest-path"])
            .arg(&manifest)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("LLVM_PROFILE_FILE")
            .status()
            .expect("failed to build stock ldk-node fixture");
        assert!(status.success(), "failed to build stock ldk-node fixture");

        let mut child = Command::new(target_dir.join("debug/stock-ldk-node"))
            .args([test_dir, &format!("127.0.0.1:{listening_port}")])
            .env_remove("LLVM_PROFILE_FILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start stock ldk-node fixture");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        assert_eq!(parts.next(), Some("NODE"));
        let node_id = parts.next().unwrap().to_string();
        let address = parts.next().unwrap().to_string();
        (
            Self {
                child,
                stdin,
                stdout,
                node_id,
            },
            address,
        )
    }

    fn command(&mut self, command: &str) -> String {
        writeln!(self.stdin, "{command}").unwrap();
        self.stdin.flush().unwrap();
        let mut response = String::new();
        self.stdout.read_line(&mut response).unwrap();
        assert!(
            !response.is_empty(),
            "stock ldk-node exited during {command}"
        );
        response.trim().to_string()
    }

    fn open_channel(&mut self, peer_pubkey: &str, peer_port: u16) {
        let command = format!("open {peer_pubkey} 127.0.0.1:{peer_port}");
        assert_eq!(self.command(&command), "OPENING");
    }

    fn open_announced_channel(&mut self, peer_pubkey: &str, peer_port: u16) {
        let command = format!("open-announced {peer_pubkey} 127.0.0.1:{peer_port}");
        assert_eq!(self.command(&command), "OPENING");
    }

    /// Number of channels the stock node has, and how many of them are ready
    fn channels(&mut self) -> (usize, usize) {
        let response = self.command("channels");
        let mut parts = response.split_whitespace();
        assert_eq!(parts.next(), Some("CHANNELS"));
        (
            parts.next().unwrap().parse().unwrap(),
            parts.next().unwrap().parse().unwrap(),
        )
    }

    fn balances(&mut self) -> ChannelBalances {
        let response = self.command("balances");
        let mut parts = response.split_whitespace();
        assert_eq!(parts.next(), Some("BALANCES"));
        ChannelBalances {
            outbound_msat: parts.next().unwrap().parse().unwrap(),
            inbound_msat: parts.next().unwrap().parse().unwrap(),
        }
    }

    fn invoice(&mut self, amount_msat: u64) -> String {
        self.command(&format!("invoice {amount_msat}"))
            .strip_prefix("INVOICE ")
            .unwrap()
            .to_string()
    }

    fn pay(&mut self, invoice: &str) {
        assert_eq!(self.command(&format!("pay {invoice}")), "PAID");
    }

    fn onchain_spendable(&mut self) -> u64 {
        let response = self.command("onchain");
        let mut parts = response.split_whitespace();
        assert_eq!(parts.next(), Some("ONCHAIN"));
        parts.next().unwrap().parse().unwrap()
    }
}

impl Drop for StockLdkNode {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = writeln!(self.stdin, "stop");
            let _ = self.stdin.flush();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_stock_funds(stock: &mut StockLdkNode) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if stock.onchain_spendable() > 0 {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 60.0 {
            panic!("stock LDK wallet is taking too long to be funded");
        }
        mine(false);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn wait_for_stock_channel_ready(stock: &mut StockLdkNode) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if stock.channels().1 > 0 {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("stock LDK channel is taking too long to be ready");
        }
        mine(false);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn wait_for_stock_channel_closed(stock: &mut StockLdkNode, initial_spendable: u64) {
    let t_0 = OffsetDateTime::now_utc();
    loop {
        if stock.channels().0 == 0 && stock.onchain_spendable() > initial_spendable {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 90.0 {
            panic!("stock LDK is taking too long to settle the cooperative close");
        }
        mine(false);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

mod ldk;
