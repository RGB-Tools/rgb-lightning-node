use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Network;
use ldk_node::entropy::NodeEntropy;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::payment::PaymentStatus;
use ldk_node::Builder;
use std::io::{self, BufRead, Write};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

const CHANNEL_CAPACITY_SAT: u64 = 600_000;
const PAYMENT_TIMEOUT: Duration = Duration::from_secs(45);

fn respond(message: impl std::fmt::Display) {
    println!("{message}");
    io::stdout().flush().unwrap();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let storage_dir = args.next().unwrap();
    let listening_address = SocketAddress::from_str(&args.next().unwrap()).unwrap();

    let mut builder = Builder::new();
    builder
        .set_network(Network::Regtest)
        .set_storage_dir_path(storage_dir.clone())
        .set_chain_source_bitcoind_rpc(
            "127.0.0.1".to_string(),
            18443,
            "user".to_string(),
            "password".to_string(),
        );
    builder
        .set_listening_addresses(vec![listening_address])
        .unwrap();
    builder
        .set_node_alias("stock-ldk-test".to_string())
        .unwrap();
    let entropy = NodeEntropy::from_seed_path(format!("{storage_dir}/keys_seed")).unwrap();
    let node = builder.build(entropy).unwrap();
    node.start().unwrap();

    let address = node.onchain_payment().new_address().unwrap();
    respond(format!("NODE {} {address}", node.node_id()));

    let description = Bolt11InvoiceDescription::Direct(
        Description::new("RLN interoperability test".to_string()).unwrap(),
    );
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut parts = line.split_whitespace();
        match parts.next().unwrap() {
            "open" => {
                let peer_id = PublicKey::from_str(parts.next().unwrap()).unwrap();
                let peer_address = SocketAddress::from_str(parts.next().unwrap()).unwrap();
                node.open_channel(peer_id, peer_address, CHANNEL_CAPACITY_SAT, None, None)
                    .unwrap();
                respond("OPENING");
            }
            "open-announced" => {
                let peer_id = PublicKey::from_str(parts.next().unwrap()).unwrap();
                let peer_address = SocketAddress::from_str(parts.next().unwrap()).unwrap();
                node.open_announced_channel(
                    peer_id,
                    peer_address,
                    CHANNEL_CAPACITY_SAT,
                    None,
                    None,
                )
                .unwrap();
                respond("OPENING");
            }
            "channels" => {
                let channels = node.list_channels();
                let ready = channels.iter().filter(|c| c.is_channel_ready).count();
                respond(format!("CHANNELS {} {ready}", channels.len()));
            }
            "balances" => {
                let channel = node
                    .list_channels()
                    .into_iter()
                    .find(|channel| channel.is_channel_ready)
                    .expect("no ready channel");
                respond(format!(
                    "BALANCES {} {}",
                    channel.outbound_capacity_msat, channel.inbound_capacity_msat
                ));
            }
            "invoice" => {
                let amount_msat = parts.next().unwrap().parse().unwrap();
                let invoice = node
                    .bolt11_payment()
                    .receive(amount_msat, &description, 900)
                    .unwrap();
                respond(format!("INVOICE {invoice}"));
            }
            "pay" => {
                let invoice = Bolt11Invoice::from_str(parts.next().unwrap()).unwrap();
                let payment_id = node.bolt11_payment().send(&invoice, None).unwrap();
                let started = Instant::now();
                let status = loop {
                    let status = node.payment(&payment_id).unwrap().status;
                    if status != PaymentStatus::Pending {
                        break status;
                    }
                    assert!(
                        started.elapsed() < PAYMENT_TIMEOUT,
                        "payment did not complete"
                    );
                    thread::sleep(Duration::from_millis(100));
                };
                assert_eq!(status, PaymentStatus::Succeeded, "payment failed");
                respond("PAID");
            }
            "onchain" => {
                let balances = node.list_balances();
                respond(format!(
                    "ONCHAIN {} {}",
                    balances.spendable_onchain_balance_sats, balances.total_onchain_balance_sats
                ));
            }
            "stop" => break,
            command => panic!("unknown command: {command}"),
        }
    }
    node.stop().unwrap();
}
