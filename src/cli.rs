use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::multipart;
use serde_json::Value;

type ApiResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(name = "rln-cli")]
#[command(about = "RGB Lightning Node CLI", long_about = None)]
#[command(version)]
struct Cli {
    /// Server URL
    #[arg(
        short,
        long,
        env = "RLN_SERVER_URL",
        default_value = "http://localhost:3001"
    )]
    server: String,

    /// Authentication bearer token
    #[arg(short, long, env = "RLN_AUTH_TOKEN")]
    token: Option<String>,

    /// Pretty print JSON output
    #[arg(short, long, default_value = "true")]
    pretty: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Node management operations
    Node {
        #[command(subcommand)]
        command: NodeCommands,
    },
    /// On-chain Bitcoin operations
    Onchain {
        #[command(subcommand)]
        command: OnchainCommands,
    },
    /// RGB asset operations
    Rgb {
        #[command(subcommand)]
        command: RgbCommands,
    },
    /// Lightning channel operations
    Channel {
        #[command(subcommand)]
        command: ChannelCommands,
    },
    /// Lightning peer operations
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },
    /// Lightning payment operations
    Payment {
        #[command(subcommand)]
        command: PaymentCommands,
    },
    /// Lightning invoice operations
    Invoice {
        #[command(subcommand)]
        command: InvoiceCommands,
    },
    /// Asset swap operations
    Swap {
        #[command(subcommand)]
        command: SwapCommands,
    },
}

#[derive(Subcommand)]
enum NodeCommands {
    /// Initialize a new node
    Init {
        /// Password for encrypting the mnemonic
        password: String,
    },
    /// Unlock the node
    Unlock {
        /// Password to decrypt the mnemonic
        password: String,
        /// Bitcoin RPC username
        #[arg(long)]
        bitcoind_rpc_username: String,
        /// Bitcoin RPC password
        #[arg(long)]
        bitcoind_rpc_password: String,
        /// Bitcoin RPC host
        #[arg(long)]
        bitcoind_rpc_host: String,
        /// Bitcoin RPC port
        #[arg(long)]
        bitcoind_rpc_port: u16,
        /// Indexer URL (electrum or esplora)
        #[arg(long)]
        indexer_url: Option<String>,
        /// RGB proxy endpoint
        #[arg(long)]
        proxy_endpoint: Option<String>,
        /// Announce addresses (comma-separated)
        #[arg(long, value_delimiter = ',')]
        announce_addresses: Vec<String>,
        /// Announce alias
        #[arg(long)]
        announce_alias: Option<String>,
    },
    /// Lock the node
    Lock,
    /// Get node information
    Info,
    /// Get network information
    NetworkInfo,
    /// Backup the node
    Backup {
        /// Path for the backup file
        backup_path: String,
        /// Password for encrypting the backup
        password: String,
    },
    /// Restore the node from backup
    Restore {
        /// Path to the backup file
        backup_path: String,
        /// Password to decrypt the backup
        password: String,
    },
    /// Change password
    ChangePassword {
        /// Old password
        old_password: String,
        /// New password
        new_password: String,
    },
    /// Check indexer URL
    CheckIndexer {
        /// Indexer URL to check
        indexer_url: String,
    },
    /// Check proxy endpoint
    CheckProxy {
        /// Proxy URL to check
        proxy_url: String,
    },
    /// Revoke authentication token
    RevokeToken {
        /// Token to revoke
        token: String,
    },
    /// Send onion message
    SendOnionMessage {
        /// Node IDs for the path (comma-separated)
        #[arg(long, value_delimiter = ',')]
        node_ids: Vec<String>,
        /// TLV type
        tlv_type: u64,
        /// Data (hex string)
        data: String,
    },
    /// Shutdown the node
    Shutdown,
    /// Sign a message
    SignMessage {
        /// Message to sign
        message: String,
    },
}

#[derive(Subcommand)]
enum OnchainCommands {
    /// Get a new Bitcoin address
    Address,
    /// Get BTC balance
    BtcBalance {
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// Estimate fee
    EstimateFee {
        /// Number of blocks for confirmation target
        blocks: u16,
    },
    /// List transactions
    ListTransactions {
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// List unspent outputs
    ListUnspents {
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// Send BTC
    SendBtc {
        /// Amount in satoshis
        amount: u64,
        /// Destination address
        address: String,
        /// Fee rate (sat/vB)
        fee_rate: u64,
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
}

#[derive(Subcommand)]
enum RgbCommands {
    /// Get asset balance
    AssetBalance {
        /// Asset ID
        asset_id: String,
    },
    /// Get asset metadata
    AssetMetadata {
        /// Asset ID
        asset_id: String,
    },
    /// Create UTXOs for RGB operations
    CreateUtxos {
        /// Create up to this number (instead of exactly this number)
        #[arg(long)]
        up_to: bool,
        /// Number of UTXOs
        num: u8,
        /// Size of each UTXO in satoshis
        size: u32,
        /// Fee rate (sat/vB)
        fee_rate: u64,
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// Decode RGB invoice
    DecodeInvoice {
        /// RGB invoice string
        invoice: String,
    },
    /// Fail RGB transfers
    FailTransfers {
        /// Batch transfer index
        #[arg(long)]
        batch_transfer_idx: Option<i32>,
        /// Only fail transfers with no asset
        #[arg(long)]
        no_asset_only: bool,
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// Get asset media
    GetMedia {
        /// Media digest
        digest: String,
    },
    /// Issue CFA asset
    IssueCfa {
        /// Amounts (comma-separated)
        #[arg(long, value_delimiter = ',')]
        amounts: Vec<u64>,
        /// Asset name
        name: String,
        /// Asset details
        #[arg(long)]
        details: Option<String>,
        /// Precision
        #[arg(long, default_value = "0")]
        precision: u8,
        /// File digest for media
        #[arg(long)]
        file_digest: Option<String>,
    },
    /// Issue NIA asset
    IssueNia {
        /// Amounts (comma-separated)
        #[arg(long, value_delimiter = ',')]
        amounts: Vec<u64>,
        /// Asset ticker
        ticker: String,
        /// Asset name
        name: String,
        /// Precision
        #[arg(long, default_value = "0")]
        precision: u8,
    },
    /// Issue UDA asset
    IssueUda {
        /// Asset ticker
        ticker: String,
        /// Asset name
        name: String,
        /// Asset details
        #[arg(long)]
        details: Option<String>,
        /// Precision
        #[arg(long, default_value = "0")]
        precision: u8,
        /// Media file digest
        #[arg(long)]
        media_file_digest: Option<String>,
        /// Attachment file digests (comma-separated)
        #[arg(long, value_delimiter = ',')]
        attachments_file_digests: Vec<String>,
    },
    /// List assets
    ListAssets {
        /// Filter by asset schemas (comma-separated: Nia,Uda,Cfa)
        #[arg(long, value_delimiter = ',')]
        filter_schemas: Vec<String>,
    },
    /// List transfers for an asset
    ListTransfers {
        /// Asset ID
        asset_id: String,
    },
    /// Post asset media
    PostMedia {
        /// Path to media file
        file_path: String,
    },
    /// Refresh transfers
    RefreshTransfers {
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// Get RGB invoice
    RgbInvoice {
        /// Asset ID
        asset_id: String,
        /// Amount
        #[arg(long)]
        amount: Option<u64>,
        /// Duration in seconds
        #[arg(long)]
        duration_seconds: Option<u32>,
        /// Minimum confirmations
        #[arg(long, default_value = "1")]
        min_confirmations: u8,
        /// Use witness recipient
        #[arg(long)]
        witness: bool,
    },
    /// Send RGB asset
    SendAsset {
        /// Asset ID
        asset_id: String,
        /// Amount
        amount: u64,
        /// Recipient ID (from invoice)
        recipient_id: String,
        /// Donation (no change)
        #[arg(long)]
        donation: bool,
        /// Fee rate (sat/vB)
        fee_rate: u64,
        /// Minimum confirmations
        #[arg(long, default_value = "1")]
        min_confirmations: u8,
        /// Transport endpoints (comma-separated)
        #[arg(long, value_delimiter = ',')]
        transport_endpoints: Vec<String>,
        /// Skip sync
        #[arg(long)]
        skip_sync: bool,
    },
    /// Sync RGB wallet
    Sync,
}

#[derive(Subcommand)]
enum ChannelCommands {
    /// Open a channel
    Open {
        /// Peer pubkey@host:port
        peer: String,
        /// Channel capacity in satoshis
        capacity_sat: u64,
        /// Push amount in msats
        #[arg(long, default_value = "0")]
        push_msat: u64,
        /// RGB asset amount
        #[arg(long)]
        asset_amount: Option<u64>,
        /// RGB asset ID
        #[arg(long)]
        asset_id: Option<String>,
        /// Make channel public
        #[arg(long)]
        public: bool,
        /// Use anchors
        #[arg(long, default_value = "true")]
        with_anchors: bool,
        /// Fee base in msats
        #[arg(long)]
        fee_base_msat: Option<u32>,
        /// Fee proportional millionths
        #[arg(long)]
        fee_proportional_millionths: Option<u32>,
        /// Temporary channel ID
        #[arg(long)]
        temporary_channel_id: Option<String>,
    },
    /// Close a channel
    Close {
        /// Channel ID
        channel_id: String,
        /// Peer pubkey
        peer_pubkey: String,
        /// Force close
        #[arg(long)]
        force: bool,
    },
    /// Get channel ID from temporary channel ID
    GetId {
        /// Temporary channel ID
        temporary_channel_id: String,
    },
    /// List channels
    List,
}

#[derive(Subcommand)]
enum PeerCommands {
    /// Connect to a peer
    Connect {
        /// Peer pubkey@host:port
        peer_pubkey_and_addr: String,
    },
    /// Disconnect from a peer
    Disconnect {
        /// Peer pubkey
        peer_pubkey: String,
    },
    /// List peers
    List,
}

#[derive(Subcommand)]
enum PaymentCommands {
    /// Send a keysend payment
    Keysend {
        /// Destination pubkey
        dest_pubkey: String,
        /// Amount in msats
        amt_msat: u64,
        /// RGB asset ID
        #[arg(long)]
        asset_id: Option<String>,
        /// RGB asset amount
        #[arg(long)]
        asset_amount: Option<u64>,
    },
    /// Send a payment
    Send {
        /// Lightning invoice
        invoice: String,
        /// Amount in msats (for zero-amount invoices)
        #[arg(long)]
        amt_msat: Option<u64>,
    },
    /// Get payment details
    Get {
        /// Payment hash
        payment_hash: String,
    },
    /// List payments
    List,
}

#[derive(Subcommand)]
enum InvoiceCommands {
    /// Create a Lightning invoice
    LnInvoice {
        /// Amount in msats
        amt_msat: u64,
        /// Expiry in seconds
        #[arg(long, default_value = "3600")]
        expiry_sec: u32,
        /// RGB asset ID
        #[arg(long)]
        asset_id: Option<String>,
        /// RGB asset amount
        #[arg(long)]
        asset_amount: Option<u64>,
    },
    /// Decode a Lightning invoice
    DecodeLn {
        /// Lightning invoice
        invoice: String,
    },
    /// Get invoice status
    Status {
        /// Lightning invoice
        invoice: String,
    },
}

#[derive(Subcommand)]
enum SwapCommands {
    /// Initialize a maker swap
    MakerInit {
        /// Quantity from (taker sends)
        qty_from: u64,
        /// Quantity to (taker receives)
        qty_to: u64,
        /// From asset ID (taker sends)
        from_asset: String,
        /// To asset ID (taker receives)
        to_asset: String,
        /// Timeout in seconds
        #[arg(long, default_value = "300")]
        timeout_sec: u32,
    },
    /// Execute a maker swap
    MakerExecute {
        /// Swap string from maker init
        swapstring: String,
        /// Payment secret
        payment_secret: String,
        /// Taker pubkey
        taker_pubkey: String,
    },
    /// Accept a swap as taker
    Taker {
        /// Swap string from maker
        swapstring: String,
    },
    /// Get swap details
    Get {
        /// Payment hash
        payment_hash: String,
        /// Is taker swap
        #[arg(long)]
        taker: bool,
    },
    /// List swaps
    List,
}

struct ApiClient {
    client: reqwest::Client,
    server: String,
    token: Option<String>,
    pretty: bool,
}

impl ApiClient {
    fn new(server: String, token: Option<String>, pretty: bool) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
            token,
            pretty,
        }
    }

    async fn get(&self, endpoint: &str) -> ApiResult<Value> {
        let url = format!("{}{}", self.server, endpoint);
        let mut req = self.client.get(&url);

        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;

        if !status.is_success() {
            return Err(format!("HTTP {}: {}", status, text).into());
        }

        Ok(serde_json::from_str(&text)?)
    }

    async fn post<T: serde::Serialize>(&self, endpoint: &str, body: &T) -> ApiResult<Value> {
        let url = format!("{}{}", self.server, endpoint);
        let mut req = self.client.post(&url).json(body);

        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;

        if !status.is_success() {
            return Err(format!("HTTP {}: {}", status, text).into());
        }

        Ok(serde_json::from_str(&text)?)
    }

    async fn post_multipart(&self, endpoint: &str, form: multipart::Form) -> ApiResult<Value> {
        let url = format!("{}{}", self.server, endpoint);
        let mut req = self.client.post(&url).multipart(form);

        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;

        if !status.is_success() {
            return Err(format!("HTTP {}: {}", status, text).into());
        }

        Ok(serde_json::from_str(&text)?)
    }

    fn print(&self, value: &Value) {
        if self.pretty {
            println!("{}", serde_json::to_string_pretty(value).unwrap());
        } else {
            println!("{}", serde_json::to_string(value).unwrap());
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = ApiClient::new(cli.server, cli.token, cli.pretty);

    let result = match cli.command {
        Commands::Node { command } => handle_node_commands(client, command).await,
        Commands::Onchain { command } => handle_onchain_commands(client, command).await,
        Commands::Rgb { command } => handle_rgb_commands(client, command).await,
        Commands::Channel { command } => handle_channel_commands(client, command).await,
        Commands::Peer { command } => handle_peer_commands(client, command).await,
        Commands::Payment { command } => handle_payment_commands(client, command).await,
        Commands::Invoice { command } => handle_invoice_commands(client, command).await,
        Commands::Swap { command } => handle_swap_commands(client, command).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_node_commands(client: ApiClient, command: NodeCommands) -> ApiResult<()> {
    match command {
        NodeCommands::Init { password } => {
            let body = serde_json::json!({ "password": password });
            let res = client.post("/init", &body).await?;
            client.print(&res);
        }
        NodeCommands::Unlock {
            password,
            bitcoind_rpc_username,
            bitcoind_rpc_password,
            bitcoind_rpc_host,
            bitcoind_rpc_port,
            indexer_url,
            proxy_endpoint,
            announce_addresses,
            announce_alias,
        } => {
            let body = serde_json::json!({
                "password": password,
                "bitcoind_rpc_username": bitcoind_rpc_username,
                "bitcoind_rpc_password": bitcoind_rpc_password,
                "bitcoind_rpc_host": bitcoind_rpc_host,
                "bitcoind_rpc_port": bitcoind_rpc_port,
                "indexer_url": indexer_url,
                "proxy_endpoint": proxy_endpoint,
                "announce_addresses": announce_addresses,
                "announce_alias": announce_alias,
            });
            let res = client.post("/unlock", &body).await?;
            client.print(&res);
        }
        NodeCommands::Lock => {
            let res = client.post("/lock", &serde_json::json!({})).await?;
            client.print(&res);
        }
        NodeCommands::Info => {
            let res = client.get("/nodeinfo").await?;
            client.print(&res);
        }
        NodeCommands::NetworkInfo => {
            let res = client.get("/networkinfo").await?;
            client.print(&res);
        }
        NodeCommands::Backup {
            backup_path,
            password,
        } => {
            let body = serde_json::json!({
                "backup_path": backup_path,
                "password": password,
            });
            let res = client.post("/backup", &body).await?;
            client.print(&res);
        }
        NodeCommands::Restore {
            backup_path,
            password,
        } => {
            let body = serde_json::json!({
                "backup_path": backup_path,
                "password": password,
            });
            let res = client.post("/restore", &body).await?;
            client.print(&res);
        }
        NodeCommands::ChangePassword {
            old_password,
            new_password,
        } => {
            let body = serde_json::json!({
                "old_password": old_password,
                "new_password": new_password,
            });
            let res = client.post("/changepassword", &body).await?;
            client.print(&res);
        }
        NodeCommands::CheckIndexer { indexer_url } => {
            let body = serde_json::json!({ "indexer_url": indexer_url });
            let res = client.post("/checkindexerurl", &body).await?;
            client.print(&res);
        }
        NodeCommands::CheckProxy { proxy_url } => {
            let body = serde_json::json!({ "proxy_endpoint": proxy_url });
            let res = client.post("/checkproxyendpoint", &body).await?;
            client.print(&res);
        }
        NodeCommands::RevokeToken { token } => {
            let body = serde_json::json!({ "token": token });
            let res = client.post("/revoketoken", &body).await?;
            client.print(&res);
        }
        NodeCommands::SendOnionMessage {
            node_ids,
            tlv_type,
            data,
        } => {
            let body = serde_json::json!({
                "node_ids": node_ids,
                "tlv_type": tlv_type,
                "data": data,
            });
            let res = client.post("/sendonionmessage", &body).await?;
            client.print(&res);
        }
        NodeCommands::Shutdown => {
            let res = client.post("/shutdown", &serde_json::json!({})).await?;
            client.print(&res);
        }
        NodeCommands::SignMessage { message } => {
            let body = serde_json::json!({ "message": message });
            let res = client.post("/signmessage", &body).await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_onchain_commands(client: ApiClient, command: OnchainCommands) -> ApiResult<()> {
    match command {
        OnchainCommands::Address => {
            let res = client.post("/address", &serde_json::json!({})).await?;
            client.print(&res);
        }
        OnchainCommands::BtcBalance { skip_sync } => {
            let body = serde_json::json!({ "skip_sync": skip_sync });
            let res = client.post("/btcbalance", &body).await?;
            client.print(&res);
        }
        OnchainCommands::EstimateFee { blocks } => {
            let body = serde_json::json!({ "blocks": blocks });
            let res = client.post("/estimatefee", &body).await?;
            client.print(&res);
        }
        OnchainCommands::ListTransactions { skip_sync } => {
            let body = serde_json::json!({ "skip_sync": skip_sync });
            let res = client.post("/listtransactions", &body).await?;
            client.print(&res);
        }
        OnchainCommands::ListUnspents { skip_sync } => {
            let body = serde_json::json!({ "skip_sync": skip_sync });
            let res = client.post("/listunspents", &body).await?;
            client.print(&res);
        }
        OnchainCommands::SendBtc {
            amount,
            address,
            fee_rate,
            skip_sync,
        } => {
            let body = serde_json::json!({
                "amount": amount,
                "address": address,
                "fee_rate": fee_rate,
                "skip_sync": skip_sync,
            });
            let res = client.post("/sendbtc", &body).await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_rgb_commands(client: ApiClient, command: RgbCommands) -> ApiResult<()> {
    match command {
        RgbCommands::AssetBalance { asset_id } => {
            let body = serde_json::json!({ "asset_id": asset_id });
            let res = client.post("/assetbalance", &body).await?;
            client.print(&res);
        }
        RgbCommands::AssetMetadata { asset_id } => {
            let body = serde_json::json!({ "asset_id": asset_id });
            let res = client.post("/assetmetadata", &body).await?;
            client.print(&res);
        }
        RgbCommands::CreateUtxos {
            up_to,
            num,
            size,
            fee_rate,
            skip_sync,
        } => {
            let body = serde_json::json!({
                "up_to": up_to,
                "num": num,
                "size": size,
                "fee_rate": fee_rate,
                "skip_sync": skip_sync,
            });
            let res = client.post("/createutxos", &body).await?;
            client.print(&res);
        }
        RgbCommands::DecodeInvoice { invoice } => {
            let body = serde_json::json!({ "invoice": invoice });
            let res = client.post("/decodergbinvoice", &body).await?;
            client.print(&res);
        }
        RgbCommands::FailTransfers {
            batch_transfer_idx,
            no_asset_only,
            skip_sync,
        } => {
            let body = serde_json::json!({
                "batch_transfer_idx": batch_transfer_idx,
                "no_asset_only": no_asset_only,
                "skip_sync": skip_sync,
            });
            let res = client.post("/failtransfers", &body).await?;
            client.print(&res);
        }
        RgbCommands::GetMedia { digest } => {
            let body = serde_json::json!({ "digest": digest });
            let res = client.post("/getassetmedia", &body).await?;
            client.print(&res);
        }
        RgbCommands::IssueCfa {
            amounts,
            name,
            details,
            precision,
            file_digest,
        } => {
            let body = serde_json::json!({
                "amounts": amounts,
                "name": name,
                "details": details,
                "precision": precision,
                "file_digest": file_digest,
            });
            let res = client.post("/issueassetcfa", &body).await?;
            client.print(&res);
        }
        RgbCommands::IssueNia {
            amounts,
            ticker,
            name,
            precision,
        } => {
            let body = serde_json::json!({
                "amounts": amounts,
                "ticker": ticker,
                "name": name,
                "precision": precision,
            });
            let res = client.post("/issueassetnia", &body).await?;
            client.print(&res);
        }
        RgbCommands::IssueUda {
            ticker,
            name,
            details,
            precision,
            media_file_digest,
            attachments_file_digests,
        } => {
            let body = serde_json::json!({
                "ticker": ticker,
                "name": name,
                "details": details,
                "precision": precision,
                "media_file_digest": media_file_digest,
                "attachments_file_digests": attachments_file_digests,
            });
            let res = client.post("/issueassetuda", &body).await?;
            client.print(&res);
        }
        RgbCommands::ListAssets { filter_schemas } => {
            let schemas: Vec<String> = if filter_schemas.is_empty() {
                vec!["Nia".to_string(), "Uda".to_string(), "Cfa".to_string()]
            } else {
                filter_schemas
            };
            let body = serde_json::json!({ "filter_asset_schemas": schemas });
            let res = client.post("/listassets", &body).await?;
            client.print(&res);
        }
        RgbCommands::ListTransfers { asset_id } => {
            let body = serde_json::json!({ "asset_id": asset_id });
            let res = client.post("/listtransfers", &body).await?;
            client.print(&res);
        }
        RgbCommands::PostMedia { file_path } => {
            let file_bytes = std::fs::read(&file_path)?;
            let file_name = std::path::Path::new(&file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");

            let part = multipart::Part::bytes(file_bytes).file_name(file_name.to_string());

            let form = multipart::Form::new().part("file", part);
            let res = client.post_multipart("/postassetmedia", form).await?;
            client.print(&res);
        }
        RgbCommands::RefreshTransfers { skip_sync } => {
            let body = serde_json::json!({ "skip_sync": skip_sync });
            let res = client.post("/refreshtransfers", &body).await?;
            client.print(&res);
        }
        RgbCommands::RgbInvoice {
            asset_id,
            amount,
            duration_seconds,
            min_confirmations,
            witness,
        } => {
            let assignment = if let Some(amt) = amount {
                serde_json::json!({
                    "type": "Fungible",
                    "value": amt
                })
            } else {
                serde_json::json!({
                    "type": "Any"
                })
            };

            let body = serde_json::json!({
                "asset_id": asset_id,
                "assignment": assignment,
                "duration_seconds": duration_seconds,
                "min_confirmations": min_confirmations,
                "witness": witness,
            });
            let res = client.post("/rgbinvoice", &body).await?;
            client.print(&res);
        }
        RgbCommands::SendAsset {
            asset_id,
            amount,
            recipient_id,
            donation,
            fee_rate,
            min_confirmations,
            transport_endpoints,
            skip_sync,
        } => {
            let body = serde_json::json!({
                "asset_id": asset_id,
                "assignment": {
                    "type": "Fungible",
                    "value": amount
                },
                "recipient_id": recipient_id,
                "witness_data": null,
                "donation": donation,
                "fee_rate": fee_rate,
                "min_confirmations": min_confirmations,
                "transport_endpoints": transport_endpoints,
                "skip_sync": skip_sync,
            });
            let res = client.post("/sendasset", &body).await?;
            client.print(&res);
        }
        RgbCommands::Sync => {
            let res = client.post("/sync", &serde_json::json!({})).await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_channel_commands(client: ApiClient, command: ChannelCommands) -> ApiResult<()> {
    match command {
        ChannelCommands::Open {
            peer,
            capacity_sat,
            push_msat,
            asset_amount,
            asset_id,
            public,
            with_anchors,
            fee_base_msat,
            fee_proportional_millionths,
            temporary_channel_id,
        } => {
            let body = serde_json::json!({
                "peer_pubkey_and_opt_addr": peer,
                "capacity_sat": capacity_sat,
                "push_msat": push_msat,
                "asset_amount": asset_amount,
                "asset_id": asset_id,
                "public": public,
                "with_anchors": with_anchors,
                "fee_base_msat": fee_base_msat,
                "fee_proportional_millionths": fee_proportional_millionths,
                "temporary_channel_id": temporary_channel_id,
            });
            let res = client.post("/openchannel", &body).await?;
            client.print(&res);
        }
        ChannelCommands::Close {
            channel_id,
            peer_pubkey,
            force,
        } => {
            let body = serde_json::json!({
                "channel_id": channel_id,
                "peer_pubkey": peer_pubkey,
                "force": force,
            });
            let res = client.post("/closechannel", &body).await?;
            client.print(&res);
        }
        ChannelCommands::GetId {
            temporary_channel_id,
        } => {
            let body = serde_json::json!({ "temporary_channel_id": temporary_channel_id });
            let res = client.post("/getchannelid", &body).await?;
            client.print(&res);
        }
        ChannelCommands::List => {
            let res = client.get("/listchannels").await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_peer_commands(client: ApiClient, command: PeerCommands) -> ApiResult<()> {
    match command {
        PeerCommands::Connect {
            peer_pubkey_and_addr,
        } => {
            let body = serde_json::json!({ "peer_pubkey_and_addr": peer_pubkey_and_addr });
            let res = client.post("/connectpeer", &body).await?;
            client.print(&res);
        }
        PeerCommands::Disconnect { peer_pubkey } => {
            let body = serde_json::json!({ "peer_pubkey": peer_pubkey });
            let res = client.post("/disconnectpeer", &body).await?;
            client.print(&res);
        }
        PeerCommands::List => {
            let res = client.get("/listpeers").await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_payment_commands(client: ApiClient, command: PaymentCommands) -> ApiResult<()> {
    match command {
        PaymentCommands::Keysend {
            dest_pubkey,
            amt_msat,
            asset_id,
            asset_amount,
        } => {
            let body = serde_json::json!({
                "dest_pubkey": dest_pubkey,
                "amt_msat": amt_msat,
                "asset_id": asset_id,
                "asset_amount": asset_amount,
            });
            let res = client.post("/keysend", &body).await?;
            client.print(&res);
        }
        PaymentCommands::Send { invoice, amt_msat } => {
            let body = serde_json::json!({
                "invoice": invoice,
                "amt_msat": amt_msat,
            });
            let res = client.post("/sendpayment", &body).await?;
            client.print(&res);
        }
        PaymentCommands::Get { payment_hash } => {
            let body = serde_json::json!({ "payment_hash": payment_hash });
            let res = client.post("/getpayment", &body).await?;
            client.print(&res);
        }
        PaymentCommands::List => {
            let res = client.get("/listpayments").await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_invoice_commands(client: ApiClient, command: InvoiceCommands) -> ApiResult<()> {
    match command {
        InvoiceCommands::LnInvoice {
            amt_msat,
            expiry_sec,
            asset_id,
            asset_amount,
        } => {
            let body = serde_json::json!({
                "amt_msat": amt_msat,
                "expiry_sec": expiry_sec,
                "asset_id": asset_id,
                "asset_amount": asset_amount,
            });
            let res = client.post("/lninvoice", &body).await?;
            client.print(&res);
        }
        InvoiceCommands::DecodeLn { invoice } => {
            let body = serde_json::json!({ "invoice": invoice });
            let res = client.post("/decodelninvoice", &body).await?;
            client.print(&res);
        }
        InvoiceCommands::Status { invoice } => {
            let body = serde_json::json!({ "invoice": invoice });
            let res = client.post("/invoicestatus", &body).await?;
            client.print(&res);
        }
    }
    Ok(())
}

async fn handle_swap_commands(client: ApiClient, command: SwapCommands) -> ApiResult<()> {
    match command {
        SwapCommands::MakerInit {
            qty_from,
            qty_to,
            from_asset,
            to_asset,
            timeout_sec,
        } => {
            let from_asset = if from_asset.to_lowercase() == "btc" {
                None
            } else {
                Some(from_asset)
            };
            let to_asset = if to_asset.to_lowercase() == "btc" {
                None
            } else {
                Some(to_asset)
            };

            let body = serde_json::json!({
                "qty_from": qty_from,
                "qty_to": qty_to,
                "from_asset": from_asset,
                "to_asset": to_asset,
                "timeout_sec": timeout_sec,
            });
            let res = client.post("/makerinit", &body).await?;
            client.print(&res);
        }
        SwapCommands::MakerExecute {
            swapstring,
            payment_secret,
            taker_pubkey,
        } => {
            let body = serde_json::json!({
                "swapstring": swapstring,
                "payment_secret": payment_secret,
                "taker_pubkey": taker_pubkey,
            });
            let res = client.post("/makerexecute", &body).await?;
            client.print(&res);
        }
        SwapCommands::Taker { swapstring } => {
            let body = serde_json::json!({ "swapstring": swapstring });
            let res = client.post("/taker", &body).await?;
            client.print(&res);
        }
        SwapCommands::Get {
            payment_hash,
            taker,
        } => {
            let body = serde_json::json!({
                "payment_hash": payment_hash,
                "taker": taker,
            });
            let res = client.post("/getswap", &body).await?;
            client.print(&res);
        }
        SwapCommands::List => {
            let res = client.get("/listswaps").await?;
            client.print(&res);
        }
    }
    Ok(())
}
