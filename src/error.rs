use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bitcoin::Network;
use serde_json::json;

/// The error variants returned by APIs
#[derive(Debug, thiserror::Error)]
pub enum APIError {
    /// Provided blinded UTXO has already been used for another transfer
    #[error("Blinded UTXO already used")]
    BlindedUTXOAlreadyUsed,

    #[error("Failed closing channel: {0}")]
    FailedClosingChannel(String),

    #[error("Failed to create invoice: {0}")]
    FailedInvoiceCreation(String),

    #[error("Failed to sign message: {0}")]
    FailedMessageSigning(String),

    #[error("Failed to open channel: {0}")]
    FailedOpenChannel(String),

    #[error("Failed to connect to peer")]
    FailedPeerConnection,

    #[error("Failed to disconnect to peer: {0}")]
    FailedPeerDisconnection(String),

    #[error("Failed to post consignment")]
    FailedPostingConsignment,

    #[error("Failed to send onion message: {0}")]
    FailedSendingOnionMessage(String),

    #[error("Not enough assets, available: {0}")]
    InsufficientAssets(u64),

    #[error("Not enough funds, call getaddress and send {0} satoshis")]
    InsufficientFunds(u64),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Invalid asset ID: {0}")]
    InvalidAssetID(String),

    #[error("Invalid blinded UTXO: {0}")]
    InvalidBlindedUTXO(String),

    #[error("Invalid channel ID")]
    InvalidChannelID,

    #[error("Invalid invoice: {0}")]
    InvalidInvoice(String),

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Invalid node IDs: {0}")]
    InvalidNodeIds(String),

    #[error("Invalid onion data: {0}")]
    InvalidOnionData(String),

    #[error("Invalid peer info: {0}")]
    InvalidPeerInfo(String),

    #[error("Invalid precision: {0}")]
    InvalidPrecision(String),

    #[error("Invalid pubkey")]
    InvalidPubkey,

    #[error("Invalid ticker: {0}")]
    InvalidTicker(String),

    #[error("Invalid tlv type: {0}")]
    InvalidTlvType(String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    #[error("No uncolored UTXOs are available (hint: call createutxos)")]
    NoAvailableUtxos,

    #[error("Proxy error: {0}")]
    Proxy(#[from] reqwest::Error),

    #[error("Unknown RGB contract ID")]
    UnknownContractId,

    #[error("Unknown LN invoice")]
    UnknownLNInvoice,
}

impl IntoResponse for APIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            APIError::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
            APIError::FailedClosingChannel(_)
            | APIError::FailedInvoiceCreation(_)
            | APIError::FailedMessageSigning(_)
            | APIError::FailedOpenChannel(_)
            | APIError::FailedPeerConnection
            | APIError::FailedPeerDisconnection(_)
            | APIError::FailedPostingConsignment
            | APIError::FailedSendingOnionMessage(_)
            | APIError::IO(_)
            | APIError::Proxy(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            APIError::InvalidAmount(_)
            | APIError::InvalidAssetID(_)
            | APIError::InvalidBlindedUTXO(_)
            | APIError::InvalidChannelID
            | APIError::InvalidInvoice(_)
            | APIError::InvalidName(_)
            | APIError::InvalidNodeIds(_)
            | APIError::InvalidOnionData(_)
            | APIError::InvalidPeerInfo(_)
            | APIError::InvalidPrecision(_)
            | APIError::InvalidPubkey
            | APIError::InvalidTicker(_)
            | APIError::InvalidTlvType(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            APIError::BlindedUTXOAlreadyUsed
            | APIError::InsufficientAssets(_)
            | APIError::InsufficientFunds(_)
            | APIError::NoAvailableUtxos
            | APIError::UnknownContractId
            | APIError::UnknownLNInvoice => (StatusCode::FORBIDDEN, self.to_string()),
        };

        let body = Json(json!({
            "error": error_message,
            "code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// The error variants returned by the app
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Failed to connect to bitcoind client: {0}")]
    FailedBitcoindConnection(String),

    #[error("Unable to create keys seed file {0}: {1}")]
    FailedKeysCreation(String, String),

    #[error("Invalid announced listen addresses: {0}")]
    InvalidAnnouncedListenAddresses(String),

    #[error("Chain argument ({0}) didn't match bitcoind chain ({1})")]
    InvalidBitcoinNetwork(Network, String),

    #[error("Invalid bitcoind RPC info: {0}")]
    InvalidBitcoinRPCInfo(String),

    #[error("Invalid node alias: {0}")]
    InvalidNodeAlias(String),

    #[error("PoC does not support selected network")]
    UnsupportedBitcoinNetwork,
}
