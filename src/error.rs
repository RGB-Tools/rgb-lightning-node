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
    #[error("Allocacations already available")]
    AllocationsAlreadyAvailable,

    #[error("Node has already been initialized")]
    AlreadyInitialized,

    #[error("Anchor outputs are required for RGB channels")]
    AnchorsRequired,

    #[error("Cannot call other APIs while node is changing state")]
    ChangingState,

    #[error("Failed closing channel: {0}")]
    FailedClosingChannel(String),

    #[error("Failed to create invoice: {0}")]
    FailedInvoiceCreation(String),

    #[error("Failed to issue asset: {0}")]
    FailedIssuingAsset(String),

    #[error("Unable to create keys seed file {0}: {1}")]
    FailedKeysCreation(String, String),

    #[error("Failed to sign message: {0}")]
    FailedMessageSigning(String),

    #[error("Failed to open channel: {0}")]
    FailedOpenChannel(String),

    #[error("Failed to connect to peer")]
    FailedPeerConnection,

    #[error("Failed to disconnect to peer: {0}")]
    FailedPeerDisconnection(String),

    #[error("Failed to send onion message: {0}")]
    FailedSendingOnionMessage(String),

    #[error("Failed to start LDK: {0}")]
    FailedStartingLDK(String),

    #[error("Not enough assets, available: {0}")]
    InsufficientAssets(u64),

    #[error("Not enough funds, call getaddress and send {0} satoshis")]
    InsufficientFunds(u64),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Invalid asset ID: {0}")]
    InvalidAssetID(String),

    #[error("Invalid backup path")]
    InvalidBackupPath,

    #[error("Invalid blinded UTXO: {0}")]
    InvalidBlindedUTXO(String),

    #[error("Invalid channel ID")]
    InvalidChannelID,

    #[error("Invalid fee rate: {0}")]
    InvalidFeeRate(String),

    #[error("Invalid invoice: {0}")]
    InvalidInvoice(String),

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Invalid node IDs: {0}")]
    InvalidNodeIds(String),

    #[error("Invalid onion data: {0}")]
    InvalidOnionData(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

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

    #[error("Invalid transport endpoints: {0}")]
    InvalidTransportEndpoints(String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    #[error("Node is locked (hint: call unlock)")]
    LockedNode,

    #[error("No uncolored UTXOs are available (hint: call createutxos)")]
    NoAvailableUtxos,

    #[error("Wallet has not been initialized (hint: call init)")]
    NotInitialized,

    #[error("Output below the dust limit")]
    OutputBelowDustLimit,

    #[error("Proxy error: {0}")]
    Proxy(#[from] reqwest::Error),

    #[error("Recipient ID already used")]
    RecipientIDAlreadyUsed,

    #[error("Unexpected error")]
    Unexpected,

    #[error("Unknown RGB contract ID")]
    UnknownContractId,

    #[error("Unknown LN invoice")]
    UnknownLNInvoice,

    #[error("Node is unlocked (hint: call lock)")]
    UnlockedNode,

    #[error("The provided backup has an unsupported version: {version}")]
    UnsupportedBackupVersion { version: String },

    #[error("The provided password is incorrect")]
    WrongPassword,
}

impl IntoResponse for APIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            APIError::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
            APIError::FailedClosingChannel(_)
            | APIError::FailedInvoiceCreation(_)
            | APIError::FailedIssuingAsset(_)
            | APIError::FailedKeysCreation(_, _)
            | APIError::FailedMessageSigning(_)
            | APIError::FailedOpenChannel(_)
            | APIError::FailedPeerConnection
            | APIError::FailedPeerDisconnection(_)
            | APIError::FailedSendingOnionMessage(_)
            | APIError::FailedStartingLDK(_)
            | APIError::IO(_)
            | APIError::Proxy(_)
            | APIError::Unexpected => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            APIError::AnchorsRequired
            | APIError::InvalidAmount(_)
            | APIError::InvalidAssetID(_)
            | APIError::InvalidBackupPath
            | APIError::InvalidBlindedUTXO(_)
            | APIError::InvalidChannelID
            | APIError::InvalidFeeRate(_)
            | APIError::InvalidInvoice(_)
            | APIError::InvalidName(_)
            | APIError::InvalidNodeIds(_)
            | APIError::InvalidOnionData(_)
            | APIError::InvalidPassword(_)
            | APIError::InvalidPeerInfo(_)
            | APIError::InvalidPrecision(_)
            | APIError::InvalidPubkey
            | APIError::InvalidTicker(_)
            | APIError::InvalidTlvType(_)
            | APIError::InvalidTransportEndpoints(_)
            | APIError::OutputBelowDustLimit
            | APIError::UnsupportedBackupVersion { .. } => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            APIError::WrongPassword => (StatusCode::UNAUTHORIZED, self.to_string()),
            APIError::AllocationsAlreadyAvailable
            | APIError::AlreadyInitialized
            | APIError::ChangingState
            | APIError::InsufficientAssets(_)
            | APIError::InsufficientFunds(_)
            | APIError::LockedNode
            | APIError::NoAvailableUtxos
            | APIError::NotInitialized
            | APIError::RecipientIDAlreadyUsed
            | APIError::UnknownContractId
            | APIError::UnknownLNInvoice
            | APIError::UnlockedNode => (StatusCode::FORBIDDEN, self.to_string()),
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
