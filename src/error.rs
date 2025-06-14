use amplify::s;
use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use rgb_lib::{BitcoinNetwork, Error as RgbLibError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct APIErrorResponse {
    pub(crate) error: String,
    pub(crate) code: u16,
    pub(crate) name: String,
}

/// The error variants returned by APIs
#[derive(Debug, thiserror::Error)]
pub enum APIError {
    #[error("Allocations already available")]
    AllocationsAlreadyAvailable,

    #[error("Node has already been initialized")]
    AlreadyInitialized,

    #[error("Anchor outputs are required for RGB channels")]
    AnchorsRequired,

    #[error("Node has already been unlocked")]
    AlreadyUnlocked,

    #[error("Batch transfer not found")]
    BatchTransferNotFound,

    #[error("Cannot estimate fees")]
    CannotEstimateFees,

    #[error("Batch transfer cannot be set to failed status")]
    CannotFailBatchTransfer,

    #[error("Cannot call other APIs while node is changing state")]
    ChangingState,

    #[error("Another payment for this invoice is already in status {0}")]
    DuplicatePayment(String),

    #[error("The swap offer has expired")]
    ExpiredSwapOffer,

    #[error("Failed to sync BDK: {0}")]
    FailedBdkSync(String),

    #[error("Failed to connect to bitcoind client: {0}")]
    FailedBitcoindConnection(String),

    #[error("Failed broadcast: {0}")]
    FailedBroadcast(String),

    #[error("Failed closing channel: {0}")]
    FailedClosingChannel(String),

    #[error("Failed to create invoice: {0}")]
    FailedInvoiceCreation(String),

    #[error("Failed to issue asset: {0}")]
    FailedIssuingAsset(String),

    #[error("Unable to create keys seed file {0}: {1}")]
    FailedKeysCreation(String, String),

    #[error("Failed to open channel: {0}")]
    FailedOpenChannel(String),

    #[error("Failed payment: {0}")]
    FailedPayment(String),

    #[error("Failed to connect to peer")]
    FailedPeerConnection,

    #[error("Failed to disconnect to peer: {0}")]
    FailedPeerDisconnection(String),

    #[error("Failed to send onion message: {0}")]
    FailedSendingOnionMessage(String),

    #[error("For an RGB operation both asset_id and asset_amount must be set")]
    IncompleteRGBInfo,

    #[error("Not enough assets")]
    InsufficientAssets,

    #[error("Insufficient capacity to cover the commitment transaction fees ({0} sat)")]
    InsufficientCapacity(u64),

    #[error("Not enough funds, get an address and send {0} sats there")]
    InsufficientFunds(u64),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Invalid announce addresses: {0}")]
    InvalidAnnounceAddresses(String),

    #[error("Invalid announce alias: {0}")]
    InvalidAnnounceAlias(String),

    #[error("Invalid asset ID: {0}")]
    InvalidAssetID(String),

    #[error("Invalid hex bytes")]
    InvalidAssetIDBytes,

    #[error("Invalid attachments: {0}")]
    InvalidAttachments(String),

    #[error("Invalid backup path")]
    InvalidBackupPath,

    #[error("Invalid channel ID")]
    InvalidChannelID,

    #[error("Invalid details: {0}")]
    InvalidDetails(String),

    #[error("Trying to request fee estimation for an invalid block number")]
    InvalidEstimationBlocks,

    #[error("Invalid fee rate: {0}")]
    InvalidFeeRate(String),

    #[error("Invalid hex string: {0}")]
    InvalidHexString(String),

    #[error("Invalid indexer: {0}")]
    InvalidIndexer(String),

    #[error("Invalid invoice: {0}")]
    InvalidInvoice(String),

    #[error("Invalid media digest")]
    InvalidMediaDigest,

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Invalid node IDs: {0}")]
    InvalidNodeIds(String),

    #[error("Invalid onion data: {0}")]
    InvalidOnionData(String),

    #[error("Invalid payment hash: {0}")]
    InvalidPaymentHash(String),

    #[error("Invalid payment secret")]
    InvalidPaymentSecret,

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Invalid peer info: {0}")]
    InvalidPeerInfo(String),

    #[error("Invalid precision: {0}")]
    InvalidPrecision(String),

    #[error("Invalid proxy endpoint")]
    InvalidProxyEndpoint,

    #[error("Invalid proxy protocol version: {0}")]
    InvalidProxyProtocol(String),

    #[error("Invalid pubkey")]
    InvalidPubkey,

    #[error("The provided recipient ID is neither a blinded UTXO or a script")]
    InvalidRecipientID,

    #[error("The provided recipient ID is for a different network than the wallet's one")]
    InvalidRecipientNetwork,

    #[error("Invalid swap: {0}")]
    InvalidSwap(String),

    #[error("Invalid swap string '{0}': {1}")]
    InvalidSwapString(String, String),

    #[error("Invalid ticker: {0}")]
    InvalidTicker(String),

    #[error("Invalid tlv type: {0}")]
    InvalidTlvType(String),

    #[error("Invalid transport endpoint: {0}")]
    InvalidTransportEndpoint(String),

    #[error("Invalid transport endpoints: {0}")]
    InvalidTransportEndpoints(String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    #[error("Node is locked (hint: call unlock)")]
    LockedNode,

    #[error("Media file is empty")]
    MediaFileEmpty,

    #[error("Media file has not been provided")]
    MediaFileNotProvided,

    #[error("Max fee exceeded for transfer with TXID: {0}")]
    MaxFeeExceeded(String),

    #[error("Min fee not met for transfer with TXID: {0}")]
    MinFeeNotMet(String),

    #[error("Unable to find payment preimage, be sure you've provided the correct swap info")]
    MissingSwapPaymentPreimage,

    #[error("Network error: {0}")]
    Network(String),

    #[error("The network of the given bitcoind ({0}) doesn't match the node's chain ({1})")]
    NetworkMismatch(String, BitcoinNetwork),

    #[error("No uncolored UTXOs are available (hint: call createutxos)")]
    NoAvailableUtxos,

    #[error("No route found")]
    NoRoute,

    #[error("Wallet has not been initialized (hint: call init)")]
    NotInitialized,

    #[error("No valid transport endpoint found")]
    NoValidTransportEndpoint,

    #[error("Cannot perform this operation while an open channel operation is in progress")]
    OpenChannelInProgress,

    #[error("Output below the dust limit")]
    OutputBelowDustLimit,

    #[error("Payment not found: {0}")]
    PaymentNotFound(String),

    #[error("Recipient ID already used")]
    RecipientIDAlreadyUsed,

    #[error("Swap not found: {0}")]
    SwapNotFound(String),

    #[error("Sync needed")]
    SyncNeeded,

    #[error("Temporary channel ID already used")]
    TemporaryChannelIdAlreadyUsed,

    #[error("Unexpected error: {0}")]
    Unexpected(String),

    #[error("Unknown RGB contract ID")]
    UnknownContractId,

    #[error("Unknown LN invoice")]
    UnknownLNInvoice,

    #[error("Unknown temporary channel ID")]
    UnknownTemporaryChannelId,

    #[error("Node is unlocked (hint: call lock)")]
    UnlockedNode,

    #[error("The provided backup has an unsupported version: {version}")]
    UnsupportedBackupVersion { version: String },

    #[error("Layer 1 {0} is not supported")]
    UnsupportedLayer1(String),

    #[error("Transport type is not supported")]
    UnsupportedTransportType,

    #[error("The provided password is incorrect")]
    WrongPassword,
}

impl APIError {
    fn name(&self) -> String {
        format!("{:?}", self)
            .split('(')
            .next()
            .unwrap()
            .split(" {")
            .next()
            .unwrap()
            .to_string()
    }
}

impl From<RgbLibError> for APIError {
    fn from(error: RgbLibError) -> Self {
        match error {
            RgbLibError::AllocationsAlreadyAvailable => APIError::AllocationsAlreadyAvailable,
            RgbLibError::AssetNotFound { .. } => APIError::UnknownContractId,
            RgbLibError::BatchTransferNotFound { .. } => APIError::BatchTransferNotFound,
            RgbLibError::CannotEstimateFees => APIError::CannotEstimateFees,
            RgbLibError::CannotFailBatchTransfer => APIError::CannotFailBatchTransfer,
            RgbLibError::EmptyFile { .. } => APIError::MediaFileEmpty,
            RgbLibError::FailedBdkSync { details } => APIError::FailedBdkSync(details),
            RgbLibError::FailedBroadcast { details } => APIError::FailedBroadcast(details),
            RgbLibError::FailedIssuance { details } => APIError::FailedIssuingAsset(details),
            RgbLibError::IO { details } => {
                APIError::IO(std::io::Error::other(format!("rgb-lib err: {details}")))
            }
            RgbLibError::Inconsistency { details } => {
                APIError::Unexpected(format!("rgb-lib inconsistency detected: {details}"))
            }
            RgbLibError::Indexer { details } => {
                APIError::Network(format!("indexer err: {details}"))
            }
            RgbLibError::InsufficientAllocationSlots => APIError::NoAvailableUtxos,
            RgbLibError::InsufficientBitcoins { needed, available } => {
                APIError::InsufficientFunds(needed - available)
            }
            RgbLibError::InsufficientSpendableAssets { .. } => APIError::InsufficientAssets,
            RgbLibError::InsufficientTotalAssets { .. } => APIError::InsufficientAssets,
            RgbLibError::InvalidAddress { details } => APIError::InvalidAddress(details),
            RgbLibError::InvalidAmountZero => APIError::InvalidAmount(s!("0")),
            RgbLibError::InvalidAssetID { asset_id } => APIError::InvalidAssetID(asset_id),
            RgbLibError::InvalidAttachments { details } => APIError::InvalidAttachments(details),
            RgbLibError::InvalidDetails { details } => APIError::InvalidDetails(details),
            RgbLibError::InvalidElectrum { details } => APIError::InvalidIndexer(details),
            RgbLibError::InvalidEstimationBlocks => APIError::InvalidEstimationBlocks,
            RgbLibError::InvalidFeeRate { details } => APIError::InvalidFeeRate(details),
            RgbLibError::InvalidFilePath { .. } => APIError::MediaFileNotProvided,
            RgbLibError::InvalidIndexer { details } => APIError::InvalidIndexer(details),
            RgbLibError::InvalidInvoice { details } => APIError::InvalidInvoice(details),
            RgbLibError::InvalidName { details } => APIError::InvalidName(details),
            RgbLibError::InvalidPrecision { details } => APIError::InvalidPrecision(details),
            RgbLibError::InvalidProxyProtocol { version } => {
                APIError::InvalidProxyProtocol(version)
            }
            RgbLibError::InvalidRecipientID => APIError::InvalidRecipientID,
            RgbLibError::InvalidRecipientNetwork => APIError::InvalidRecipientNetwork,
            RgbLibError::InvalidTicker { details } => APIError::InvalidTicker(details),
            RgbLibError::InvalidTransportEndpoint { details } => {
                APIError::InvalidTransportEndpoint(details)
            }
            RgbLibError::InvalidTransportEndpoints { details } => {
                APIError::InvalidTransportEndpoints(details)
            }
            RgbLibError::MaxFeeExceeded { txid } => APIError::MaxFeeExceeded(txid),
            RgbLibError::MinFeeNotMet { txid } => APIError::MinFeeNotMet(txid),
            RgbLibError::Network { details } => APIError::Network(details),
            RgbLibError::NoIssuanceAmounts => {
                APIError::InvalidAmount(s!("issuance request with no provided amounts"))
            }
            RgbLibError::NoValidTransportEndpoint => APIError::NoValidTransportEndpoint,
            RgbLibError::OutputBelowDustLimit => APIError::OutputBelowDustLimit,
            RgbLibError::Proxy { details } => APIError::Network(format!("proxy err: {details}")),
            RgbLibError::RecipientIDAlreadyUsed => APIError::RecipientIDAlreadyUsed,
            RgbLibError::SyncNeeded => APIError::SyncNeeded,
            RgbLibError::TooHighIssuanceAmounts => {
                APIError::InvalidAmount(s!("trying to issue too many assets"))
            }
            RgbLibError::UnsupportedLayer1 { layer_1 } => APIError::UnsupportedLayer1(layer_1),
            RgbLibError::UnsupportedTransportType => APIError::UnsupportedTransportType,
            _ => {
                tracing::debug!("Unexpected rgb-lib error: {error:?}");
                APIError::Unexpected(format!("Unmapped rgb-lib error: {error:?}"))
            }
        }
    }
}

impl IntoResponse for APIError {
    fn into_response(self) -> Response {
        let (status, error, name) = match self {
            APIError::JsonExtractorRejection(ref json_rejection) => (
                json_rejection.status(),
                json_rejection.body_text(),
                self.name(),
            ),
            APIError::FailedClosingChannel(_)
            | APIError::FailedInvoiceCreation(_)
            | APIError::FailedIssuingAsset(_)
            | APIError::FailedKeysCreation(_, _)
            | APIError::FailedOpenChannel(_)
            | APIError::FailedPayment(_)
            | APIError::FailedPeerDisconnection(_)
            | APIError::FailedSendingOnionMessage(_)
            | APIError::IO(_)
            | APIError::Unexpected(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.to_string(),
                self.name(),
            ),
            APIError::AnchorsRequired
            | APIError::ExpiredSwapOffer
            | APIError::IncompleteRGBInfo
            | APIError::InvalidAddress(_)
            | APIError::InvalidAmount(_)
            | APIError::InvalidAnnounceAddresses(_)
            | APIError::InvalidAnnounceAlias(_)
            | APIError::InvalidAssetID(_)
            | APIError::InvalidAssetIDBytes
            | APIError::InvalidAttachments(_)
            | APIError::InvalidBackupPath
            | APIError::InvalidChannelID
            | APIError::InvalidDetails(_)
            | APIError::InvalidEstimationBlocks
            | APIError::InvalidFeeRate(_)
            | APIError::InvalidHexString(_)
            | APIError::InvalidInvoice(_)
            | APIError::InvalidMediaDigest
            | APIError::InvalidName(_)
            | APIError::InvalidNodeIds(_)
            | APIError::InvalidOnionData(_)
            | APIError::InvalidPassword(_)
            | APIError::InvalidPaymentHash(_)
            | APIError::InvalidPaymentSecret
            | APIError::InvalidPeerInfo(_)
            | APIError::InvalidPrecision(_)
            | APIError::InvalidPubkey
            | APIError::InvalidRecipientID
            | APIError::InvalidRecipientNetwork
            | APIError::InvalidSwap(_)
            | APIError::InvalidSwapString(_, _)
            | APIError::InvalidTicker(_)
            | APIError::InvalidTlvType(_)
            | APIError::InvalidTransportEndpoint(_)
            | APIError::InvalidTransportEndpoints(_)
            | APIError::MediaFileEmpty
            | APIError::MediaFileNotProvided
            | APIError::MissingSwapPaymentPreimage
            | APIError::OutputBelowDustLimit
            | APIError::UnsupportedBackupVersion { .. } => {
                (StatusCode::BAD_REQUEST, self.to_string(), self.name())
            }
            APIError::WrongPassword => (StatusCode::UNAUTHORIZED, self.to_string(), self.name()),
            APIError::AllocationsAlreadyAvailable
            | APIError::AlreadyInitialized
            | APIError::AlreadyUnlocked
            | APIError::BatchTransferNotFound
            | APIError::CannotEstimateFees
            | APIError::CannotFailBatchTransfer
            | APIError::ChangingState
            | APIError::DuplicatePayment(_)
            | APIError::FailedBdkSync(_)
            | APIError::FailedBitcoindConnection(_)
            | APIError::FailedBroadcast(_)
            | APIError::FailedPeerConnection
            | APIError::InsufficientAssets
            | APIError::InsufficientCapacity(_)
            | APIError::InsufficientFunds(_)
            | APIError::InvalidIndexer(_)
            | APIError::InvalidProxyEndpoint
            | APIError::InvalidProxyProtocol(_)
            | APIError::LockedNode
            | APIError::MaxFeeExceeded(_)
            | APIError::MinFeeNotMet(_)
            | APIError::NetworkMismatch(_, _)
            | APIError::NoAvailableUtxos
            | APIError::NoRoute
            | APIError::NotInitialized
            | APIError::OpenChannelInProgress
            | APIError::PaymentNotFound(_)
            | APIError::RecipientIDAlreadyUsed
            | APIError::SwapNotFound(_)
            | APIError::SyncNeeded
            | APIError::TemporaryChannelIdAlreadyUsed
            | APIError::UnknownContractId
            | APIError::UnknownLNInvoice
            | APIError::UnknownTemporaryChannelId
            | APIError::UnlockedNode
            | APIError::UnsupportedLayer1(_)
            | APIError::UnsupportedTransportType => {
                (StatusCode::FORBIDDEN, self.to_string(), self.name())
            }
            APIError::Network(_) | APIError::NoValidTransportEndpoint => (
                StatusCode::SERVICE_UNAVAILABLE,
                self.to_string(),
                self.name(),
            ),
        };

        let error = error.replace("\n", " ");

        tracing::error!("APIError: {error}");

        let body = Json(
            serde_json::to_value(APIErrorResponse {
                error,
                code: status.as_u16(),
                name,
            })
            .unwrap(),
        );

        (status, body).into_response()
    }
}

/// The error variants returned by the app
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Port {0} is unavailable")]
    UnavailablePort(u16),

    #[error("PoC does not support selected network")]
    UnsupportedBitcoinNetwork,
}
