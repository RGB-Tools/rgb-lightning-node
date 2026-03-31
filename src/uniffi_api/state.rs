use std::sync::Arc;

use crate::error::APIError;
use crate::error::AppError;
use crate::utils::AppState;
use crate::NodeHandle;

use super::types::{uniffi_state_slot, RlnError};

fn lock_uniffi_state_slot() -> Result<std::sync::MutexGuard<'static, Option<NodeHandle>>, RlnError>
{
    uniffi_state_slot().lock().map_err(|_| {
        tracing::error!("UniFFI global state mutex is poisoned");
        RlnError::Internal
    })
}

pub(crate) fn set_uniffi_app_state(state: Arc<AppState>) {
    set_uniffi_node_handle(NodeHandle::from_app_state(state));
}

pub(crate) fn set_uniffi_node_handle(handle: NodeHandle) {
    // UniFFI currently uses a single global node handle per process.
    match lock_uniffi_state_slot() {
        Ok(mut slot) => *slot = Some(handle),
        Err(_) => tracing::error!("Failed to register UniFFI node handle"),
    }
}

pub(crate) fn clear_uniffi_app_state() {
    clear_uniffi_node_handle();
}

pub(crate) fn clear_uniffi_node_handle() {
    // Clear global state on daemon shutdown to avoid stale handles.
    match lock_uniffi_state_slot() {
        Ok(mut slot) => *slot = None,
        Err(_) => tracing::error!("Failed to clear UniFFI node handle"),
    }
}

pub(super) fn is_uniffi_app_state_initialized() -> bool {
    // Lightweight readiness probe used by SDK clients before making calls.
    match lock_uniffi_state_slot() {
        Ok(slot) => slot.is_some(),
        Err(_) => false,
    }
}

pub(super) fn get_uniffi_app_state() -> Result<Arc<AppState>, RlnError> {
    lock_uniffi_state_slot()?
        .clone()
        .map(|h| h.app_state())
        .ok_or(RlnError::NotInitialized)
}

pub(super) fn block_on_sdk<F, T>(fut: F) -> Result<T, RlnError>
where
    F: std::future::Future<Output = Result<T, APIError>>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        match handle.runtime_flavor() {
            // Reuse multithread runtime safely from sync boundary.
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(fut)).map_err(map_api_error)
            }
            // `block_in_place` panics on current-thread runtime; run on dedicated runtime instead.
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                shared_uniffi_runtime().block_on(fut).map_err(map_api_error)
            }
            _ => shared_uniffi_runtime().block_on(fut).map_err(map_api_error),
        }
    } else {
        // Use a shared runtime for UniFFI calls from non-async hosts.
        shared_uniffi_runtime().block_on(fut).map_err(map_api_error)
    }
}

pub(super) fn block_on_app<F, T>(fut: F) -> Result<T, RlnError>
where
    F: std::future::Future<Output = Result<T, AppError>>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(fut)).map_err(map_app_error)
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                shared_uniffi_runtime().block_on(fut).map_err(map_app_error)
            }
            _ => shared_uniffi_runtime().block_on(fut).map_err(map_app_error),
        }
    } else {
        shared_uniffi_runtime().block_on(fut).map_err(map_app_error)
    }
}

fn shared_uniffi_runtime() -> &'static tokio::runtime::Runtime {
    // Fallback runtime for sync UniFFI calls when we're not in Tokio, or when
    // host code uses a current-thread Tokio runtime where `block_in_place` is invalid.
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build uniffi runtime")
    })
}

pub(crate) fn map_api_error(err: APIError) -> RlnError {
    match err {
        APIError::LockedNode | APIError::NotInitialized => RlnError::NotInitialized,
        APIError::PaymentNotFound(_)
        | APIError::SwapNotFound(_)
        | APIError::BatchTransferNotFound
        | APIError::UnknownChannelId
        | APIError::UnknownContractId
        | APIError::UnknownLNInvoice
        | APIError::UnknownTemporaryChannelId => RlnError::NotFound,
        APIError::AlreadyInitialized
        | APIError::AlreadyUnlocked
        | APIError::UnlockedNode
        | APIError::ChangingState
        | APIError::OpenChannelInProgress
        | APIError::CannotCloseChannel(_)
        | APIError::DuplicatePayment(_)
        | APIError::RecipientIDAlreadyUsed
        | APIError::TemporaryChannelIdAlreadyUsed
        | APIError::CannotFailBatchTransfer => RlnError::Conflict,
        APIError::InvalidAddress(_)
        | APIError::InvalidAmount(_)
        | APIError::InvalidAssetID(_)
        | APIError::InvalidChannelID
        | APIError::InvalidInvoice(_)
        | APIError::InvalidPaymentHash(_)
        | APIError::InvalidRecipientData(_)
        | APIError::InvalidRecipientID
        | APIError::InvalidRecipientNetwork
        | APIError::InvalidTransportEndpoint(_)
        | APIError::InvalidTransportEndpoints(_)
        | APIError::IncompleteRGBInfo => RlnError::InvalidRequest,
        _ => RlnError::Internal,
    }
}

pub(super) fn map_app_error(err: AppError) -> RlnError {
    match err {
        AppError::UnavailablePort(_) | AppError::InvalidAuthenticationArgs => {
            RlnError::InvalidRequest
        }
        _ => RlnError::Internal,
    }
}
