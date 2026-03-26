use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

use crate::disk::FilesystemLogger;
use crate::error::APIError;
use crate::utils::{AppState, StaticState};
use crate::{NodeHandle, RlnError};

pub struct TestAppState(Arc<AppState>);

pub fn mock_locked_app_state() -> TestAppState {
    let tmp = tempfile::tempdir().expect("tempdir for mock state");
    let path = tmp.keep();

    TestAppState(Arc::new(AppState {
        static_state: Arc::new(StaticState {
            ldk_peer_listening_port: 9735,
            network: rgb_lib::BitcoinNetwork::Regtest,
            storage_dir_path: path.clone(),
            ldk_data_dir: path.join(".ldk"),
            logger: Arc::new(FilesystemLogger::new(path)),
            max_media_upload_size_mb: 1,
        }),
        cancel_token: CancellationToken::new(),
        unlocked_app_state: Arc::new(TokioMutex::new(None)),
        ldk_background_services: Arc::new(Mutex::new(None)),
        changing_state: Mutex::new(false),
        root_public_key: None,
        revoked_tokens: Arc::new(Mutex::new(HashSet::new())),
    }))
}

pub fn register_uniffi_state_for_tests(state: &TestAppState) {
    crate::set_uniffi_app_state(state.0.clone());
}

pub fn clear_uniffi_state_for_tests() {
    crate::clear_uniffi_app_state();
}

pub fn node_handle_from_mock_state_for_tests(state: &TestAppState) -> NodeHandle {
    NodeHandle::from_app_state(state.0.clone())
}

pub struct ErrorMappingSnapshot {
    pub locked_node: RlnError,
    pub payment_not_found: RlnError,
    pub io_error: RlnError,
}

pub fn error_mapping_snapshot_for_tests() -> ErrorMappingSnapshot {
    ErrorMappingSnapshot {
        locked_node: crate::uniffi_api::state::map_api_error(APIError::LockedNode),
        payment_not_found: crate::uniffi_api::state::map_api_error(APIError::PaymentNotFound(
            "x".to_string(),
        )),
        io_error: crate::uniffi_api::state::map_api_error(APIError::IO(std::io::Error::other(
            "boom",
        ))),
    }
}
