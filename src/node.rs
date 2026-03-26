use std::sync::Arc;

use rgb_lib::BitcoinNetwork;

use crate::args::UserArgs;
use crate::error::AppError;
use crate::ldk::stop_ldk;
use crate::utils::{start_daemon, AppState};

pub struct NodeConfig {
    pub storage_dir_path: std::path::PathBuf,
    pub daemon_listening_port: u16,
    pub ldk_peer_listening_port: u16,
    pub network: BitcoinNetwork,
    pub max_media_upload_size_mb: u16,
    pub root_public_key: Option<biscuit_auth::PublicKey>,
}

#[derive(Clone)]
pub struct NodeHandle {
    state: Arc<AppState>,
}

impl NodeHandle {
    #[cfg(feature = "uniffi")]
    pub(crate) fn from_app_state(state: Arc<AppState>) -> Self {
        Self { state }
    }

    #[cfg(feature = "uniffi")]
    pub(crate) fn app_state(&self) -> Arc<AppState> {
        self.state.clone()
    }

    pub async fn new(config: NodeConfig) -> Result<Self, AppError> {
        let args = UserArgs {
            storage_dir_path: config.storage_dir_path,
            daemon_listening_port: config.daemon_listening_port,
            ldk_peer_listening_port: config.ldk_peer_listening_port,
            network: config.network,
            max_media_upload_size_mb: config.max_media_upload_size_mb,
            root_public_key: config.root_public_key,
        };
        let state = start_daemon(&args).await?;
        Ok(Self { state })
    }

    pub async fn shutdown(&self) {
        self.state.cancel_token.cancel();
        stop_ldk(self.state.clone()).await;
    }

    #[cfg(feature = "uniffi")]
    pub fn register_for_uniffi(&self) {
        crate::set_uniffi_app_state(self.state.clone());
    }

    #[cfg(feature = "uniffi")]
    pub fn unregister_for_uniffi(&self) {
        crate::clear_uniffi_app_state();
    }
}
