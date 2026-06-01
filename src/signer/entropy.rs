use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use lightning::sign::EntropySource;
use std::sync::Arc;

/// Entropy boundary for RLN runtime code so randomness is decoupled from
/// concrete signer implementations.
pub(crate) trait RlnEntropySource: Send + Sync {
    fn get_secure_random_bytes(&self) -> [u8; 32];
}

#[derive(Clone)]
pub(crate) struct LightningEntropySource {
    inner: Arc<dyn RlnEntropySource>,
}

impl LightningEntropySource {
    pub(crate) fn new(inner: Arc<dyn RlnEntropySource>) -> Self {
        Self { inner }
    }
}

impl EntropySource for LightningEntropySource {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.inner.get_secure_random_bytes()
    }
}

#[derive(Debug, Default)]
pub(crate) struct SystemEntropySource;

impl RlnEntropySource for SystemEntropySource {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }
}
