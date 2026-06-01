use super::types::RlnSignerError;

/// Synchronous in-process transport for external signer requests.
pub(crate) trait ExternalSignerTransport: Send + Sync {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, RlnSignerError>;
}
