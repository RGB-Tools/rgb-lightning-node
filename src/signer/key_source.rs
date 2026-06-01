use super::types::{BootstrapData, RlnSignerError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) const KEY_SOURCE_FILE_NAME: &str = "key_source.json";
pub(crate) const EXTERNAL_SIGNER_MODE_V1: &str = "external_signer_v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct KeySourceFile {
    pub(crate) mode: String,
    pub(crate) node_id: String,
    pub(crate) account_xpub_vanilla: String,
    pub(crate) account_xpub_colored: String,
    pub(crate) master_fingerprint: String,
    pub(crate) protocol_version: String,
    pub(crate) api_level: u32,
}

impl KeySourceFile {
    pub(crate) fn from_bootstrap(bootstrap: &BootstrapData) -> Self {
        Self {
            mode: EXTERNAL_SIGNER_MODE_V1.to_string(),
            node_id: bootstrap.identity.node_id.clone(),
            account_xpub_vanilla: bootstrap.identity.account_xpub_vanilla.clone(),
            account_xpub_colored: bootstrap.identity.account_xpub_colored.clone(),
            master_fingerprint: bootstrap.identity.master_fingerprint.clone(),
            protocol_version: bootstrap.protocol_version.clone(),
            api_level: bootstrap.api_level,
        }
    }
}

pub(crate) fn key_source_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(KEY_SOURCE_FILE_NAME)
}

pub(crate) fn read_key_source_file(
    storage_dir: &Path,
) -> Result<Option<KeySourceFile>, RlnSignerError> {
    let path = key_source_path(storage_dir);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)
        .map_err(|e| RlnSignerError::Protocol(format!("failed to read key source file: {e}")))?;
    let parsed = serde_json::from_slice::<KeySourceFile>(&bytes)
        .map_err(|e| RlnSignerError::Protocol(format!("failed to decode key source file: {e}")))?;
    Ok(Some(parsed))
}

#[allow(dead_code)]
pub(crate) fn write_key_source_file(
    storage_dir: &Path,
    key_source: &KeySourceFile,
) -> Result<(), RlnSignerError> {
    let path = key_source_path(storage_dir);
    let bytes = serde_json::to_vec_pretty(key_source)
        .map_err(|e| RlnSignerError::Protocol(format!("failed to encode key source file: {e}")))?;
    write_restricted_file(&path, &bytes)?;
    Ok(())
}

#[allow(dead_code)]
fn write_restricted_file(path: &Path, bytes: &[u8]) -> Result<(), RlnSignerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                RlnSignerError::Protocol(format!(
                    "failed to open key source file with restricted permissions: {e}"
                ))
            })?;
        file.write_all(bytes).map_err(|e| {
            RlnSignerError::Protocol(format!("failed to write key source file: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            RlnSignerError::Protocol(format!("failed to sync key source file: {e}"))
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
            .map_err(|e| RlnSignerError::Protocol(format!("failed to write key source file: {e}")))
    }
}

pub(crate) fn validate_key_source_matches_bootstrap(
    key_source: &KeySourceFile,
    bootstrap: &BootstrapData,
) -> Result<(), RlnSignerError> {
    if key_source.mode != EXTERNAL_SIGNER_MODE_V1 {
        return Err(RlnSignerError::Unsupported(format!(
            "unsupported key source mode: {}",
            key_source.mode
        )));
    }

    let expected = KeySourceFile::from_bootstrap(bootstrap);
    if *key_source == expected {
        return Ok(());
    }

    Err(RlnSignerError::Protocol(
        "external signer identity does not match persisted key_source.json".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::types::SignerIdentity;

    fn sample_bootstrap() -> BootstrapData {
        BootstrapData {
            identity: SignerIdentity {
                node_id: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                account_xpub_vanilla: "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKpJ7c2P4YFQki71RJKVQ1BM8DT6vKrrf5gkP7vC18JNpDutLCRa14Q6gttxyPjdvVSxGJySLjeRG".to_string(),
                account_xpub_colored: "xpub6BosfCnifzQ5xU6LhM1cBh73PvvrLpzjAU6YewsGmmKzBSSMSmc5QwDFi1Cdm42Hcps225y7sY9qsJhK8GugHgd6NqBJ38qRAjPR9U1FVL".to_string(),
                master_fingerprint: "deadbeef".to_string(),
            },
            protocol_version: "v1".to_string(),
            api_level: 1,
        }
    }

    #[test]
    fn key_source_roundtrip_read_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bootstrap = sample_bootstrap();
        let key_source = KeySourceFile::from_bootstrap(&bootstrap);

        write_key_source_file(tmp.path(), &key_source).expect("write key source");
        let read_back = read_key_source_file(tmp.path())
            .expect("read key source")
            .expect("key source exists");
        assert_eq!(read_back, key_source);
    }

    #[cfg(unix)]
    #[test]
    fn key_source_written_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bootstrap = sample_bootstrap();
        let key_source = KeySourceFile::from_bootstrap(&bootstrap);

        write_key_source_file(tmp.path(), &key_source).expect("write key source");
        let metadata =
            fs::metadata(key_source_path(tmp.path())).expect("metadata for key source file");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn read_key_source_returns_none_when_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let value = read_key_source_file(tmp.path()).expect("read missing key source");
        assert!(value.is_none());
    }

    #[test]
    fn validate_key_source_checks_mode_and_identity() {
        let bootstrap = sample_bootstrap();
        let valid = KeySourceFile::from_bootstrap(&bootstrap);
        assert!(validate_key_source_matches_bootstrap(&valid, &bootstrap).is_ok());

        let mut wrong_mode = valid.clone();
        wrong_mode.mode = "legacy".to_string();
        assert!(matches!(
            validate_key_source_matches_bootstrap(&wrong_mode, &bootstrap),
            Err(RlnSignerError::Unsupported(_))
        ));

        let mut wrong_identity = valid;
        wrong_identity.node_id =
            "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        assert!(matches!(
            validate_key_source_matches_bootstrap(&wrong_identity, &bootstrap),
            Err(RlnSignerError::Protocol(_))
        ));
    }
}
