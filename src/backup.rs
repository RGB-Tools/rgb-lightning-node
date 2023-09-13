use chacha20poly1305::aead::{generic_array::GenericArray, stream};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use rand::{distributions::Alphanumeric, Rng};
use scrypt::password_hash::{PasswordHasher, Salt};
use scrypt::Scrypt;
use tempfile::TempDir;
use typenum::consts::U32;
use walkdir::WalkDir;
use zip::write::FileOptions;

use std::fs::{create_dir_all, read_to_string, remove_file, write, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::APIError;
use crate::utils::LOGS_DIR;

const BACKUP_BUFFER_LEN_ENCRYPT: usize = 239; // 255 max, leaving 16 for the checksum
const BACKUP_BUFFER_LEN_DECRYPT: usize = BACKUP_BUFFER_LEN_ENCRYPT + 16;
const BACKUP_KEY_LENGTH: usize = 32;
const BACKUP_NONCE_LENGTH: usize = 19;
const BACKUP_VERSION: u8 = 1;

struct BackupPaths {
    encrypted: PathBuf,
    nonce: PathBuf,
    salt: PathBuf,
    tempdir: TempDir,
    version: PathBuf,
    zip: PathBuf,
}

struct CypherSecrets {
    key: GenericArray<u8, U32>,
    nonce: [u8; BACKUP_NONCE_LENGTH],
}

/// Create a backup of the wallet as a file with the provided name and encrypted with the
/// provided password.
///
/// Scrypt is used for hashing and xchacha20poly1305 is used for encryption. A random salt for
/// hashing and a random nonce for encrypting are randomly generated and included in the final
/// backup file, along with the backup version
pub fn do_backup(wallet_dir: PathBuf, backup_path: &str, password: &str) -> Result<(), APIError> {
    // setup
    tracing::info!("starting backup...");
    let backup_file = PathBuf::from(&backup_path);
    if backup_file.exists() {
        return Err(APIError::InvalidBackupPath)?;
    }
    let tmp_base_path = _get_parent_path(&backup_file)?;
    let files = _get_backup_paths(&tmp_base_path)?;
    let salt: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(BACKUP_KEY_LENGTH)
        .map(char::from)
        .collect();
    tracing::debug!("using generated salt: {}", &salt);
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(BACKUP_NONCE_LENGTH)
        .map(char::from)
        .collect();
    tracing::debug!("using generated nonce: {}", &nonce);

    // create zip archive of wallet data
    tracing::debug!("\nzipping {:?} to {:?}", &wallet_dir, &files.zip);
    _zip_dir(&wallet_dir, &files.zip)?;

    // encrypt the backup file
    tracing::debug!("\nencrypting {:?} to {:?}", &files.zip, &files.encrypted);
    _encrypt_file(&files.zip, &files.encrypted, password, &salt, &nonce)?;

    // add backup nonce + salt + version to final zip file
    write(files.nonce, nonce)?;
    write(files.salt, salt)?;
    write(files.version, BACKUP_VERSION.to_string())?;
    tracing::debug!("\nzipping {:?} to {:?}", &files.tempdir, &backup_file);
    _zip_dir(&PathBuf::from(files.tempdir.path()), &backup_file)?;

    tracing::info!("backup completed");
    Ok(())
}

/// Restore a backup from the given file and password to the provided target directory.
pub fn restore_backup(backup_path: &str, password: &str, target_dir: &str) -> Result<(), APIError> {
    // setup
    tracing::info!("starting restore...");
    let backup_file = PathBuf::from(backup_path);
    let tmp_base_path = _get_parent_path(&backup_file)?;
    let files = _get_backup_paths(&tmp_base_path)?;
    let target_dir_path = PathBuf::from(&target_dir);

    // unpack given zip file and retrieve backup data
    tracing::info!("unzipping {:?}", backup_file);
    _unzip(&backup_file, &PathBuf::from(files.tempdir.path()))?;
    let nonce = read_to_string(files.nonce)?;
    tracing::debug!("using retrieved nonce: {}", &nonce);
    let salt = read_to_string(files.salt)?;
    tracing::debug!("using retrieved salt: {}", &salt);
    let version = read_to_string(files.version)?
        .parse::<u8>()
        .map_err(|_| APIError::Unexpected)?;
    tracing::debug!("retrieved version: {}", &version);
    if version != BACKUP_VERSION {
        return Err(APIError::UnsupportedBackupVersion {
            version: version.to_string(),
        });
    }

    // decrypt backup and restore files
    tracing::info!("decrypting {:?} to {:?}", files.encrypted, files.zip);
    _decrypt_file(&files.encrypted, &files.zip, password, &salt, &nonce)?;
    tracing::info!("unzipping {:?} to {:?}", &files.zip, &target_dir_path);
    _unzip(&files.zip, &target_dir_path)?;

    tracing::info!("restore completed");
    Ok(())
}

fn _get_backup_paths(tmp_base_path: &Path) -> Result<BackupPaths, APIError> {
    create_dir_all(tmp_base_path)?;
    let tempdir = tempfile::tempdir_in(tmp_base_path)?;
    let encrypted = tempdir.path().join("backup.enc");
    let nonce = tempdir.path().join("backup.nonce");
    let salt = tempdir.path().join("backup.salt");
    let version = tempdir.path().join("backup.version");
    let zip = tempdir.path().join("backup.zip");
    Ok(BackupPaths {
        encrypted,
        nonce,
        salt,
        tempdir,
        version,
        zip,
    })
}

fn _get_parent_path(file: &Path) -> Result<PathBuf, APIError> {
    if let Some(parent) = file.parent() {
        Ok(parent.to_path_buf())
    } else {
        Err(APIError::Unexpected)
    }
}

fn _zip_dir(path_in: &PathBuf, path_out: &PathBuf) -> Result<(), APIError> {
    // setup
    let writer = File::create(path_out)?;
    let mut zip = zip::ZipWriter::new(writer);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Zstd);
    let mut buffer = [0u8; 4096];

    // archive
    let entry_iterator = WalkDir::new(path_in).into_iter().filter_map(|e| e.ok());
    for entry in entry_iterator {
        let path = entry.path();
        let name = path
            .strip_prefix(path_in)
            .map_err(|_| APIError::Unexpected)?;
        let name_str = name.to_str().ok_or_else(|| APIError::Unexpected)?;
        if path.is_file() {
            if path.ends_with("log") {
                continue;
            }
            tracing::debug!("adding file {path:?} as {name:?}");
            zip.start_file(name_str, options)
                .map_err(|_| APIError::Unexpected)?;
            let mut f = File::open(path)?;
            loop {
                let read_count = f.read(&mut buffer)?;
                if read_count != 0 {
                    zip.write_all(&buffer[..read_count])?;
                } else {
                    break;
                }
            }
        } else if !name.as_os_str().is_empty() {
            if name_str.ends_with(LOGS_DIR) {
                continue;
            }
            tracing::debug!("adding directory {path:?} as {name:?}");
            zip.add_directory(name_str, options)
                .map_err(|_| APIError::Unexpected)?;
        }
    }

    // finalize
    let mut file = zip.finish().map_err(|_| APIError::Unexpected)?;
    file.flush()?;
    file.sync_all()?;

    Ok(())
}

fn _unzip(zip_path: &PathBuf, path_out: &Path) -> Result<(), APIError> {
    // setup
    let file = File::open(zip_path).map_err(|_| APIError::Unexpected)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| APIError::Unexpected)?;

    // extract
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|_| APIError::Unexpected)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path_out.join(path),
            None => continue,
        };
        if file.name().ends_with('/') {
            tracing::debug!("creating directory {i} as {}", outpath.display());
            create_dir_all(&outpath)?;
        } else {
            tracing::debug!(
                "extracting file {i} to {} ({} bytes)",
                outpath.display(),
                file.size()
            );
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    tracing::debug!("creating parent dir {}", p.display());
                    create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

fn _get_cypher_secrets(
    password: &str,
    salt_str: &str,
    nonce_str: &str,
) -> Result<CypherSecrets, APIError> {
    // hash password using scrypt with the provided salt
    let password_bytes = password.as_bytes();
    let salt = Salt::from_b64(salt_str).map_err(|_| APIError::Unexpected)?;
    let password_hash = Scrypt
        .hash_password(password_bytes, salt)
        .map_err(|_| APIError::Unexpected)?;
    let hash_output = password_hash.hash.ok_or_else(|| APIError::Unexpected)?;
    let hash = hash_output.as_bytes();

    // get key from password hash
    let key = Key::clone_from_slice(&hash[..BACKUP_KEY_LENGTH]);

    // get nonce from provided str
    let nonce_bytes = nonce_str.as_bytes();
    let nonce: [u8; BACKUP_NONCE_LENGTH] = nonce_bytes[0..BACKUP_NONCE_LENGTH]
        .try_into()
        .map_err(|_| APIError::Unexpected)?;

    Ok(CypherSecrets { key, nonce })
}

fn _encrypt_file(
    path_cleartext: &PathBuf,
    path_encrypted: &PathBuf,
    password: &str,
    salt_str: &str,
    nonce_str: &str,
) -> Result<(), APIError> {
    let cypher_secrets = _get_cypher_secrets(password, salt_str, nonce_str)?;

    // - XChacha20Poly1305 is fast, requires no special hardware and supports stream operation
    // - stream mode required as files to encrypt may be big, so avoiding a memory buffer

    // setup
    let aead = XChaCha20Poly1305::new(&cypher_secrets.key);
    let nonce = GenericArray::from_slice(&cypher_secrets.nonce);
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce);
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_ENCRYPT];
    let mut source_file = File::open(path_cleartext)?;
    let mut destination_file = File::create(path_encrypted)?;

    // encrypt file
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BACKUP_BUFFER_LEN_ENCRYPT {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|_e| APIError::Unexpected)?;
            destination_file.write_all(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|_e| APIError::Unexpected)?;
            destination_file.write_all(&ciphertext)?;
            break;
        }
    }

    // remove cleartext source file
    remove_file(path_cleartext)?;

    Ok(())
}

fn _decrypt_file(
    path_encrypted: &PathBuf,
    path_cleartext: &PathBuf,
    password: &str,
    salt_str: &str,
    nonce_str: &str,
) -> Result<(), APIError> {
    let cypher_secrets = _get_cypher_secrets(password, salt_str, nonce_str)?;

    // setup
    let aead = XChaCha20Poly1305::new(&cypher_secrets.key);
    let nonce = GenericArray::from_slice(&cypher_secrets.nonce);
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce);
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_DECRYPT];
    let mut source_file = File::open(path_encrypted)?;
    let mut destination_file = File::create(path_cleartext)?;

    // decrypt file
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BACKUP_BUFFER_LEN_DECRYPT {
            let cleartext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|_e| APIError::WrongPassword)?;
            destination_file.write_all(&cleartext)?;
        } else if read_count == 0 {
            break;
        } else {
            let cleartext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|_e| APIError::WrongPassword)?;
            destination_file.write_all(&cleartext)?;
            break;
        }
    }

    Ok(())
}
