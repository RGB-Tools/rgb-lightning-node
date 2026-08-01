//! Encrypted mnemonic file format, plus the password-based key derivation and cipher setup it
//! shares with the streaming backup encryption in [`crate::backup`].
//!
//! Keys are derived with scrypt and data is encrypted with XChaCha20Poly1305.

use amplify::s;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};

use crate::error::APIError;

// Length of the keys derived from a password.
pub(crate) const KEY_LEN: usize = 32;

const MNEMONIC_VERSION: u8 = 1;
const MNEMONIC_SALT_LEN: usize = 16;
const MNEMONIC_NONCE_LEN: usize = 24;
// Bytes taken by the version and the work factors, which precede the salt and the nonce in a
// mnemonic header.
const MNEMONIC_HEADER_PREFIX_LEN: usize = 1 + 1 + 4 + 4;
const MNEMONIC_HEADER_LEN: usize =
    MNEMONIC_HEADER_PREFIX_LEN + MNEMONIC_SALT_LEN + MNEMONIC_NONCE_LEN;

// The scrypt CPU/memory cost of the work factors.
const CURRENT_LOG_N: u8 = 17;
const BACKUP_V1_LOG_N: u8 = 17;

// The test build is unoptimized, which makes scrypt about 30 times slower,
// therefore the work factors are lowered for tests.
const TEST_LOG_N: u8 = 10;

// The scrypt work factors.
//
// Values are pinned here instead of being taken from `ScryptParams::recommended()`, whose
// defaults can change between crate releases and would then leave already encrypted data
// undecryptable.
#[derive(Clone, Copy)]
pub(crate) struct KdfParams {
    log_n: u8,
    r: u32,
    p: u32,
}

impl KdfParams {
    // Work factors used for newly encrypted data.
    pub(crate) const CURRENT: Self = Self {
        log_n: if cfg!(test) {
            TEST_LOG_N
        } else {
            CURRENT_LOG_N
        },
        r: 8,
        p: 1,
    };

    // Work factors of backup format version 1, which has no field to record them and therefore
    // requires these values to stay unchanged.
    pub(crate) const BACKUP_V1: Self = Self {
        log_n: if cfg!(test) {
            TEST_LOG_N
        } else {
            BACKUP_V1_LOG_N
        },
        r: 8,
        p: 1,
    };

    // Highest accepted work factors: scrypt allocates `128 * r * 2^log_n` bytes, so reading back
    // unbounded values would let a damaged file exhaust the available memory
    const MAX_LOG_N: u8 = 20;
    const MAX_R: u32 = 32;
    const MAX_P: u32 = 16;

    // Returns `None` if the given work factors are out of range or rejected by scrypt.
    fn checked(log_n: u8, r: u32, p: u32) -> Option<Self> {
        let in_range = log_n <= Self::MAX_LOG_N
            && (1..=Self::MAX_R).contains(&r)
            && (1..=Self::MAX_P).contains(&p);
        (in_range && ScryptParams::new(log_n, r, p, KEY_LEN).is_ok()).then_some(Self {
            log_n,
            r,
            p,
        })
    }

    fn to_scrypt(self) -> ScryptParams {
        ScryptParams::new(self.log_n, self.r, self.p, KEY_LEN).expect("checked work factors")
    }
}

// Derive an encryption key from the given password and salt.
pub(crate) fn derive_key(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<[u8; KEY_LEN], APIError> {
    let mut key = [0u8; KEY_LEN];
    scrypt(password.as_bytes(), salt, &params.to_scrypt(), &mut key)
        .map_err(|e| APIError::Unexpected(format!("Failed to derive key: {e}")))?;
    Ok(key)
}

// Build an XChaCha20Poly1305 AEAD from a key returned by [`derive_key`].
pub(crate) fn aead_from_key(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key))
}

// Data preceding the ciphertext of an encrypted mnemonic.
//
// It is serialized as: version (1 byte), scrypt `log_n` (1 byte), scrypt `r` (4 bytes, big
// endian), scrypt `p` (4 bytes, big endian), salt, nonce.
struct MnemonicHeader {
    params: KdfParams,
    salt: [u8; MNEMONIC_SALT_LEN],
    nonce: [u8; MNEMONIC_NONCE_LEN],
}

impl MnemonicHeader {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(MNEMONIC_HEADER_LEN);
        encoded.push(MNEMONIC_VERSION);
        encoded.push(self.params.log_n);
        encoded.extend_from_slice(&self.params.r.to_be_bytes());
        encoded.extend_from_slice(&self.params.p.to_be_bytes());
        encoded.extend_from_slice(&self.salt);
        encoded.extend_from_slice(&self.nonce);
        encoded
    }

    fn decode(encoded: &[u8; MNEMONIC_HEADER_LEN]) -> Result<Self, APIError> {
        let version = encoded[0];
        if version != MNEMONIC_VERSION {
            return Err(APIError::CorruptedMnemonic(format!(
                "unsupported version {version}"
            )));
        }
        let log_n = encoded[1];
        let r = u32::from_be_bytes(encoded[2..6].try_into().expect("4 bytes"));
        let p = u32::from_be_bytes(encoded[6..10].try_into().expect("4 bytes"));
        let params = KdfParams::checked(log_n, r, p).ok_or_else(|| {
            APIError::CorruptedMnemonic(format!(
                "unsupported scrypt work factors (log_n {log_n}, r {r}, p {p})"
            ))
        })?;
        let salt_end = MNEMONIC_HEADER_PREFIX_LEN + MNEMONIC_SALT_LEN;

        Ok(Self {
            params,
            salt: encoded[MNEMONIC_HEADER_PREFIX_LEN..salt_end]
                .try_into()
                .expect("salt length"),
            nonce: encoded[salt_end..].try_into().expect("nonce length"),
        })
    }
}

// Encrypt a mnemonic with the given password.
//
// The work factors are stored along with the ciphertext, so raising the ones used for new data
// keeps previously encrypted mnemonics readable.
pub(crate) fn encrypt_mnemonic(password: &str, mnemonic: &str) -> Result<String, APIError> {
    let mut salt = [0u8; MNEMONIC_SALT_LEN];
    let mut nonce = [0u8; MNEMONIC_NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    encrypt_with(
        password,
        KdfParams::CURRENT,
        salt,
        nonce,
        mnemonic.as_bytes(),
    )
}

// Encrypt a mnemonic with the given password, work factors, salt and nonce.
//
// Split out of [`encrypt_mnemonic`] so that tests can encrypt deterministically, and with work
// factors cheaper than the current ones, without reimplementing the payload layout.
fn encrypt_with(
    password: &str,
    params: KdfParams,
    salt: [u8; MNEMONIC_SALT_LEN],
    nonce: [u8; MNEMONIC_NONCE_LEN],
    plaintext: &[u8],
) -> Result<String, APIError> {
    let key = derive_key(password, &salt, params)?;
    let ciphertext = aead_from_key(&key)
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| APIError::Unexpected(format!("Failed to encrypt mnemonic: {e}")))?;

    let mut payload = MnemonicHeader {
        params,
        salt,
        nonce,
    }
    .encode();
    payload.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(payload))
}

// Decrypt a mnemonic encrypted with [`encrypt_mnemonic`].
//
// A wrong password is the only cause for [`APIError::WrongPassword`], data that cannot be
// interpreted is reported as [`APIError::CorruptedMnemonic`] instead.
pub(crate) fn decrypt_mnemonic(password: &str, encrypted: &str) -> Result<String, APIError> {
    let payload = BASE64
        .decode(encrypted)
        .map_err(|e| APIError::CorruptedMnemonic(format!("invalid base64: {e}")))?;
    let Some((header, ciphertext)) = payload.split_first_chunk::<MNEMONIC_HEADER_LEN>() else {
        return Err(APIError::CorruptedMnemonic(format!(
            "got {} bytes, expected more than {MNEMONIC_HEADER_LEN}",
            payload.len()
        )));
    };
    if ciphertext.is_empty() {
        return Err(APIError::CorruptedMnemonic(s!("no ciphertext")));
    }
    let header = MnemonicHeader::decode(header)?;

    let key = derive_key(password, &header.salt, header.params)?;
    let plaintext = aead_from_key(&key)
        .decrypt(XNonce::from_slice(&header.nonce), ciphertext)
        .map_err(|_| APIError::WrongPassword)?;

    String::from_utf8(plaintext).map_err(|_| APIError::CorruptedMnemonic(s!("invalid UTF-8")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "password123";
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    // Work factors differing from the ones used for new data, so that data encrypted with them can
    // only be decrypted if the work factors stored along with it are honored.
    const OTHER_PARAMS: KdfParams = KdfParams {
        log_n: TEST_LOG_N + 1,
        r: 8,
        p: 1,
    };

    fn encrypt_with_other_params(plaintext: &[u8]) -> String {
        let salt = [7u8; MNEMONIC_SALT_LEN];
        let nonce = [9u8; MNEMONIC_NONCE_LEN];
        encrypt_with(PASSWORD, OTHER_PARAMS, salt, nonce, plaintext).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let encrypted = encrypt_mnemonic(PASSWORD, MNEMONIC).unwrap();
        assert_eq!(decrypt_mnemonic(PASSWORD, &encrypted).unwrap(), MNEMONIC);
    }

    #[test]
    fn real_work_factors_are_usable() {
        // everywhere else in this module a test build swaps the work factors of a real build for a
        // much cheaper cost, so this is the only place checking the real ones are usable
        let current = KdfParams {
            log_n: CURRENT_LOG_N,
            ..KdfParams::CURRENT
        };
        let backup_v1 = KdfParams {
            log_n: BACKUP_V1_LOG_N,
            ..KdfParams::BACKUP_V1
        };

        // backups derive a key without going through the mnemonic format
        assert!(KdfParams::checked(backup_v1.log_n, backup_v1.r, backup_v1.p).is_some());
        derive_key(PASSWORD, &[7u8; MNEMONIC_SALT_LEN], backup_v1).unwrap();

        // mnemonics store their work factors, so a roundtrip also covers reading them back
        assert!(KdfParams::checked(current.log_n, current.r, current.p).is_some());
        let encrypted = encrypt_with(
            PASSWORD,
            current,
            [7u8; MNEMONIC_SALT_LEN],
            [9u8; MNEMONIC_NONCE_LEN],
            MNEMONIC.as_bytes(),
        )
        .unwrap();
        assert_eq!(decrypt_mnemonic(PASSWORD, &encrypted).unwrap(), MNEMONIC);
    }

    #[test]
    fn stored_work_factors_are_used() {
        // decrypting data encrypted with work factors other than the current ones can only
        // succeed if the ones stored along with it are being used
        let encrypted = encrypt_with_other_params(MNEMONIC.as_bytes());
        assert_eq!(decrypt_mnemonic(PASSWORD, &encrypted).unwrap(), MNEMONIC);
    }

    #[test]
    fn wrong_password_is_detected() {
        let encrypted = encrypt_with_other_params(MNEMONIC.as_bytes());
        assert!(matches!(
            decrypt_mnemonic("wrong-password", &encrypted),
            Err(APIError::WrongPassword)
        ));
    }

    #[test]
    fn corrupted_data_is_not_a_wrong_password() {
        let with_header = |version: u8, log_n: u8, r: u32, p: u32| {
            let mut payload = vec![version, log_n];
            payload.extend_from_slice(&r.to_be_bytes());
            payload.extend_from_slice(&p.to_be_bytes());
            payload.extend_from_slice(&[0u8; MNEMONIC_SALT_LEN + MNEMONIC_NONCE_LEN]);
            payload.extend_from_slice(b"ciphertext");
            BASE64.encode(payload)
        };

        for encrypted in [
            s!("not base64 at all"),
            // truncated, then complete but without any ciphertext
            BASE64.encode([0u8; MNEMONIC_HEADER_LEN - 1]),
            BASE64.encode([0u8; MNEMONIC_HEADER_LEN]),
            encrypt_with_other_params(b"\xff not valid UTF-8"),
            with_header(MNEMONIC_VERSION + 1, 17, 8, 1),
            with_header(MNEMONIC_VERSION, KdfParams::MAX_LOG_N + 1, 8, 1),
            with_header(MNEMONIC_VERSION, 17, 0, 1),
            with_header(MNEMONIC_VERSION, 17, 8, 0),
        ] {
            assert!(matches!(
                decrypt_mnemonic(PASSWORD, &encrypted),
                Err(APIError::CorruptedMnemonic(_))
            ));
        }
    }
}
