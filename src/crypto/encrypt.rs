use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::errors::{Result, SneakError};

pub const DATA_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Argon2idParamsV1 {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2idParamsV1 {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn random_data_key() -> [u8; DATA_KEY_LEN] {
    random_array()
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    random_array()
}

pub fn random_salt() -> [u8; SALT_LEN] {
    random_array()
}

pub fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8],
    params: &Argon2idParamsV1,
) -> Result<[u8; DATA_KEY_LEN]> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(DATA_KEY_LEN),
    )
    .map_err(|err| SneakError::other(format!("invalid Argon2id params: {err}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; DATA_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|err| SneakError::other(format!("Argon2id failed: {err}")))?;
    Ok(out)
}

pub fn encrypt(
    key: &[u8; DATA_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| SneakError::other("encryption failed"))
}

pub fn decrypt(
    key: &[u8; DATA_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| SneakError::WrongPassphrase)
}

pub fn wrap_data_key(
    passphrase: &str,
    data_key: &[u8; DATA_KEY_LEN],
    parcel_id: &[u8; 32],
) -> Result<(Argon2idParamsV1, [u8; SALT_LEN], [u8; NONCE_LEN], Vec<u8>)> {
    let params = Argon2idParamsV1::default();
    let salt = random_salt();
    let nonce = random_nonce();
    let mut wrapping_key = derive_passphrase_key(passphrase, &salt, &params)?;
    let aad = data_key_aad(parcel_id);
    let encrypted_key = encrypt(&wrapping_key, &nonce, &aad, data_key)?;
    wrapping_key.zeroize();
    Ok((params, salt, nonce, encrypted_key))
}

pub fn unwrap_data_key(
    passphrase: &str,
    salt: &[u8],
    nonce: &[u8],
    params: &Argon2idParamsV1,
    encrypted_key: &[u8],
    parcel_id: &[u8; 32],
) -> Result<[u8; DATA_KEY_LEN]> {
    let salt: &[u8; SALT_LEN] = salt
        .try_into()
        .map_err(|_| SneakError::other("invalid passphrase key slot salt length"))?;
    let nonce: &[u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| SneakError::other("invalid passphrase key slot nonce length"))?;

    let mut wrapping_key = derive_passphrase_key(passphrase, salt, params)?;
    let aad = data_key_aad(parcel_id);
    let clear = decrypt(&wrapping_key, nonce, &aad, encrypted_key)?;
    wrapping_key.zeroize();

    clear
        .as_slice()
        .try_into()
        .map_err(|_| SneakError::WrongPassphrase)
}

fn data_key_aad(parcel_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"sneakers:data-key:v1:".to_vec();
    aad.extend_from_slice(parcel_id);
    aad
}
