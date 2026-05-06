use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::errors::{Result, SneakError};

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    signing_key.sign(message).to_bytes().to_vec()
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SneakError::InvalidSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| SneakError::InvalidSignature)?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| SneakError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature);

    key.verify(message, &signature)
        .map_err(|_| SneakError::InvalidSignature)
}

pub fn public_key_bytes(signing_key: &SigningKey) -> Vec<u8> {
    signing_key.verifying_key().to_bytes().to_vec()
}
