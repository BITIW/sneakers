use crate::crypto::encrypt::{
    Argon2idParamsV1, DATA_KEY_LEN, NONCE_LEN, SALT_LEN, unwrap_data_key, wrap_data_key,
};
use crate::errors::{Result, SneakError};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum KeySlotV1 {
    Passphrase {
        kdf: Argon2idParamsV1,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        encrypted_data_key: Vec<u8>,
    },
    Recipient {
        recipient_pubkey: Vec<u8>,
        ephemeral_pubkey: Vec<u8>,
        encrypted_data_key: Vec<u8>,
    },
}

impl KeySlotV1 {
    pub fn passphrase(
        passphrase: &str,
        data_key: &[u8; DATA_KEY_LEN],
        parcel_id: &[u8; 32],
    ) -> Result<Self> {
        let (kdf, salt, nonce, encrypted_data_key) =
            wrap_data_key(passphrase, data_key, parcel_id)?;
        Ok(Self::Passphrase {
            kdf,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            encrypted_data_key,
        })
    }

    pub fn try_unlock(&self, passphrase: &str, parcel_id: &[u8; 32]) -> Result<[u8; DATA_KEY_LEN]> {
        match self {
            Self::Passphrase {
                kdf,
                salt,
                nonce,
                encrypted_data_key,
            } => {
                if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
                    return Err(SneakError::WrongPassphrase);
                }

                unwrap_data_key(passphrase, salt, nonce, kdf, encrypted_data_key, parcel_id)
            }
            Self::Recipient { .. } => Err(SneakError::WrongPassphrase),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Passphrase { .. } => "passphrase",
            Self::Recipient { .. } => "recipient",
        }
    }
}
