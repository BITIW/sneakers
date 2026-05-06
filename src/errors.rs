use thiserror::Error;

pub type Result<T> = std::result::Result<T, SneakError>;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum SneakError {
    #[error("invalid parcel magic")]
    InvalidMagic,
    #[error("unsupported parcel format version {0}")]
    UnsupportedVersion(u16),
    #[error("wrong passphrase or unsupported key slot")]
    WrongPassphrase,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("manifest is corrupt")]
    ManifestCorrupt,
    #[error("chunk {0} is corrupt")]
    ChunkCorrupt(u64),
    #[error("footer is missing")]
    FooterMissing,
    #[error("header/footer mismatch")]
    HeaderFooterMismatch,
    #[error("medium appears to be mounted")]
    MediumMounted,
    #[error("not enough space on target medium")]
    NotEnoughSpace,
    #[error("operation was interrupted or parcel is incomplete")]
    InterruptedWrite,
    #[error("path is outside of this MVP's safety rules: {0}")]
    UnsafePath(String),
    #[error("{0}")]
    Other(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl SneakError {
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}
