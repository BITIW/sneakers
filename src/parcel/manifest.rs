use std::fs::Metadata;

use crate::compression::CompressionKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum MetadataProfile {
    Portable,
    UnixBasic,
}

impl MetadataProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::UnixBasic => "unix-basic",
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ManifestV1 {
    pub parcel_id: Vec<u8>,
    pub format_version: u16,
    pub metadata_profile: MetadataProfile,
    pub files: Vec<FileEntryV1>,
    pub directories: Vec<DirectoryEntryV1>,
    pub symlinks: Vec<SymlinkEntryV1>,
    pub chunks: Vec<ChunkEntryV1>,
    pub compression: CompressionKind,
    pub crypto: CryptoInfoV1,
    pub policy: ParcelPolicyV1,
    pub plaintext_total_size: u64,
    pub stored_total_size: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CryptoInfoV1 {
    pub suite: String,
    pub chunk_size: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ParcelPolicyV1 {
    pub default_extract_policy: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct FileEntryV1 {
    pub file_id: u64,
    pub path: String,
    pub size: u64,
    pub mtime: u64,
    pub mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub chunks: Vec<u64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DirectoryEntryV1 {
    pub path: String,
    pub mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SymlinkEntryV1 {
    pub path: String,
    pub target: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ChunkEntryV1 {
    pub chunk_id: u64,
    pub file_id: u64,
    pub plain_offset: u64,
    pub plain_size: u64,
    pub stored_size: u64,
    pub compression: CompressionKind,
    pub encryption_nonce: Vec<u8>,
    pub plain_hash: Vec<u8>,
    pub compressed_hash: Option<Vec<u8>>,
    pub cipher_hash: Vec<u8>,
    pub frame_sequence: u64,
    pub frame_offset: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SignatureBlockV1 {
    pub transcript_hash: Vec<u8>,
    pub records: Vec<SignatureRecordV1>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SignatureRecordV1 {
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl FileEntryV1 {
    pub fn from_metadata(file_id: u64, path: String, metadata: &Metadata) -> Self {
        Self {
            file_id,
            path,
            size: metadata.len(),
            mtime: mtime(metadata),
            mode: mode(metadata),
            uid: uid(metadata),
            gid: gid(metadata),
            chunks: Vec::new(),
        }
    }
}

impl DirectoryEntryV1 {
    pub fn from_metadata(path: String, metadata: &Metadata) -> Self {
        Self {
            path,
            mode: mode(metadata),
            uid: uid(metadata),
            gid: gid(metadata),
            mtime: mtime(metadata),
        }
    }
}

impl SymlinkEntryV1 {
    pub fn from_metadata(path: String, target: String, metadata: &Metadata) -> Self {
        Self {
            path,
            target,
            uid: uid(metadata),
            gid: gid(metadata),
            mtime: mtime(metadata),
        }
    }
}

fn mtime(metadata: &Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(unix)]
fn mode(metadata: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn mode(_metadata: &Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn uid(metadata: &Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.uid())
}

#[cfg(not(unix))]
fn uid(_metadata: &Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn gid(metadata: &Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.gid())
}

#[cfg(not(unix))]
fn gid(_metadata: &Metadata) -> Option<u32> {
    None
}
