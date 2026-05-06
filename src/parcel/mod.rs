pub mod footer;
pub mod frame;
pub mod header;
pub mod manifest;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use walkdir::WalkDir;

use crate::compression::{CompressionKind, zstd};
use crate::core::now_unix;
use crate::crypto::encrypt::{DATA_KEY_LEN, decrypt, encrypt, random_data_key, random_nonce};
use crate::crypto::hash::{hash, hash_many};
use crate::crypto::keys::KeySlotV1;
use crate::crypto::sign;
use crate::errors::{Result, SneakError};
use crate::identity::IdentityStore;
use crate::log::{LogEventType, LogRecordV1};
use crate::parcel::footer::ParcelFooterV1;
use crate::parcel::frame::{Frame, FrameType};
use crate::parcel::header::ParcelHeader;
use crate::parcel::manifest::{
    ChunkEntryV1, CryptoInfoV1, DirectoryEntryV1, FileEntryV1, ManifestV1, MetadataProfile,
    ParcelPolicyV1, SignatureBlockV1, SignatureRecordV1,
};

pub const FORMAT_VERSION: u16 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyMode {
    Quick,
    Normal,
    Full,
}

impl VerifyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Normal => "normal",
            Self::Full => "full",
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "quick" => Ok(Self::Quick),
            "normal" => Ok(Self::Normal),
            "full" => Ok(Self::Full),
            other => Err(SneakError::other(format!(
                "unknown verify mode '{other}', expected quick|normal|full"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreateOptions {
    pub src: PathBuf,
    pub output: PathBuf,
    pub passphrase: String,
    pub identity_name: Option<String>,
    pub compression: CompressionKind,
    pub compression_level: i32,
    pub compression_threads: Option<usize>,
    pub chunk_size: usize,
    pub metadata_profile: MetadataProfile,
}

#[derive(Clone, Debug)]
pub struct ParcelSummary {
    pub header: ParcelHeader,
    pub footer: ParcelFooterV1,
    pub manifest: ManifestV1,
    pub key_slots: Vec<KeySlotV1>,
    pub signature_block: SignatureBlockV1,
    pub data_key: [u8; DATA_KEY_LEN],
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ChunkStatus {
    pub chunk_id: u64,
    pub valid: bool,
    pub error: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub summary: ParcelSummary,
    pub mode: VerifyMode,
    pub signature_valid: bool,
    pub trusted_signers: Vec<String>,
    pub untrusted_signers: Vec<String>,
    pub unsigned: bool,
    pub chunks_checked: usize,
    pub damaged_chunks: Vec<ChunkStatus>,
}

pub fn create(options: CreateOptions) -> Result<()> {
    if options.chunk_size == 0 {
        return Err(SneakError::other("chunk size must be greater than zero"));
    }
    if let Some(parent) = options
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    let mut parcel_id = [0u8; 32];
    OsRng.fill_bytes(&mut parcel_id);
    let data_key = random_data_key();

    let identity_store = IdentityStore::open()?;
    let identity = match &options.identity_name {
        Some(name) => identity_store.load(name)?,
        None => identity_store.default_identity()?.ok_or_else(|| {
            SneakError::other(
                "parcel create needs a signing identity; run `sneakers identity create \"Laptop A\"` or pass `--identity <name>`",
            )
        })?,
    };
    let creator_pubkey = identity.public_key.clone();

    let key_slots = vec![KeySlotV1::passphrase(
        &options.passphrase,
        &data_key,
        &parcel_id,
    )?];

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&options.output)?;
    file.write_all(&vec![0u8; header::FIXED_HEADER_LEN])?;
    let mut writer = BufWriter::new(file);

    let mut sequence = 1u64;
    let mut previous_hash = [0u8; 32];
    let key_slots_offset = writer.stream_position()?;
    let key_slots_payload = to_msgpack(&key_slots)?;
    let key_slots_frame = Frame::new(
        FrameType::KeySlots,
        sequence,
        previous_hash,
        key_slots_payload,
    );
    key_slots_frame.write_to(&mut writer)?;
    previous_hash = key_slots_frame.frame_hash();
    sequence += 1;

    let chunk_stream_offset = writer.stream_position()?;
    let source = collect_source(&options.src)?;
    let mut manifest = ManifestV1 {
        parcel_id: parcel_id.to_vec(),
        format_version: FORMAT_VERSION,
        metadata_profile: options.metadata_profile,
        files: Vec::new(),
        directories: source.directories,
        symlinks: source.symlinks,
        chunks: Vec::new(),
        compression: options.compression,
        crypto: CryptoInfoV1 {
            suite: "xchacha20poly1305+argon2id+blake3+ed25519".to_string(),
            chunk_size: options.chunk_size as u64,
        },
        policy: ParcelPolicyV1 {
            default_extract_policy: "safe".to_string(),
        },
        plaintext_total_size: 0,
        stored_total_size: 0,
        created_at: now_unix(),
    };

    let mut file_id = 1u64;
    let mut chunk_id = 1u64;

    for source_file in source.files {
        let mut entry = source_file.entry;
        entry.file_id = file_id;
        entry.chunks.clear();

        let mut reader = BufReader::new(File::open(&source_file.absolute_path)?);
        let mut offset = 0u64;
        loop {
            let mut plain = vec![0u8; options.chunk_size];
            let read = reader.read(&mut plain)?;
            if read == 0 {
                break;
            }
            plain.truncate(read);

            let plain_hash = hash(&plain);
            let compressed = zstd::compress(
                options.compression,
                options.compression_level,
                options.compression_threads,
                &plain,
            )?;
            let compressed_hash = if options.compression == CompressionKind::Zstd {
                Some(hash(&compressed).to_vec())
            } else {
                None
            };
            let nonce = random_nonce();
            let aad = chunk_aad(&parcel_id, chunk_id);
            let ciphertext = encrypt(&data_key, &nonce, &aad, &compressed)?;
            let cipher_hash = hash(&ciphertext);
            let frame_offset = writer.stream_position()?;
            let payload = to_msgpack(&EncryptedChunkPayloadV1 {
                chunk_id,
                nonce: nonce.to_vec(),
                ciphertext,
            })?;
            let frame = Frame::new(FrameType::Chunk, sequence, previous_hash, payload);
            frame.write_to(&mut writer)?;

            let stored_size = frame.header.payload_len;
            entry.chunks.push(chunk_id);
            manifest.chunks.push(ChunkEntryV1 {
                chunk_id,
                file_id,
                plain_offset: offset,
                plain_size: read as u64,
                stored_size,
                compression: options.compression,
                encryption_nonce: nonce.to_vec(),
                plain_hash: plain_hash.to_vec(),
                compressed_hash: compressed_hash.clone(),
                cipher_hash: cipher_hash.to_vec(),
                frame_sequence: sequence,
                frame_offset,
            });
            manifest.plaintext_total_size += read as u64;
            manifest.stored_total_size += stored_size;

            previous_hash = frame.frame_hash();
            sequence += 1;
            chunk_id += 1;
            offset += read as u64;
        }

        manifest.files.push(entry);
        file_id += 1;
    }

    let manifest_plain = to_msgpack(&manifest)?;
    let manifest_hash = hash(&manifest_plain);
    let manifest_nonce = random_nonce();
    let manifest_aad = manifest_aad(&parcel_id);
    let encrypted_manifest = encrypt(&data_key, &manifest_nonce, &manifest_aad, &manifest_plain)?;
    let manifest_offset = writer.stream_position()?;
    let manifest_payload = to_msgpack(&EncryptedManifestPayloadV1 {
        nonce: manifest_nonce.to_vec(),
        ciphertext: encrypted_manifest,
        plaintext_hash: manifest_hash.to_vec(),
    })?;
    let manifest_frame = Frame::new(
        FrameType::EncryptedManifest,
        sequence,
        previous_hash,
        manifest_payload,
    );
    manifest_frame.write_to(&mut writer)?;
    previous_hash = manifest_frame.frame_hash();
    sequence += 1;

    let chunk_merkle_root = chunk_root(&manifest.chunks);
    let policy_hash = hash(&to_msgpack(&manifest.policy)?);
    let log_head = [0u8; 32];
    let parcel_fingerprint = parcel_fingerprint(
        &parcel_id,
        &manifest_hash,
        &chunk_merkle_root,
        &policy_hash,
        &creator_pubkey,
    );
    let transcript = signature_transcript(
        &parcel_id,
        &parcel_fingerprint,
        &manifest_hash,
        &chunk_merkle_root,
        &policy_hash,
        &log_head,
        &creator_pubkey,
    );
    let signing_key = identity.signing_key()?;
    let signature_records = vec![SignatureRecordV1 {
        signer_pubkey: identity.public_key,
        signature: sign::sign(&signing_key, &transcript),
    }];
    let signature_block = SignatureBlockV1 {
        transcript_hash: transcript.to_vec(),
        records: signature_records,
    };

    let signature_offset = writer.stream_position()?;
    let signature_payload = to_msgpack(&signature_block)?;
    let signature_frame = Frame::new(
        FrameType::SignatureBlock,
        sequence,
        previous_hash,
        signature_payload,
    );
    signature_frame.write_to(&mut writer)?;
    previous_hash = signature_frame.frame_hash();
    sequence += 1;

    let log_record = LogRecordV1::unsigned(
        1,
        LogEventType::Created,
        creator_pubkey.clone(),
        parcel_id.to_vec(),
        parcel_fingerprint.to_vec(),
    );
    let log_offset = writer.stream_position()?;
    let log_payload = to_msgpack(&log_record)?;
    let log_frame = Frame::new(FrameType::LogRecord, sequence, previous_hash, log_payload);
    log_frame.write_to(&mut writer)?;
    previous_hash = log_frame.frame_hash();
    sequence += 1;

    let footer_offset = writer.stream_position()?;
    let footer = ParcelFooterV1 {
        parcel_id: parcel_id.to_vec(),
        parcel_fingerprint: parcel_fingerprint.to_vec(),
        manifest_hash: manifest_hash.to_vec(),
        chunk_merkle_root: chunk_merkle_root.to_vec(),
        frame_count: sequence,
        last_frame_hash: previous_hash.to_vec(),
        created_at: manifest.created_at,
    };
    let footer_payload = to_msgpack(&footer)?;
    let footer_frame = Frame::new(FrameType::Footer, sequence, previous_hash, footer_payload);
    footer_frame.write_to(&mut writer)?;
    writer.flush()?;

    let mut file = writer
        .into_inner()
        .map_err(|err| SneakError::Io(err.into_error()))?;
    let header = ParcelHeader::new(
        parcel_id,
        creator_pubkey,
        key_slots.len() as u16,
        key_slots_offset,
        manifest_offset,
        chunk_stream_offset,
        signature_offset,
        log_offset,
        footer_offset,
    );
    file.seek(SeekFrom::Start(0))?;
    header.write_to(&mut file)?;
    file.flush()?;

    Ok(())
}

pub fn open(path: &Path, passphrase: &str) -> Result<ParcelSummary> {
    let mut file = File::open(path)?;
    let header = ParcelHeader::read_from(&mut file)?;
    if header.format_version != FORMAT_VERSION {
        return Err(SneakError::UnsupportedVersion(header.format_version));
    }

    let key_slots: Vec<KeySlotV1> =
        read_frame_payload_at(&mut file, header.key_slots_offset, FrameType::KeySlots)?;
    let data_key = unlock_data_key(&key_slots, passphrase, &header.parcel_id)?;
    let footer: ParcelFooterV1 =
        read_frame_payload_at(&mut file, header.footer_offset, FrameType::Footer)?;
    if footer.parcel_id.as_slice() != header.parcel_id {
        return Err(SneakError::HeaderFooterMismatch);
    }

    let encrypted_manifest: EncryptedManifestPayloadV1 = read_frame_payload_at(
        &mut file,
        header.manifest_offset,
        FrameType::EncryptedManifest,
    )?;
    let manifest_nonce: [u8; 24] = encrypted_manifest
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SneakError::ManifestCorrupt)?;
    let manifest_plain = decrypt(
        &data_key,
        &manifest_nonce,
        &manifest_aad(&header.parcel_id),
        &encrypted_manifest.ciphertext,
    )
    .map_err(|_| SneakError::ManifestCorrupt)?;

    let manifest_hash = hash(&manifest_plain);
    if encrypted_manifest.plaintext_hash.as_slice() != manifest_hash
        || footer.manifest_hash.as_slice() != manifest_hash
    {
        return Err(SneakError::ManifestCorrupt);
    }
    let manifest: ManifestV1 = from_msgpack(&manifest_plain)?;
    if manifest.parcel_id.as_slice() != header.parcel_id {
        return Err(SneakError::HeaderFooterMismatch);
    }

    let signature_block: SignatureBlockV1 = read_frame_payload_at(
        &mut file,
        header.signature_offset,
        FrameType::SignatureBlock,
    )?;

    Ok(ParcelSummary {
        header,
        footer,
        manifest,
        key_slots,
        signature_block,
        data_key,
    })
}

pub fn verify(path: &Path, passphrase: &str, mode: VerifyMode) -> Result<VerificationReport> {
    let summary = open(path, passphrase)?;
    verify_signature(&summary)?;

    let trust = IdentityStore::open()?.load_trusted_keys()?;
    let trusted: HashMap<Vec<u8>, String> = trust
        .into_iter()
        .map(|trusted| (trusted.pubkey, trusted.name))
        .collect();

    let mut trusted_signers = Vec::new();
    let mut untrusted_signers = Vec::new();
    for record in &summary.signature_block.records {
        if let Some(name) = trusted.get(&record.signer_pubkey) {
            trusted_signers.push(name.clone());
        } else {
            untrusted_signers.push(hex::encode(&record.signer_pubkey));
        }
    }

    let mut chunks_checked = 0usize;
    let mut damaged_chunks = Vec::new();
    if mode != VerifyMode::Quick {
        damaged_chunks = verify_chunks(path, &summary, mode)?;
        chunks_checked = summary.manifest.chunks.len();
    }

    let unsigned = summary.signature_block.records.is_empty();
    Ok(VerificationReport {
        summary,
        mode,
        signature_valid: true,
        trusted_signers,
        untrusted_signers,
        unsigned,
        chunks_checked,
        damaged_chunks,
    })
}

pub fn read_log_record(path: &Path, summary: &ParcelSummary) -> Result<LogRecordV1> {
    let mut file = File::open(path)?;
    read_frame_payload_at(&mut file, summary.header.log_offset, FrameType::LogRecord)
}

pub fn read_chunk(path: &Path, summary: &ParcelSummary, chunk: &ChunkEntryV1) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let payload: EncryptedChunkPayloadV1 =
        read_frame_payload_at(&mut file, chunk.frame_offset, FrameType::Chunk)?;
    if payload.chunk_id != chunk.chunk_id {
        return Err(SneakError::ChunkCorrupt(chunk.chunk_id));
    }
    let cipher_hash = hash(&payload.ciphertext);
    if chunk.cipher_hash.as_slice() != cipher_hash {
        return Err(SneakError::ChunkCorrupt(chunk.chunk_id));
    }

    let nonce: [u8; 24] = payload
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SneakError::ChunkCorrupt(chunk.chunk_id))?;
    let compressed = decrypt(
        &summary.data_key,
        &nonce,
        &chunk_aad(&summary.header.parcel_id, chunk.chunk_id),
        &payload.ciphertext,
    )
    .map_err(|_| SneakError::ChunkCorrupt(chunk.chunk_id))?;

    if let Some(expected) = &chunk.compressed_hash {
        if expected.as_slice() != hash(&compressed) {
            return Err(SneakError::ChunkCorrupt(chunk.chunk_id));
        }
    }

    let plain = zstd::decompress(chunk.compression, chunk.plain_size, &compressed)?;
    if plain.len() as u64 != chunk.plain_size || chunk.plain_hash.as_slice() != hash(&plain) {
        return Err(SneakError::ChunkCorrupt(chunk.chunk_id));
    }

    Ok(plain)
}

pub fn verify_chunks(
    path: &Path,
    summary: &ParcelSummary,
    mode: VerifyMode,
) -> Result<Vec<ChunkStatus>> {
    let mut damaged = Vec::new();
    for chunk in &summary.manifest.chunks {
        let result = match mode {
            VerifyMode::Quick => Ok(()),
            VerifyMode::Normal => verify_chunk_ciphertext(path, chunk),
            VerifyMode::Full => read_chunk(path, summary, chunk).map(|_| ()),
        };

        if let Err(err) = result {
            damaged.push(ChunkStatus {
                chunk_id: chunk.chunk_id,
                valid: false,
                error: Some(err.to_string()),
            });
        }
    }
    Ok(damaged)
}

pub fn verify_signature(summary: &ParcelSummary) -> Result<()> {
    if summary.signature_block.records.is_empty() {
        return Err(SneakError::other(
            "parcel is unsigned; refusing to treat it as valid",
        ));
    }

    let manifest_plain = to_msgpack(&summary.manifest)?;
    let manifest_hash = hash(&manifest_plain);
    let chunk_merkle_root = chunk_root(&summary.manifest.chunks);
    let policy_hash = hash(&to_msgpack(&summary.manifest.policy)?);
    let log_head = [0u8; 32];
    let expected_transcript = signature_transcript(
        &summary.header.parcel_id,
        vec_to_32(&summary.footer.parcel_fingerprint, "parcel fingerprint")?,
        &manifest_hash,
        &chunk_merkle_root,
        &policy_hash,
        &log_head,
        &summary.header.created_by_pubkey,
    );

    if summary.signature_block.transcript_hash.as_slice() != expected_transcript {
        return Err(SneakError::InvalidSignature);
    }

    for record in &summary.signature_block.records {
        sign::verify(
            &record.signer_pubkey,
            &expected_transcript,
            &record.signature,
        )?;
    }

    Ok(())
}

pub fn signature_transcript(
    parcel_id: &[u8; 32],
    parcel_fingerprint: &[u8; 32],
    manifest_hash: &[u8; 32],
    chunk_merkle_root: &[u8; 32],
    policy_hash: &[u8; 32],
    log_head: &[u8; 32],
    creator_pubkey: &[u8],
) -> [u8; 32] {
    hash_many(&[
        b"sneakers:signature-transcript:v1",
        &FORMAT_VERSION.to_le_bytes(),
        parcel_id,
        parcel_fingerprint,
        manifest_hash,
        chunk_merkle_root,
        policy_hash,
        log_head,
        creator_pubkey,
    ])
}

pub fn parcel_fingerprint(
    parcel_id: &[u8; 32],
    manifest_hash: &[u8; 32],
    chunk_merkle_root: &[u8; 32],
    policy_hash: &[u8; 32],
    creator_pubkey: &[u8],
) -> [u8; 32] {
    hash_many(&[
        b"sneakers:parcel-fingerprint:v1",
        parcel_id,
        manifest_hash,
        chunk_merkle_root,
        policy_hash,
        creator_pubkey,
    ])
}

pub fn chunk_root(chunks: &[ChunkEntryV1]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sneakers:chunk-root:v1");
    for chunk in chunks {
        hasher.update(&chunk.chunk_id.to_le_bytes());
        hasher.update(&chunk.cipher_hash);
        hasher.update(&chunk.plain_hash);
    }
    *hasher.finalize().as_bytes()
}

fn verify_chunk_ciphertext(path: &Path, chunk: &ChunkEntryV1) -> Result<()> {
    let mut file = File::open(path)?;
    let payload: EncryptedChunkPayloadV1 =
        read_frame_payload_at(&mut file, chunk.frame_offset, FrameType::Chunk)?;
    if payload.chunk_id != chunk.chunk_id || payload.ciphertext.len() as u64 > chunk.stored_size {
        return Err(SneakError::ChunkCorrupt(chunk.chunk_id));
    }
    let cipher_hash = hash(&payload.ciphertext);
    if chunk.cipher_hash.as_slice() != cipher_hash {
        return Err(SneakError::ChunkCorrupt(chunk.chunk_id));
    }
    Ok(())
}

fn unlock_data_key(
    key_slots: &[KeySlotV1],
    passphrase: &str,
    parcel_id: &[u8; 32],
) -> Result<[u8; DATA_KEY_LEN]> {
    for slot in key_slots {
        if let Ok(data_key) = slot.try_unlock(passphrase, parcel_id) {
            return Ok(data_key);
        }
    }
    Err(SneakError::WrongPassphrase)
}

pub fn read_frame_payload_at<T: serde::de::DeserializeOwned>(
    file: &mut File,
    offset: u64,
    expected_type: FrameType,
) -> Result<T> {
    file.seek(SeekFrom::Start(offset))?;
    let frame = Frame::read_from(file)?;
    if frame.header.frame_type != expected_type {
        return Err(SneakError::other(format!(
            "expected frame {:?} at offset {offset}, found {:?}",
            expected_type, frame.header.frame_type
        )));
    }
    from_msgpack(&frame.payload)
}

pub fn to_msgpack<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|err| SneakError::other(format!("msgpack encode failed: {err}")))
}

pub fn from_msgpack<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes)
        .map_err(|err| SneakError::other(format!("msgpack decode failed: {err}")))
}

pub fn manifest_aad(parcel_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"sneakers:manifest:v1:".to_vec();
    aad.extend_from_slice(parcel_id);
    aad
}

pub fn chunk_aad(parcel_id: &[u8; 32], chunk_id: u64) -> Vec<u8> {
    let mut aad = b"sneakers:chunk:v1:".to_vec();
    aad.extend_from_slice(parcel_id);
    aad.extend_from_slice(&chunk_id.to_le_bytes());
    aad
}

fn vec_to_32<'a>(bytes: &'a [u8], name: &str) -> Result<&'a [u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| SneakError::other(format!("invalid {name} length")))
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedManifestPayloadV1 {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub plaintext_hash: Vec<u8>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedChunkPayloadV1 {
    pub chunk_id: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

struct SourceTree {
    files: Vec<SourceFile>,
    directories: Vec<DirectoryEntryV1>,
    symlinks: Vec<manifest::SymlinkEntryV1>,
}

struct SourceFile {
    absolute_path: PathBuf,
    entry: FileEntryV1,
}

fn collect_source(src: &Path) -> Result<SourceTree> {
    let src = fs::canonicalize(src)?;
    let base = if src.is_file() {
        src.parent().unwrap_or_else(|| Path::new("/")).to_path_buf()
    } else {
        src.clone()
    };
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut symlinks = Vec::new();
    let mut seen_dirs = HashSet::new();

    for entry in WalkDir::new(&src).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|err| SneakError::other(format!("walk failed: {err}")))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(path)?;
        let rel = path
            .strip_prefix(&base)
            .map_err(|_| SneakError::UnsafePath(path.display().to_string()))?;
        let rel_string = normalize_relpath(rel)?;

        if metadata.is_dir() {
            if !rel_string.is_empty() && seen_dirs.insert(rel_string.clone()) {
                directories.push(DirectoryEntryV1::from_metadata(rel_string, &metadata));
            }
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            symlinks.push(manifest::SymlinkEntryV1::from_metadata(
                rel_string,
                target.to_string_lossy().into_owned(),
                &metadata,
            ));
        } else if metadata.is_file() {
            files.push(SourceFile {
                absolute_path: path.to_path_buf(),
                entry: FileEntryV1::from_metadata(0, rel_string, &metadata),
            });
        }
    }

    if files.is_empty() && symlinks.is_empty() {
        return Err(SneakError::other("source contains no regular files"));
    }

    Ok(SourceTree {
        files,
        directories,
        symlinks,
    })
}

fn normalize_relpath(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            std::path::Component::CurDir => {}
            _ => return Err(SneakError::UnsafePath(path.display().to_string())),
        }
    }
    Ok(parts.join("/"))
}
