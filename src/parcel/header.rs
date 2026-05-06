use std::io::{Read, Write};

use crate::crypto::hash::hash;
use crate::errors::{Result, SneakError};

pub const MAGIC: &[u8; 12] = b"SNEAKPARCEL\0";
pub const FIXED_HEADER_LEN: usize = 256;
const HEADER_HASH_OFFSET: usize = 138;

#[derive(Clone, Debug)]
pub struct ParcelHeader {
    pub format_version: u16,
    pub header_len: u32,
    pub flags: u32,
    pub parcel_id: [u8; 32],
    pub crypto_suite: u16,
    pub created_by_pubkey: Vec<u8>,
    pub key_slot_count: u16,
    pub key_slots_offset: u64,
    pub manifest_offset: u64,
    pub chunk_stream_offset: u64,
    pub signature_offset: u64,
    pub log_offset: u64,
    pub footer_offset: u64,
    pub header_hash: [u8; 32],
}

impl ParcelHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parcel_id: [u8; 32],
        created_by_pubkey: Vec<u8>,
        key_slot_count: u16,
        key_slots_offset: u64,
        manifest_offset: u64,
        chunk_stream_offset: u64,
        signature_offset: u64,
        log_offset: u64,
        footer_offset: u64,
    ) -> Self {
        let mut created = created_by_pubkey;
        created.resize(32, 0);
        created.truncate(32);
        let mut header = Self {
            format_version: 1,
            header_len: FIXED_HEADER_LEN as u32,
            flags: 0,
            parcel_id,
            crypto_suite: 1,
            created_by_pubkey: created,
            key_slot_count,
            key_slots_offset,
            manifest_offset,
            chunk_stream_offset,
            signature_offset,
            log_offset,
            footer_offset,
            header_hash: [0u8; 32],
        };
        header.header_hash = header.compute_hash();
        header
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let mut bytes = [0u8; FIXED_HEADER_LEN];
        reader.read_exact(&mut bytes)?;
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(SneakError::InvalidMagic);
        }

        let mut cursor = MAGIC.len();
        let format_version = read_u16(&bytes, &mut cursor);
        let header_len = read_u32(&bytes, &mut cursor);
        if header_len as usize != FIXED_HEADER_LEN {
            return Err(SneakError::other(format!(
                "unsupported header length {header_len}"
            )));
        }
        let flags = read_u32(&bytes, &mut cursor);
        let parcel_id = read_array::<32>(&bytes, &mut cursor);
        let crypto_suite = read_u16(&bytes, &mut cursor);
        let created_by_pubkey = read_array::<32>(&bytes, &mut cursor).to_vec();
        let key_slot_count = read_u16(&bytes, &mut cursor);
        let key_slots_offset = read_u64(&bytes, &mut cursor);
        let manifest_offset = read_u64(&bytes, &mut cursor);
        let chunk_stream_offset = read_u64(&bytes, &mut cursor);
        let signature_offset = read_u64(&bytes, &mut cursor);
        let log_offset = read_u64(&bytes, &mut cursor);
        let footer_offset = read_u64(&bytes, &mut cursor);
        let header_hash = read_array::<32>(&bytes, &mut cursor);

        let header = Self {
            format_version,
            header_len,
            flags,
            parcel_id,
            crypto_suite,
            created_by_pubkey,
            key_slot_count,
            key_slots_offset,
            manifest_offset,
            chunk_stream_offset,
            signature_offset,
            log_offset,
            footer_offset,
            header_hash,
        };
        if header.compute_hash() != header.header_hash {
            return Err(SneakError::other("header hash mismatch"));
        }
        Ok(header)
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        let mut bytes = [0u8; FIXED_HEADER_LEN];
        let mut cursor = 0usize;
        bytes[cursor..cursor + MAGIC.len()].copy_from_slice(MAGIC);
        cursor += MAGIC.len();
        write_u16(&mut bytes, &mut cursor, self.format_version);
        write_u32(&mut bytes, &mut cursor, self.header_len);
        write_u32(&mut bytes, &mut cursor, self.flags);
        write_bytes(&mut bytes, &mut cursor, &self.parcel_id);
        write_u16(&mut bytes, &mut cursor, self.crypto_suite);
        let mut pubkey = self.created_by_pubkey.clone();
        pubkey.resize(32, 0);
        write_bytes(&mut bytes, &mut cursor, &pubkey[..32]);
        write_u16(&mut bytes, &mut cursor, self.key_slot_count);
        write_u64(&mut bytes, &mut cursor, self.key_slots_offset);
        write_u64(&mut bytes, &mut cursor, self.manifest_offset);
        write_u64(&mut bytes, &mut cursor, self.chunk_stream_offset);
        write_u64(&mut bytes, &mut cursor, self.signature_offset);
        write_u64(&mut bytes, &mut cursor, self.log_offset);
        write_u64(&mut bytes, &mut cursor, self.footer_offset);
        write_bytes(&mut bytes, &mut cursor, &self.header_hash);
        writer.write_all(&bytes)?;
        Ok(())
    }

    fn compute_hash(&self) -> [u8; 32] {
        let mut bytes = [0u8; FIXED_HEADER_LEN];
        let mut cursor = 0usize;
        bytes[cursor..cursor + MAGIC.len()].copy_from_slice(MAGIC);
        cursor += MAGIC.len();
        write_u16(&mut bytes, &mut cursor, self.format_version);
        write_u32(&mut bytes, &mut cursor, self.header_len);
        write_u32(&mut bytes, &mut cursor, self.flags);
        write_bytes(&mut bytes, &mut cursor, &self.parcel_id);
        write_u16(&mut bytes, &mut cursor, self.crypto_suite);
        let mut pubkey = self.created_by_pubkey.clone();
        pubkey.resize(32, 0);
        write_bytes(&mut bytes, &mut cursor, &pubkey[..32]);
        write_u16(&mut bytes, &mut cursor, self.key_slot_count);
        write_u64(&mut bytes, &mut cursor, self.key_slots_offset);
        write_u64(&mut bytes, &mut cursor, self.manifest_offset);
        write_u64(&mut bytes, &mut cursor, self.chunk_stream_offset);
        write_u64(&mut bytes, &mut cursor, self.signature_offset);
        write_u64(&mut bytes, &mut cursor, self.log_offset);
        write_u64(&mut bytes, &mut cursor, self.footer_offset);
        debug_assert_eq!(cursor, HEADER_HASH_OFFSET);
        hash(&bytes)
    }
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    out
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
    u16::from_le_bytes(read_array(bytes, cursor))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
    u32::from_le_bytes(read_array(bytes, cursor))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    u64::from_le_bytes(read_array(bytes, cursor))
}

fn write_bytes(bytes: &mut [u8], cursor: &mut usize, value: &[u8]) {
    bytes[*cursor..*cursor + value.len()].copy_from_slice(value);
    *cursor += value.len();
}

fn write_u16(bytes: &mut [u8], cursor: &mut usize, value: u16) {
    write_bytes(bytes, cursor, &value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], cursor: &mut usize, value: u32) {
    write_bytes(bytes, cursor, &value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], cursor: &mut usize, value: u64) {
    write_bytes(bytes, cursor, &value.to_le_bytes());
}
