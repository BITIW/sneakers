use std::io::{Read, Write};

use crate::crypto::hash::hash_many;
use crate::errors::{Result, SneakError};

pub const FRAME_MAGIC: &[u8; 8] = b"SNFRAME\0";
pub const FRAME_HEADER_LEN: usize = 92;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[repr(u16)]
pub enum FrameType {
    HeaderExt = 1,
    KeySlots = 2,
    EncryptedManifest = 3,
    Chunk = 4,
    SignatureBlock = 5,
    LogRecord = 6,
    Footer = 7,
}

impl TryFrom<u16> for FrameType {
    type Error = SneakError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::HeaderExt),
            2 => Ok(Self::KeySlots),
            3 => Ok(Self::EncryptedManifest),
            4 => Ok(Self::Chunk),
            5 => Ok(Self::SignatureBlock),
            6 => Ok(Self::LogRecord),
            7 => Ok(Self::Footer),
            other => Err(SneakError::other(format!("unknown frame type {other}"))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FrameHeader {
    pub frame_type: FrameType,
    pub frame_version: u16,
    pub sequence_number: u64,
    pub payload_len: u64,
    pub payload_hash: [u8; 32],
    pub previous_frame_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(
        frame_type: FrameType,
        sequence_number: u64,
        previous_frame_hash: [u8; 32],
        payload: Vec<u8>,
    ) -> Self {
        let payload_hash = *blake3::hash(&payload).as_bytes();
        Self {
            header: FrameHeader {
                frame_type,
                frame_version: 1,
                sequence_number,
                payload_len: payload.len() as u64,
                payload_hash,
                previous_frame_hash,
            },
            payload,
        }
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let header = FrameHeader::read_from(reader)?;
        let mut payload = vec![0u8; header.payload_len as usize];
        reader.read_exact(&mut payload)?;
        if *blake3::hash(&payload).as_bytes() != header.payload_hash {
            return Err(SneakError::other(format!(
                "payload hash mismatch in frame {}",
                header.sequence_number
            )));
        }
        Ok(Self { header, payload })
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        self.header.write_to(writer)?;
        writer.write_all(&self.payload)?;
        Ok(())
    }

    pub fn frame_hash(&self) -> [u8; 32] {
        let header_bytes = self.header.to_bytes();
        hash_many(&[b"sneakers:frame-hash:v1", &header_bytes, &self.payload])
    }
}

impl FrameHeader {
    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let mut bytes = [0u8; FRAME_HEADER_LEN];
        reader.read_exact(&mut bytes)?;
        if &bytes[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err(SneakError::other("invalid frame magic"));
        }

        let mut cursor = FRAME_MAGIC.len();
        let frame_type = FrameType::try_from(read_u16(&bytes, &mut cursor))?;
        let frame_version = read_u16(&bytes, &mut cursor);
        let sequence_number = read_u64(&bytes, &mut cursor);
        let payload_len = read_u64(&bytes, &mut cursor);
        let payload_hash = read_array::<32>(&bytes, &mut cursor);
        let previous_frame_hash = read_array::<32>(&bytes, &mut cursor);

        Ok(Self {
            frame_type,
            frame_version,
            sequence_number,
            payload_len,
            payload_hash,
            previous_frame_hash,
        })
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0u8; FRAME_HEADER_LEN];
        let mut cursor = 0usize;
        bytes[cursor..cursor + FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
        cursor += FRAME_MAGIC.len();
        write_u16(&mut bytes, &mut cursor, self.frame_type as u16);
        write_u16(&mut bytes, &mut cursor, self.frame_version);
        write_u64(&mut bytes, &mut cursor, self.sequence_number);
        write_u64(&mut bytes, &mut cursor, self.payload_len);
        write_bytes(&mut bytes, &mut cursor, &self.payload_hash);
        write_bytes(&mut bytes, &mut cursor, &self.previous_frame_hash);
        bytes
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

fn write_u64(bytes: &mut [u8], cursor: &mut usize, value: u64) {
    write_bytes(bytes, cursor, &value.to_le_bytes());
}
