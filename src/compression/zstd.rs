use std::io::Write;

use crate::compression::CompressionKind;
use crate::errors::{Result, SneakError};

pub fn compress(
    kind: CompressionKind,
    level: i32,
    threads: Option<usize>,
    data: &[u8],
) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::None => Ok(data.to_vec()),
        CompressionKind::Zstd => {
            if let Some(threads) = threads.filter(|threads| *threads > 0) {
                let mut encoder = zstd::stream::Encoder::new(Vec::new(), level)
                    .map_err(|err| SneakError::other(format!("zstd encoder failed: {err}")))?;
                encoder
                    .multithread(threads as u32)
                    .map_err(|err| SneakError::other(format!("zstd multithread failed: {err}")))?;
                encoder
                    .write_all(data)
                    .map_err(|err| SneakError::other(format!("zstd write failed: {err}")))?;
                encoder
                    .finish()
                    .map_err(|err| SneakError::other(format!("zstd finish failed: {err}")))
            } else {
                zstd::bulk::compress(data, level)
                    .map_err(|err| SneakError::other(format!("zstd compress failed: {err}")))
            }
        }
    }
}

pub fn decompress(kind: CompressionKind, expected_size: u64, data: &[u8]) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::None => Ok(data.to_vec()),
        CompressionKind::Zstd => zstd::bulk::decompress(data, expected_size as usize)
            .map_err(|err| SneakError::other(format!("zstd decompress failed: {err}"))),
    }
}
