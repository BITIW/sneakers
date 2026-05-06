use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{Result, SneakError};

pub const APP_NAME: &str = "sneakers";

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

pub fn config_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("SNEAKERS_CONFIG_DIR") {
        return Ok(PathBuf::from(path));
    }

    if let Ok(path) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join(APP_NAME));
    }

    let home = env::var("HOME")
        .map_err(|_| SneakError::other("HOME is not set; use SNEAKERS_CONFIG_DIR"))?;
    Ok(PathBuf::from(home).join(".config").join(APP_NAME))
}

pub fn data_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("SNEAKERS_DATA_DIR") {
        return Ok(PathBuf::from(path));
    }

    if let Ok(path) = env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join(APP_NAME));
    }

    let home = env::var("HOME")
        .map_err(|_| SneakError::other("HOME is not set; use SNEAKERS_DATA_DIR"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join(APP_NAME))
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;

    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn short_hex(bytes: &[u8]) -> String {
    hex::encode(bytes).chars().take(16).collect()
}

pub fn format_unix_time_utc(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let seconds = timestamp % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;

    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC (unix {timestamp})"
    )
}

pub fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else if ch.is_whitespace() {
            out.push('_');
        }
    }

    if out.is_empty() {
        "identity".to_string()
    } else {
        out
    }
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };

    (year as i32, month as u32, day as u32)
}
