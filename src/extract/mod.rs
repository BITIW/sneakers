use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use filetime::{FileTime, set_file_mtime};

use crate::errors::{Result, SneakError};
use crate::identity;
use crate::parcel::manifest::{ChunkEntryV1, FileEntryV1};
use crate::parcel::{self, VerifyMode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtractPolicy {
    Strict,
    Safe,
    Partial,
}

impl ExtractPolicy {
    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "strict" => Ok(Self::Strict),
            "safe" => Ok(Self::Safe),
            "partial" => Ok(Self::Partial),
            other => Err(SneakError::other(format!(
                "unknown extract policy '{other}', expected strict|safe|partial"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverwritePolicy {
    Never,
    Overwrite,
    RenameConflicts,
}

impl OverwritePolicy {
    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "never" => Ok(Self::Never),
            "overwrite" => Ok(Self::Overwrite),
            "rename-conflicts" => Ok(Self::RenameConflicts),
            other => Err(SneakError::other(format!(
                "unknown overwrite policy '{other}', expected never|overwrite|rename-conflicts"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExtractOptions {
    pub parcel_path: PathBuf,
    pub dst: PathBuf,
    pub passphrase: String,
    pub policy: ExtractPolicy,
    pub overwrite: OverwritePolicy,
}

#[derive(Clone, Debug)]
pub struct ExtractReport {
    pub files_total: usize,
    pub files_extracted: usize,
    pub files_skipped: usize,
    pub damaged_chunks: usize,
}

pub fn extract(options: ExtractOptions) -> Result<ExtractReport> {
    let summary = parcel::open(&options.parcel_path, &options.passphrase)?;
    parcel::verify_signature(&summary)?;
    let damaged = parcel::verify_chunks(&options.parcel_path, &summary, VerifyMode::Full)?;
    if options.policy == ExtractPolicy::Strict && !damaged.is_empty() {
        return Err(SneakError::other(format!(
            "strict extract refused: {} damaged chunks",
            damaged.len()
        )));
    }

    fs::create_dir_all(&options.dst)?;
    let damaged_ids: HashSet<u64> = damaged.iter().map(|chunk| chunk.chunk_id).collect();
    let chunks_by_id: HashMap<u64, &ChunkEntryV1> = summary
        .manifest
        .chunks
        .iter()
        .map(|chunk| (chunk.chunk_id, chunk))
        .collect();
    let mut files_extracted = 0usize;
    let mut files_skipped = 0usize;

    for dir in &summary.manifest.directories {
        let target = safe_join(&options.dst, &dir.path)?;
        fs::create_dir_all(&target)?;
        apply_dir_mode(&target, dir.mode)?;
    }

    for symlink in &summary.manifest.symlinks {
        let target = safe_join(&options.dst, &symlink.path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        create_symlink(&symlink.target, &target, options.overwrite)?;
    }

    for file in &summary.manifest.files {
        let file_damaged = file
            .chunks
            .iter()
            .any(|chunk_id| damaged_ids.contains(chunk_id));
        match (options.policy, file_damaged) {
            (ExtractPolicy::Safe, true) => {
                files_skipped += 1;
                continue;
            }
            _ => {}
        }

        let mut target = safe_join(&options.dst, &file.path)?;
        if options.policy == ExtractPolicy::Partial && file_damaged {
            target = target.with_extension(partial_extension(&target));
        }
        target = resolve_conflict(&target, options.overwrite)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        write_file(
            &options.parcel_path,
            &summary,
            file,
            &chunks_by_id,
            &damaged_ids,
            &target,
            options.policy,
        )?;
        apply_file_metadata(&target, file)?;
        files_extracted += 1;
    }

    identity::record_seen(
        &summary.header.parcel_id,
        &summary.footer.parcel_fingerprint,
        &summary.header.created_by_pubkey,
        true,
        None,
    )?;

    Ok(ExtractReport {
        files_total: summary.manifest.files.len(),
        files_extracted,
        files_skipped,
        damaged_chunks: damaged.len(),
    })
}

fn write_file(
    parcel_path: &Path,
    summary: &parcel::ParcelSummary,
    file_entry: &FileEntryV1,
    chunks_by_id: &HashMap<u64, &ChunkEntryV1>,
    damaged_ids: &HashSet<u64>,
    target: &Path,
    policy: ExtractPolicy,
) -> Result<()> {
    let mut out = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(target)?;

    for chunk_id in &file_entry.chunks {
        let chunk = chunks_by_id
            .get(chunk_id)
            .ok_or_else(|| SneakError::ChunkCorrupt(*chunk_id))?;
        if damaged_ids.contains(chunk_id) {
            if policy == ExtractPolicy::Partial {
                out.seek(SeekFrom::Start(chunk.plain_offset + chunk.plain_size))?;
                continue;
            }
            return Err(SneakError::ChunkCorrupt(*chunk_id));
        }
        let plain = parcel::read_chunk(parcel_path, summary, chunk)?;
        out.seek(SeekFrom::Start(chunk.plain_offset))?;
        out.write_all(&plain)?;
    }
    out.flush()?;
    Ok(())
}

fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return Err(SneakError::UnsafePath(rel.to_string()));
    }
    let mut out = base.to_path_buf();
    for component in rel_path.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => return Err(SneakError::UnsafePath(rel.to_string())),
        }
    }
    Ok(out)
}

fn resolve_conflict(path: &Path, policy: OverwritePolicy) -> Result<PathBuf> {
    if !path.exists() {
        return Ok(path.to_path_buf());
    }

    match policy {
        OverwritePolicy::Never => Err(SneakError::other(format!(
            "destination exists: {}",
            path.display()
        ))),
        OverwritePolicy::Overwrite => Ok(path.to_path_buf()),
        OverwritePolicy::RenameConflicts => {
            let parent = path.parent().unwrap_or_else(|| Path::new(""));
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("file");
            let ext = path.extension().and_then(|ext| ext.to_str());
            for index in 1..10000 {
                let filename = match ext {
                    Some(ext) => format!("{stem}.sneakers-{index}.{ext}"),
                    None => format!("{stem}.sneakers-{index}"),
                };
                let candidate = parent.join(filename);
                if !candidate.exists() {
                    return Ok(candidate);
                }
            }
            Err(SneakError::other("too many destination conflicts"))
        }
    }
}

fn partial_extension(path: &Path) -> String {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => format!("{ext}.partial"),
        None => "partial".to_string(),
    }
}

fn apply_file_metadata(path: &Path, file: &FileEntryV1) -> Result<()> {
    set_file_mtime(path, FileTime::from_unix_time(file.mtime as i64, 0))?;
    apply_file_mode(path, file.mode)?;
    Ok(())
}

#[cfg(unix)]
fn apply_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn apply_dir_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_dir_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path, overwrite: OverwritePolicy) -> Result<()> {
    use std::os::unix::fs::symlink;

    if link.exists() {
        match overwrite {
            OverwritePolicy::Never => {
                return Err(SneakError::other(format!(
                    "destination exists: {}",
                    link.display()
                )));
            }
            OverwritePolicy::Overwrite => fs::remove_file(link)?,
            OverwritePolicy::RenameConflicts => return Ok(()),
        }
    }
    symlink(target, link)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, _link: &Path, _overwrite: OverwritePolicy) -> Result<()> {
    Ok(())
}
