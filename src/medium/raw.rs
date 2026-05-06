use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::errors::{Result, SneakError};
use crate::medium::image::probe_parcel_path;
use crate::medium::{BackendCaps, MediumBackend, MediumInfo, MediumState};
use crate::parcel::header::{FIXED_HEADER_LEN, MAGIC};

#[derive(Clone, Debug)]
pub struct RawBlockBackend {
    path: PathBuf,
}

impl RawBlockBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn write_parcel_file(&self, parcel: &Path) -> Result<()> {
        ensure_raw_write_safe(&self.path)?;
        let source_len = fs::metadata(parcel)?.len();
        let device_size = block_size(&self.path)?;
        if source_len > device_size {
            return Err(SneakError::NotEnoughSpace);
        }

        let mut source = File::open(parcel)?;
        self.write_stream_after_safety_checks(&mut source)
    }

    fn write_stream_after_safety_checks(&self, source: &mut dyn Read) -> Result<()> {
        let mut target = OpenOptions::new().read(true).write(true).open(&self.path)?;
        target.seek(SeekFrom::Start(0))?;
        std::io::copy(source, &mut target)?;
        target.flush()?;
        target.seek(SeekFrom::Start(0))?;
        let mut magic = vec![0u8; MAGIC.len()];
        target.read_exact(&mut magic)?;
        if magic.as_slice() != MAGIC {
            return Err(SneakError::InterruptedWrite);
        }
        Ok(())
    }
}

impl MediumBackend for RawBlockBackend {
    fn probe(&self) -> Result<MediumInfo> {
        let mut info = probe_parcel_path(&self.path, "raw")?;
        info.size = block_size(&self.path).ok().or(info.size);
        info.model = block_attr(&self.path, "device/model");
        info.serial = block_attr(&self.path, "device/serial");
        info.partitions = partitions(&self.path);
        if info.state == MediumState::NonSneakersData {
            info.state = MediumState::NoSneakersParcel;
        }
        Ok(info)
    }

    fn read_parcel(&self) -> Result<Box<dyn Read>> {
        Ok(Box::new(File::open(&self.path)?))
    }

    fn write_parcel(&self, source: &mut dyn Read) -> Result<()> {
        ensure_raw_write_safe(&self.path)?;
        self.write_stream_after_safety_checks(source)
    }

    fn reclaim(&self) -> Result<()> {
        ensure_raw_write_safe(&self.path)?;
        let mut target = OpenOptions::new().read(true).write(true).open(&self.path)?;
        target.seek(SeekFrom::Start(0))?;
        target.write_all(&vec![0u8; FIXED_HEADER_LEN])?;
        target.flush()?;
        Ok(())
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps::READ
            | BackendCaps::WRITE
            | BackendCaps::EXTRACT
            | BackendCaps::RAW_DEVICE
            | BackendCaps::RECLAIM
            | BackendCaps::SEQUENTIAL
    }
}

#[cfg(unix)]
pub fn looks_like_raw_device(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    fs::metadata(path)
        .map(|metadata| metadata.file_type().is_block_device())
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn looks_like_raw_device(_path: &Path) -> bool {
    false
}

pub fn list_raw_devices() -> Result<Vec<MediumInfo>> {
    let mut out = Vec::new();
    let sys_block = Path::new("/sys/class/block");
    if !sys_block.exists() {
        return Ok(out);
    }

    for entry in fs::read_dir(sys_block)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_partition_name(&name) {
            continue;
        }
        let dev = PathBuf::from("/dev").join(&name);
        if dev.exists() {
            let backend = RawBlockBackend::new(dev);
            if let Ok(info) = backend.probe() {
                out.push(info);
            }
        }
    }
    out.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(out)
}

fn ensure_raw_write_safe(path: &Path) -> Result<()> {
    if is_mounted(path)? {
        return Err(SneakError::MediumMounted);
    }
    Ok(())
}

fn is_mounted(path: &Path) -> Result<bool> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let path_str = canonical.to_string_lossy();
    for line in mounts.lines() {
        if line.contains(path_str.as_ref()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn block_size(path: &Path) -> Result<u64> {
    let name = block_name(path)?;
    let sectors = read_trimmed(Path::new("/sys/class/block").join(name).join("size"))?;
    let sectors: u64 = sectors
        .parse()
        .map_err(|_| SneakError::other("invalid sysfs block size"))?;
    Ok(sectors * 512)
}

fn block_attr(path: &Path, attr: &str) -> Option<String> {
    let name = block_name(path).ok()?;
    read_trimmed(Path::new("/sys/class/block").join(name).join(attr)).ok()
}

fn partitions(path: &Path) -> Vec<String> {
    let Ok(name) = block_name(path) else {
        return Vec::new();
    };
    let root = Path::new("/sys/class/block").join(&name);
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let filename = entry.file_name().to_string_lossy().into_owned();
        if filename != name && filename.starts_with(&name) {
            out.push(format!("/dev/{filename}"));
        }
    }
    out.sort();
    out
}

fn block_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .ok_or_else(|| SneakError::other(format!("invalid block path '{}'", path.display())))
}

fn read_trimmed(path: impl AsRef<Path>) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn is_partition_name(name: &str) -> bool {
    let last_is_digit = name
        .as_bytes()
        .last()
        .map(|last| last.is_ascii_digit())
        .unwrap_or(false);

    if !last_is_digit {
        return false;
    }

    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        return name
            .rsplit_once('p')
            .map(|(_, tail)| tail.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false);
    }

    name.starts_with("sd") || name.starts_with("vd") || name.starts_with("xvd")
}
