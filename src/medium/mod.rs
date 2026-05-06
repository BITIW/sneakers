pub mod fs_fallback;
pub mod image;
pub mod raw;

use std::io::Read;
use std::path::{Path, PathBuf};

use bitflags::bitflags;

use crate::errors::Result;

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediumState {
    Available,
    Writing,
    Sealed,
    Extracted,
    InterruptedWrite,
    CorruptSneakersParcel,
    NoSneakersParcel,
    NonSneakersData,
}

impl MediumState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Writing => "Writing",
            Self::Sealed => "Sealed",
            Self::Extracted => "Extracted",
            Self::InterruptedWrite => "InterruptedWrite",
            Self::CorruptSneakersParcel => "CorruptSneakersParcel",
            Self::NoSneakersParcel => "NoSneakersParcel",
            Self::NonSneakersData => "NonSneakersData",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MediumInfo {
    pub backend: String,
    pub path: PathBuf,
    pub state: MediumState,
    pub size: Option<u64>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub partitions: Vec<String>,
    pub parcel_id: Option<Vec<u8>>,
    pub parcel_fingerprint: Option<Vec<u8>>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct BackendCaps: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXTRACT = 1 << 2;
        const RAW_DEVICE = 1 << 3;
        const FS_FALLBACK = 1 << 4;
        const RECLAIM = 1 << 5;
        const SEQUENTIAL = 1 << 6;
    }
}

#[allow(dead_code)]
pub trait MediumBackend {
    fn probe(&self) -> Result<MediumInfo>;
    fn read_parcel(&self) -> Result<Box<dyn Read>>;
    fn write_parcel(&self, source: &mut dyn Read) -> Result<()>;
    fn reclaim(&self) -> Result<()>;
    fn capabilities(&self) -> BackendCaps;
}

pub fn backend_for(path: &Path) -> Box<dyn MediumBackend> {
    if fs_fallback::looks_like_fs_fallback(path) {
        Box::new(fs_fallback::FsFallbackBackend::new(path.to_path_buf()))
    } else if raw::looks_like_raw_device(path) {
        Box::new(raw::RawBlockBackend::new(path.to_path_buf()))
    } else {
        Box::new(image::ImageBackend::new(path.to_path_buf()))
    }
}

pub fn inspect(path: &Path) -> Result<MediumInfo> {
    backend_for(path).probe()
}

pub fn burn(parcel: &Path, target: &Path) -> Result<MediumInfo> {
    if raw::looks_like_raw_device(target) {
        let backend = raw::RawBlockBackend::new(target.to_path_buf());
        backend.write_parcel_file(parcel)?;
        return backend.probe();
    }

    let mut source = std::fs::File::open(parcel)?;
    let backend = backend_for(target);
    backend.write_parcel(&mut source)?;
    backend.probe()
}

pub fn reclaim(path: &Path) -> Result<MediumInfo> {
    let backend = backend_for(path);
    backend.reclaim()?;
    backend.probe()
}

pub fn list_raw_devices() -> Result<Vec<MediumInfo>> {
    raw::list_raw_devices()
}
