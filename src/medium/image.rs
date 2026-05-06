use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::errors::{Result, SneakError};
use crate::medium::{BackendCaps, MediumBackend, MediumInfo, MediumState};
use crate::parcel::footer::ParcelFooterV1;
use crate::parcel::frame::FrameType;
use crate::parcel::header::ParcelHeader;
use crate::parcel::read_frame_payload_at;

#[derive(Clone, Debug)]
pub struct ImageBackend {
    path: PathBuf,
}

impl ImageBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl MediumBackend for ImageBackend {
    fn probe(&self) -> Result<MediumInfo> {
        probe_parcel_path(&self.path, "image")
    }

    fn read_parcel(&self) -> Result<Box<dyn Read>> {
        Ok(Box::new(File::open(&self.path)?))
    }

    fn write_parcel(&self, source: &mut dyn Read) -> Result<()> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let mut target = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.path)?;
        std::io::copy(source, &mut target)?;
        Ok(())
    }

    fn reclaim(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps::READ | BackendCaps::WRITE | BackendCaps::EXTRACT | BackendCaps::RECLAIM
    }
}

pub fn probe_parcel_path(path: &Path, backend: &str) -> Result<MediumInfo> {
    if !path.exists() {
        return Ok(MediumInfo {
            backend: backend.to_string(),
            path: path.to_path_buf(),
            state: MediumState::Available,
            size: None,
            model: None,
            serial: None,
            partitions: Vec::new(),
            parcel_id: None,
            parcel_fingerprint: None,
        });
    }

    let size = fs::metadata(path).ok().map(|metadata| metadata.len());
    let mut file = File::open(path)?;
    let header = match ParcelHeader::read_from(&mut file) {
        Ok(header) => header,
        Err(SneakError::InvalidMagic) => {
            return Ok(MediumInfo {
                backend: backend.to_string(),
                path: path.to_path_buf(),
                state: MediumState::NonSneakersData,
                size,
                model: None,
                serial: None,
                partitions: Vec::new(),
                parcel_id: None,
                parcel_fingerprint: None,
            });
        }
        Err(_) => {
            return Ok(MediumInfo {
                backend: backend.to_string(),
                path: path.to_path_buf(),
                state: MediumState::CorruptSneakersParcel,
                size,
                model: None,
                serial: None,
                partitions: Vec::new(),
                parcel_id: None,
                parcel_fingerprint: None,
            });
        }
    };

    let footer = read_footer(&mut file, &header).ok();
    let state = footer
        .as_ref()
        .map(|_| MediumState::Sealed)
        .unwrap_or(MediumState::InterruptedWrite);

    Ok(MediumInfo {
        backend: backend.to_string(),
        path: path.to_path_buf(),
        state,
        size,
        model: None,
        serial: None,
        partitions: Vec::new(),
        parcel_id: Some(header.parcel_id.to_vec()),
        parcel_fingerprint: footer.map(|footer| footer.parcel_fingerprint),
    })
}

fn read_footer(file: &mut File, header: &ParcelHeader) -> Result<ParcelFooterV1> {
    file.seek(SeekFrom::Start(header.footer_offset))?;
    read_frame_payload_at(file, header.footer_offset, FrameType::Footer)
}
