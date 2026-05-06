use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::errors::Result;
use crate::medium::image::probe_parcel_path;
use crate::medium::{BackendCaps, MediumBackend, MediumInfo};

const DIR_NAME: &str = ".sneakers";
const PARCEL_NAME: &str = "parcel.sparcel";
const STATE_NAME: &str = "medium.msgpack";
const LOCK_NAME: &str = "state.lock";

#[derive(Clone, Debug)]
pub struct FsFallbackBackend {
    root: PathBuf,
}

impl FsFallbackBackend {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn parcel_path(&self) -> PathBuf {
        self.root.join(DIR_NAME).join(PARCEL_NAME)
    }
}

impl MediumBackend for FsFallbackBackend {
    fn probe(&self) -> Result<MediumInfo> {
        let mut info = probe_parcel_path(&self.parcel_path(), "fs-fallback")?;
        info.path = self.root.clone();
        Ok(info)
    }

    fn read_parcel(&self) -> Result<Box<dyn Read>> {
        Ok(Box::new(fs::File::open(self.parcel_path())?))
    }

    fn write_parcel(&self, source: &mut dyn Read) -> Result<()> {
        let dir = self.root.join(DIR_NAME);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(LOCK_NAME), b"writing\n")?;
        let mut target = fs::File::create(self.parcel_path())?;
        std::io::copy(source, &mut target)?;
        fs::write(dir.join(STATE_NAME), b"sealed\n")?;
        let _ = fs::remove_file(dir.join(LOCK_NAME));
        Ok(())
    }

    fn reclaim(&self) -> Result<()> {
        let dir = self.root.join(DIR_NAME);
        let _ = fs::remove_file(dir.join(PARCEL_NAME));
        let _ = fs::remove_file(dir.join(STATE_NAME));
        let _ = fs::remove_file(dir.join(LOCK_NAME));
        Ok(())
    }

    fn capabilities(&self) -> BackendCaps {
        BackendCaps::READ
            | BackendCaps::WRITE
            | BackendCaps::EXTRACT
            | BackendCaps::FS_FALLBACK
            | BackendCaps::RECLAIM
    }
}

pub fn looks_like_fs_fallback(path: &Path) -> bool {
    path.is_dir() || path.join(DIR_NAME).exists()
}
