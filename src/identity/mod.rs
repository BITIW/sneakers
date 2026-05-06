use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;

use crate::core::{config_dir, data_dir, now_unix, sanitize_name};
use crate::crypto::{hash, sign};
use crate::errors::{Result, SneakError};
use crate::parcel::{from_msgpack, to_msgpack};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Identity {
    pub name: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub created_at: u64,
    pub local_counter: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicIdentity {
    pub name: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub exported_at: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TrustedKey {
    pub pubkey: Vec<u8>,
    pub name: String,
    pub fingerprint: String,
    pub trust_level: String,
    pub first_seen: u64,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
}

#[derive(Clone, Debug)]
pub struct IdentityStore {
    root: PathBuf,
}

impl IdentityStore {
    pub fn open() -> Result<Self> {
        let root = config_dir()?;
        fs::create_dir_all(root.join("identities"))?;
        Ok(Self { root })
    }

    pub fn create(&self, name: &str, overwrite: bool) -> Result<Identity> {
        let path = self.identity_path(name);
        if path.exists() && !overwrite {
            return Err(SneakError::other(format!(
                "identity '{name}' already exists; use --force to replace"
            )));
        }

        let signing_key = sign::generate_signing_key();
        let identity = Identity {
            name: name.to_string(),
            public_key: sign::public_key_bytes(&signing_key),
            secret_key: signing_key.to_bytes().to_vec(),
            created_at: now_unix(),
            local_counter: 0,
        };
        write_private_file(&path, &to_msgpack(&identity)?)?;
        self.trust_public_key(&identity.name, &identity.public_key, "ultimate", None)?;
        Ok(identity)
    }

    pub fn load(&self, name: &str) -> Result<Identity> {
        let path = self.identity_path(name);
        let bytes = fs::read(&path).map_err(|err| {
            SneakError::other(format!(
                "failed to read identity '{}': {err}",
                path.display()
            ))
        })?;
        from_msgpack(&bytes)
    }

    pub fn list(&self) -> Result<Vec<Identity>> {
        let mut identities = Vec::new();
        let dir = self.root.join("identities");
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let bytes = fs::read(entry.path())?;
                if let Ok(identity) = from_msgpack::<Identity>(&bytes) {
                    identities.push(identity);
                }
            }
        }
        identities.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(identities)
    }

    pub fn default_identity(&self) -> Result<Option<Identity>> {
        let identities = self.list()?;
        Ok(identities.into_iter().next())
    }

    pub fn export_public(&self, name: &str) -> Result<PublicIdentity> {
        let identity = self.load(name)?;
        Ok(PublicIdentity {
            name: identity.name,
            fingerprint: fingerprint(&identity.public_key),
            public_key: identity.public_key,
            exported_at: now_unix(),
        })
    }

    pub fn import_trust_file(&self, path: &std::path::Path) -> Result<TrustedKey> {
        let bytes = fs::read(path)?;
        let public = from_msgpack::<PublicIdentity>(&bytes)?;
        self.trust_public_key(&public.name, &public.public_key, "trusted", None)
    }

    pub fn trust_public_key(
        &self,
        name: &str,
        pubkey: &[u8],
        trust_level: &str,
        notes: Option<String>,
    ) -> Result<TrustedKey> {
        let mut store = self.load_trust_store()?;
        let trusted = TrustedKey {
            pubkey: pubkey.to_vec(),
            name: name.to_string(),
            fingerprint: fingerprint(pubkey),
            trust_level: trust_level.to_string(),
            first_seen: now_unix(),
            notes,
        };
        if let Some(existing) = store.keys.iter_mut().find(|key| key.pubkey == pubkey) {
            *existing = trusted.clone();
        } else {
            store.keys.push(trusted.clone());
        }
        self.save_trust_store(&store)?;
        Ok(trusted)
    }

    pub fn load_trusted_keys(&self) -> Result<Vec<TrustedKey>> {
        Ok(self.load_trust_store()?.keys)
    }

    fn identity_path(&self, name: &str) -> PathBuf {
        self.root
            .join("identities")
            .join(format!("{}.identity.msgpack", sanitize_name(name)))
    }

    fn trust_path(&self) -> PathBuf {
        self.root.join("trust.msgpack")
    }

    fn load_trust_store(&self) -> Result<TrustStore> {
        let path = self.trust_path();
        if !path.exists() {
            return Ok(TrustStore::default());
        }
        from_msgpack(&fs::read(path)?)
    }

    fn save_trust_store(&self, store: &TrustStore) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        fs::write(self.trust_path(), to_msgpack(store)?)?;
        Ok(())
    }
}

impl Identity {
    pub fn signing_key(&self) -> Result<SigningKey> {
        let secret: [u8; 32] = self
            .secret_key
            .as_slice()
            .try_into()
            .map_err(|_| SneakError::other("identity secret key has invalid length"))?;
        Ok(SigningKey::from_bytes(&secret))
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }
}

pub fn fingerprint(pubkey: &[u8]) -> String {
    hex::encode(hash::hash_many(&[
        b"sneakers:identity-fingerprint:v1",
        pubkey,
    ]))
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SeenParcel {
    pub parcel_id: Vec<u8>,
    pub parcel_fingerprint: Vec<u8>,
    pub creator_pubkey: Vec<u8>,
    pub creator_counter: Option<u64>,
    pub first_seen_local_time: u64,
    pub last_seen_local_time: u64,
    pub extracted: bool,
    pub extracted_at: Option<u64>,
    pub medium_fingerprint: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum ReplayStatus {
    FirstSeen,
    SeenBefore { extracted: bool },
}

pub fn classify_seen(parcel_fingerprint: &[u8]) -> Result<ReplayStatus> {
    let seen = load_seen()?;
    if let Some(record) = seen
        .iter()
        .find(|record| record.parcel_fingerprint == parcel_fingerprint)
    {
        Ok(ReplayStatus::SeenBefore {
            extracted: record.extracted,
        })
    } else {
        Ok(ReplayStatus::FirstSeen)
    }
}

pub fn record_seen(
    parcel_id: &[u8],
    parcel_fingerprint: &[u8],
    creator_pubkey: &[u8],
    extracted: bool,
    medium_fingerprint: Option<Vec<u8>>,
) -> Result<()> {
    let mut seen = load_seen()?;
    let now = now_unix();
    if let Some(record) = seen
        .iter_mut()
        .find(|record| record.parcel_fingerprint == parcel_fingerprint)
    {
        record.last_seen_local_time = now;
        if extracted {
            record.extracted = true;
            record.extracted_at = Some(now);
        }
        return save_seen(&seen);
    }

    seen.push(SeenParcel {
        parcel_id: parcel_id.to_vec(),
        parcel_fingerprint: parcel_fingerprint.to_vec(),
        creator_pubkey: creator_pubkey.to_vec(),
        creator_counter: None,
        first_seen_local_time: now,
        last_seen_local_time: now,
        extracted,
        extracted_at: extracted.then_some(now),
        medium_fingerprint,
    });
    save_seen(&seen)
}

fn seen_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("seen.msgpack"))
}

fn load_seen() -> Result<Vec<SeenParcel>> {
    let path = seen_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    from_msgpack(&fs::read(path)?)
}

fn save_seen(seen: &[SeenParcel]) -> Result<()> {
    let path = seen_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, to_msgpack(&seen)?)?;
    Ok(())
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    set_private_permissions(&file)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(file: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &fs::File) -> Result<()> {
    Ok(())
}
