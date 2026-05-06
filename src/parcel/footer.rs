#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ParcelFooterV1 {
    pub parcel_id: Vec<u8>,
    pub parcel_fingerprint: Vec<u8>,
    pub manifest_hash: Vec<u8>,
    pub chunk_merkle_root: Vec<u8>,
    pub frame_count: u64,
    pub last_frame_hash: Vec<u8>,
    pub created_at: u64,
}
