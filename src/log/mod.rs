use crate::core::now_unix;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum LogEventType {
    Created,
    Verified,
    Witnessed,
    Extracted,
    Rejected,
    Reclaimed,
}

impl LogEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Verified => "Verified",
            Self::Witnessed => "Witnessed",
            Self::Extracted => "Extracted",
            Self::Rejected => "Rejected",
            Self::Reclaimed => "Reclaimed",
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LogRecordV1 {
    pub seq: u64,
    pub event_type: LogEventType,
    pub actor_pubkey: Vec<u8>,
    pub parcel_id: Vec<u8>,
    pub parcel_fingerprint: Vec<u8>,
    pub previous_log_hash: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub timestamp_claim: Option<u64>,
    pub signature: Option<Vec<u8>>,
}

impl LogRecordV1 {
    pub fn unsigned(
        seq: u64,
        event_type: LogEventType,
        actor_pubkey: Vec<u8>,
        parcel_id: Vec<u8>,
        parcel_fingerprint: Vec<u8>,
    ) -> Self {
        Self {
            seq,
            event_type,
            actor_pubkey,
            parcel_id,
            parcel_fingerprint,
            previous_log_hash: vec![0u8; 32],
            body_hash: vec![0u8; 32],
            timestamp_claim: Some(now_unix()),
            signature: None,
        }
    }
}
