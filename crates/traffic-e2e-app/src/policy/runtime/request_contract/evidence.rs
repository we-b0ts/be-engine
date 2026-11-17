//! Bounded target-request witnesses; public discovery exposes selectors only.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Candidate {
    pub case_id: String,
    pub capability: String,
    pub host: String,
    pub port: u16,
    pub command: String,
    pub database: i64,
    pub path: String,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
    pub actual_anchor: DateTime<Utc>,
    #[serde(flatten)]
    pub payload: crate::policy_evidence::StoredPayload,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authentication: String,
}
pub(crate) fn discover(report: &Value) -> Value {
    Value::Array(
        report["replay_policy"]["request_contract_candidates"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|candidate| serde_json::from_value::<Candidate>(candidate.clone()).ok())
            .map(|candidate| {
                let mut candidate = serde_json::to_value(candidate).expect("candidate projection");
                for field in [
                    "encrypted_target",
                    "encrypted",
                    "encoding",
                    "data",
                    "parts",
                    "authentication",
                ] {
                    candidate.as_object_mut().unwrap().remove(field);
                }
                candidate
            })
            .collect(),
    )
}

pub(super) fn decode(value: &Value) -> Result<Vec<u8>> {
    use base64::Engine;
    ensure!(
        value["truncated"] == false,
        "request witness capture is incomplete"
    );
    let data = value["data"]
        .as_str()
        .context("request witness bytes unavailable")?;
    match value["encoding"].as_str() {
        Some("utf8") => Ok(data.as_bytes().to_vec()),
        Some("base64") => Ok(base64::engine::general_purpose::STANDARD.decode(data)?),
        _ => anyhow::bail!("unsupported request witness encoding"),
    }
}
