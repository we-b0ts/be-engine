//! Provider-owned compact facts. Storage hosts never interpret native payloads.
use anyhow::Result;
use serde_json::Value;

/// A compact immutable view of an authenticated record. Native metadata remains
/// namespaced by the registered evidence owner and is never an execution grant.
pub struct IndexProjection {
    pub record: Value,
    pub metadata: Value,
    pub stream: Option<StreamProjection>,
    pub lookups: Vec<LookupProjection>,
    pub endpoints: Vec<IndexEndpoint>,
    pub observations: Vec<Value>,
}

pub struct StreamProjection {
    /// Exact provider-owned lane identity, including endpoint and session facts.
    pub identity: Value,
    pub duration_ms: u64,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Value,
}

impl IndexProjection {
    pub fn record(record: Value) -> Self {
        Self {
            record,
            metadata: Value::Null,
            stream: None,
            lookups: Vec::new(),
            endpoints: Vec::new(),
            observations: Vec::new(),
        }
    }
}

/// Compact a complete encoded capture without concealing invalid evidence.
pub fn erase_capture(capture: &mut Value) {
    if safe_capture(capture)
        && let Some(data) = capture.get_mut("data")
    {
        *data = Value::String(String::new());
    }
}

pub fn safe_capture(capture: &Value) -> bool {
    use base64::Engine;
    if capture.is_null() {
        return true;
    }
    if capture["truncated"] == true {
        return false;
    }
    match (capture["encoding"].as_str(), capture["data"].as_str()) {
        (Some("utf8"), Some(_)) => true,
        (Some("base64"), Some(data)) => base64::engine::general_purpose::STANDARD
            .decode(data)
            .is_ok(),
        _ => false,
    }
}

/// Unknown historical records retain their shape and safety facts. Complete
/// encoded captures can be omitted from the derived index, never from Source.
pub fn compact_unknown(value: &Value) -> Result<IndexProjection> {
    fn compact(value: &mut Value) {
        match value {
            Value::Object(fields)
                if fields.contains_key("encoding") && fields.contains_key("data") =>
            {
                erase_capture(value)
            }
            Value::Object(fields) => fields.values_mut().for_each(compact),
            Value::Array(values) => values.iter_mut().for_each(compact),
            _ => {}
        }
    }
    let mut record = value.clone();
    compact(&mut record);
    Ok(IndexProjection::record(record))
}

pub struct LookupProjection {
    pub index: String,
    /// None uses the authenticated record digest, without reading native bytes.
    pub key: Option<String>,
    pub connection: Option<String>,
    pub summary: Value,
}

pub struct IndexEndpoint {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

/// Provider-selected fields are bounded independently of native representation.
pub fn select_without(event: &Value, excluded: &[&str], bounded: &[&str]) -> Value {
    let mut selected = event
        .as_object()
        .map(|fields| {
            fields
                .iter()
                .filter(|(name, _)| !excluded.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>()
        })
        .map(Value::Object)
        .unwrap_or(Value::Null);
    if let Some(fields) = selected.as_object_mut() {
        for name in bounded {
            if fields.get(*name).is_some_and(|value| {
                serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > 64 * 1024)
            }) {
                fields.remove(*name);
                fields.insert("_source_proof_requires_original".into(), true.into());
            }
        }
    }
    selected
}
