//! Bounded target-request witnesses; public discovery exposes selectors only.
use super::super::config::fingerprint;
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
impl Candidate {
    fn label(&self) -> String {
        let metadata = serde_json::to_string(&(
            &self.case_id,
            &self.capability,
            &self.host,
            self.port,
            &self.command,
            self.database,
            &self.path,
            &self.source_fingerprint,
            &self.target_fingerprint,
            self.actual_anchor,
        ))
        .expect("witness metadata serialization");
        format!("dependency-request:{metadata}")
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct HttpWitness {
    pub contract: crate::protocols::replay::http::multipart::MultipartContract,
    pub headers: BTreeMap<String, Vec<String>>,
}
impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
        clocks: crate::primary_protocol::assertion::RequestTimes,
    ) {
        if source.len() != actual.len() || source == actual {
            return;
        }
        let capability = if source.first() != actual.first()
            && matches!(command, "SET" | "INCRBY" | "EXPIRE")
            && source
                .first()
                .is_some_and(|v| v.len() <= 1024 && std::str::from_utf8(v).is_ok())
            && actual
                .first()
                .is_some_and(|v| v.len() <= 1024 && std::str::from_utf8(v).is_ok())
        {
            "redis_key_request"
        } else if source.first() != actual.first() {
            return;
        } else if (if command == "RPUSH" && source.len() >= 2 {
            Some(1)
        } else {
            traffic_protocol_redis::value_rules::message_value_index(command, source.len())
        })
        .is_some_and(|index| {
            crate::json_value::parse(&source[index]).is_some()
                && crate::json_value::parse(&actual[index]).is_some()
        }) {
            "redis_json_request"
        } else if matches!(command, "ZADD" | "ZREMRANGEBYSCORE") && source.len() == 3 {
            "redis_request_time"
        } else if matches!(command, "EVAL" | "EVALSHA") && source.len() >= 4 && source.len() <= 129
        {
            "redis_script_request_time"
        } else {
            return;
        };
        let source = serde_json::to_vec(source).expect("argument serialization");
        let actual = serde_json::to_vec(actual).expect("argument serialization");
        self.observe(
            case,
            target,
            command,
            database,
            "",
            capability,
            &source,
            &actual,
            clocks.target,
        );
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_http(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        source_headers: &BTreeMap<String, Vec<String>>,
        actual: &[u8],
        headers: &BTreeMap<String, Vec<String>>,
        clocks: crate::primary_protocol::assertion::RequestTimes,
    ) {
        if source == actual {
            return;
        }
        if crate::protocols::replay::http::multipart::compare(
            source,
            source_headers,
            actual,
            headers,
        )
        .is_err()
        {
            return;
        }
        let actual = serde_json::to_vec(&HttpWitness {
            contract: crate::protocols::replay::http::multipart::contract(actual, headers)
                .expect("validated multipart request"),
            headers: headers.clone(),
        })
        .expect("HTTP witness serialization");
        self.observe(
            case,
            target,
            method,
            0,
            path,
            "http_multipart",
            source,
            &actual,
            clocks.target,
        );
    }
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        case: &str,
        target: &TargetKey,
        command: &str,
        database: i64,
        path: &str,
        capability: &str,
        source: &[u8],
        actual: &[u8],
        actual_started_at: Option<DateTime<Utc>>,
    ) {
        if actual.len() > crate::value_limits::MAX_VALUE_BYTES {
            return;
        }
        let Ok(anchor) = self.anchor(case) else {
            return;
        };
        let Some(actual_anchor) = actual_started_at else {
            return;
        };
        let Ok(headers) = crate::request_headers::evidence::HeaderPolicy::load(&anchor.dir)
            .and_then(|policy| policy.ranges(actual))
        else {
            return;
        };
        let Ok(payload) =
            crate::policy_evidence::StoredPayload::capture(actual, 0, &headers, &anchor.dir)
        else {
            return;
        };
        let mut candidate = Candidate {
            case_id: case.into(),
            capability: capability.into(),
            host: target.host.clone(),
            port: target.port,
            command: command.into(),
            database,
            path: path.into(),
            source_fingerprint: fingerprint(source),
            target_fingerprint: fingerprint(actual),
            actual_anchor,
            payload,
            authentication: String::new(),
        };
        let Ok(authentication) =
            crate::policy_evidence::authentication::sign(&anchor.dir, &candidate.label(), actual)
        else {
            return;
        };
        candidate.authentication = authentication;
        let mut state = self.state.lock().expect("request contracts");
        if state.candidates.len() < 64
            && !state.candidates.iter().any(|c| {
                c.case_id == case
                    && c.source_fingerprint == candidate.source_fingerprint
                    && c.target_fingerprint == candidate.target_fingerprint
            })
        {
            state.candidates.push(candidate);
        }
    }
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
