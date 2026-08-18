use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::verification::{ComparisonVerificationCase, ComparisonVerificationClassification};
use crate::replay::{
    ComparisonResponseObservation, MotanBodyAssertionReport, ResponseDifferenceKind,
    read_comparison_response_observation,
};

const VALUE_LIMIT_BYTES: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonRepresentativeDifference {
    pub api: String,
    pub case_id: String,
    pub classification: ComparisonVerificationClassification,
    pub pointer: String,
    pub difference_kind: ResponseDifferenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub motan: Option<MotanBodyAssertionReport>,
    pub source_before: Value,
    pub candidate: Value,
    pub source_after: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonRepresentativePolicyMismatch {
    pub api: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    pub rule_id: String,
}

pub(super) fn difference(
    cases: &[ComparisonVerificationCase],
) -> Result<Option<ComparisonRepresentativeDifference>> {
    for classification in [
        ComparisonVerificationClassification::CandidateDifference,
        ComparisonVerificationClassification::SourceChange,
    ] {
        let Some(case) = cases
            .iter()
            .find(|case| !case.passed && case.classification == classification)
        else {
            continue;
        };
        let Some(response) = case.response.as_ref() else {
            continue;
        };
        let pointer = case
            .candidate_only_pointers
            .first()
            .or_else(|| case.source_change_pointers.first())
            .or_else(|| {
                response
                    .differences
                    .first()
                    .map(|difference| &difference.pointer)
            });
        let Some(pointer) = pointer else {
            continue;
        };
        let difference = response
            .differences
            .iter()
            .find(|difference| difference.pointer == *pointer)
            .or_else(|| {
                case.baseline_recheck.as_ref().and_then(|report| {
                    report
                        .differences
                        .iter()
                        .find(|difference| difference.pointer == *pointer)
                })
            })
            .context("representative comparison Pointer has no difference evidence")?;
        let case_dir = Path::new(&case.case_dir);
        let source_before = value(
            &case_dir.join("expected-response.json"),
            "source-before response",
            pointer,
        )?;
        let candidate = value(
            &case_dir.join("response.json"),
            "candidate response",
            pointer,
        )?;
        let source_after_path = case_dir.join("expected-response-after.json");
        let source_after = if path_is_present(&source_after_path)? {
            value(&source_after_path, "source-after response", pointer)?
        } else {
            Value::String("not_recorded".to_string())
        };
        return Ok(Some(ComparisonRepresentativeDifference {
            api: case.api.clone(),
            case_id: case.case_id.clone(),
            classification: case.classification,
            pointer: pointer.clone(),
            difference_kind: difference.kind,
            motan: response.motan.clone(),
            source_before,
            candidate,
            source_after,
        }));
    }
    Ok(None)
}

pub(super) fn policy_mismatch(
    cases: &[ComparisonVerificationCase],
) -> Option<ComparisonRepresentativePolicyMismatch> {
    cases.iter().find_map(|case| {
        case.policy_mismatch_rule_ids.first().map(|rule_id| {
            ComparisonRepresentativePolicyMismatch {
                api: case.api.clone(),
                case_id: Some(case.case_id.clone()),
                rule_id: rule_id.clone(),
            }
        })
    })
}

fn value(path: &Path, label: &str, pointer: &str) -> Result<Value> {
    let observation = read_comparison_response_observation(path, label)?;
    match pointer {
        "$status" => Ok(Value::from(observation.status)),
        "$body" => Ok(bounded_body(observation)),
        pointer => {
            let body: Value = serde_json::from_slice(&observation.body)
                .with_context(|| format!("{label} body is not JSON at Pointer {pointer:?}"))?;
            Ok(body
                .pointer(pointer)
                .cloned()
                .map(bounded_json_value)
                .unwrap_or_else(|| Value::String("<missing>".to_string())))
        }
    }
}

fn bounded_body(observation: ComparisonResponseObservation) -> Value {
    match serde_json::from_slice::<Value>(&observation.body) {
        Ok(value) => bounded_json_value(value),
        Err(_) if observation.body.len() <= VALUE_LIMIT_BYTES => {
            match String::from_utf8(observation.body) {
                Ok(value) => Value::String(value),
                Err(error) => bounded_bytes(error.as_bytes()),
            }
        }
        Err(_) => bounded_bytes(&observation.body),
    }
}

fn bounded_json_value(value: Value) -> Value {
    let Ok(bytes) = serde_json::to_vec(&value) else {
        return value;
    };
    if bytes.len() <= VALUE_LIMIT_BYTES {
        value
    } else {
        json!({
            "bounded": true,
            "json_type": json_type(&value),
            "serialized_bytes": bytes.len(),
            "fingerprint": fingerprint(&bytes),
        })
    }
}

fn bounded_bytes(bytes: &[u8]) -> Value {
    json!({
        "bounded": true,
        "encoding": "bytes",
        "length": bytes.len(),
        "fingerprint": fingerprint(bytes),
    })
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn path_is_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect optional artifact {}", path.display())),
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}
