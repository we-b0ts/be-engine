//! Bounded, token-free witnesses for one differing Redis or HTTP request value.
use super::*;
use crate::policy::runtime::config::fingerprint;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureCandidate {
    pub case_id: String,
    #[serde(default)]
    pub value_type: DynamicValueType,
    pub capture: DynamicValueCapture,
    pub source_payload_fingerprint: String,
    pub source_value_fingerprint: String,
    pub target_value_fingerprint: String,
    pub target_uuid: bool,
    pub target_uuid_v4: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_witness: Option<super::path_candidates::PathRequestWitness>,
}

impl DynamicValues {
    pub(crate) fn capture_candidates(&self) -> Vec<CaptureCandidate> {
        self.candidates.lock().expect("capture candidates").clone()
    }
    fn candidate(
        &self,
        case: &str,
        capture: DynamicValueCapture,
        payload: &[u8],
        source: &str,
        target: &str,
        value_type: DynamicValueType,
    ) {
        if source == target
            || source.is_empty()
            || target.is_empty()
            || source.len() > 1024
            || target.len() > 1024
        {
            return;
        }
        let uuid = uuid::Uuid::parse_str(target).ok();
        let candidate = CaptureCandidate {
            case_id: case.into(),
            value_type,
            capture,
            source_payload_fingerprint: fingerprint(payload),
            source_value_fingerprint: fingerprint(source.as_bytes()),
            target_value_fingerprint: fingerprint(target.as_bytes()),
            target_uuid: uuid.is_some(),
            target_uuid_v4: uuid.is_some_and(|uuid| uuid.get_version_num() == 4),
            path_witness: None,
        };
        let mut items = self.candidates.lock().expect("capture candidates");
        if !items.contains(&candidate)
            && items.iter().filter(|item| item.case_id == case).count() < 64
        {
            items.push(candidate);
        }
    }
    pub(crate) fn observe_redis(
        &self,
        case: &str,
        target: &TargetKey,
        database: i64,
        command: &str,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) {
        if !self.routes.contains_key(case)
            || source.len() != actual.len()
            || source.first() != actual.first()
        {
            return;
        }
        let indexes: Vec<usize> = match command {
            "SET" => vec![1],
            "LSET" if source.len() == 3 => vec![2],
            "HSET" => (2..source.len().min(130)).step_by(2).collect(),
            "RPUSH" if source.len() <= 129 => (1..source.len()).collect(),
            _ => return,
        };
        let Some(Ok(key)) = source.first().map(|key| std::str::from_utf8(key)) else {
            return;
        };
        if key.len() > 1024 {
            return;
        }
        for index in indexes {
            if index >= source.len()
                || source
                    .iter()
                    .zip(actual)
                    .enumerate()
                    .any(|(i, (a, b))| i != index && a != b)
            {
                continue;
            }
            let differences =
                if let Some(differences) = json_differences(&source[index], &actual[index]) {
                    if !matches!(command, "RPUSH" | "LSET") && differences.len() != 1 {
                        continue;
                    }
                    differences
                        .into_iter()
                        .map(|(pointer, left, right, kind)| (Some(pointer), left, right, kind))
                        .collect::<Vec<_>>()
                } else {
                    let (Ok(left), Ok(right)) = (
                        strings::capture(&source[index], None),
                        strings::capture(&actual[index], None),
                    ) else {
                        continue;
                    };
                    vec![(None, left, right, DynamicValueType::String)]
                };
            for (pointer, left, right, value_type) in differences {
                self.candidate(
                    case,
                    DynamicValueCapture::Redis {
                        references: None,
                        derived_from: None,
                        when: None,
                        target: DynamicValueTarget {
                            host: target.host.clone(),
                            port: target.port,
                        },
                        database,
                        command: command.into(),
                        key: crate::RedisValueKeySelector::Exact { value: key.into() },
                        argument_index: index,
                        json_pointer: pointer,
                    },
                    &serde_json::to_vec(source).expect("byte vectors serialize"),
                    &left,
                    &right,
                    value_type,
                );
            }
        }
    }
    pub(crate) fn observe_http(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        actual: &[u8],
    ) {
        if !self.routes.contains_key(case) {
            return;
        }
        if let Some((pointer, left, right, value_type)) = json_difference(source, actual) {
            self.candidate(
                case,
                DynamicValueCapture::Http {
                    target: DynamicValueTarget {
                        host: target.host.clone(),
                        port: target.port,
                    },
                    method: method.into(),
                    path: path.into(),
                    json_pointer: Some(pointer),
                    path_segment: None,
                },
                source,
                &left,
                &right,
                value_type,
            );
        }
    }
}

fn json_difference(
    source: &[u8],
    target: &[u8],
) -> Option<(String, String, String, DynamicValueType)> {
    let mut differences = json_differences(source, target)?;
    (differences.len() == 1).then(|| differences.remove(0))
}

fn json_differences(
    source: &[u8],
    target: &[u8],
) -> Option<Vec<(String, String, String, DynamicValueType)>> {
    let (source, target) = (
        crate::json_value::parse(source)?,
        crate::json_value::parse(target)?,
    );
    let mut differences = Vec::new();
    fn visit(
        source: &Value,
        target: &Value,
        path: String,
        depth: usize,
        out: &mut Vec<(String, String, String, DynamicValueType)>,
    ) -> Option<()> {
        if source == target {
            return Some(());
        }
        if depth > 64 || out.len() >= 32 {
            return None;
        }
        match (source, target) {
            (Value::String(left), Value::String(right)) => {
                out.push((path, left.clone(), right.clone(), DynamicValueType::String))
            }
            (Value::Number(left), Value::Number(right))
                if (left.is_i64() || left.is_u64()) && (right.is_i64() || right.is_u64()) =>
            {
                out.push((
                    path,
                    left.to_string(),
                    right.to_string(),
                    DynamicValueType::Integer,
                ))
            }
            (Value::Object(left), Value::Object(right)) if left.keys().eq(right.keys()) => {
                for (key, value) in left {
                    visit(
                        value,
                        &right[key],
                        format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                        depth + 1,
                        out,
                    )?;
                }
            }
            (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
                for (i, (left, right)) in left.iter().zip(right).enumerate() {
                    visit(left, right, format!("{path}/{i}"), depth + 1, out)?;
                }
            }
            _ => return None,
        }
        Some(())
    }
    visit(&source, &target, String::new(), 0, &mut differences)?;
    Some(differences)
}
