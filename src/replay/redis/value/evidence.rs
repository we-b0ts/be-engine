//! Bounded mismatch witnesses; planning rechecks finalized Replay and immutable source.
use super::super::{RedisReplayState, TargetConnection, TargetKey};
use super::*;
use crate::replay::assertion::protobuf;
use crate::replay::{ReplaySource, command_matching::CommandExchangeScope};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
const MAX_CANDIDATES: usize = 64;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in crate::replay) struct OrderEvidence {
    candidates: Vec<OrderCandidate>,
    omitted_candidates: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrderCandidate {
    case_id: Option<String>,
    source_case_id: Option<String>,
    command: String,
    selector: RedisUnorderedSelector,
    remaining_fields: Vec<RedisUnorderedField>,
    recorded_exchange_fingerprint: String,
    target_value_fingerprint: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn fingerprint(exchange: &super::super::RecordedExchange) -> String {
    digest(&serde_json::to_vec(exchange).expect("record serialization"))
}

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) fn capture_value_candidates(
        &mut self,
        case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) {
        for exchange in &self.exchanges {
            let record = &exchange.record;
            if !exchange.is_available()
                || (exchange.source == ReplaySource::Case
                    && (case_id.is_none() || exchange.case_id.as_deref() != case_id))
                || !self
                    .connection_scopes
                    .matches(exchange, case_id, connection)
                || !super::super::target_matches(
                    target,
                    &record.native.target_host,
                    record.native.target_port,
                )
                || record.native.resp_version != resp_version
                || record.native.database != database
                || super::super::normalize_optional(username)
                    != super::super::normalize_optional(record.native.username.as_deref())
                || !record.native.command.eq_ignore_ascii_case(command)
                || record.native.response_kind == "error"
                || record.native.outcome != crate::DependencyExchangeOutcome::Response
            {
                continue;
            }
            let Some((expected, actual)) = paired_values(command, &exchange.args, args) else {
                continue;
            };
            let Some(key) = args
                .first()
                .and_then(|k| std::str::from_utf8(k).ok())
                .filter(|k| k.len() <= 1024)
            else {
                continue;
            };
            let fields = discover_fields(expected, actual);
            for field in &fields {
                if self.unordered_value.candidates.len() >= MAX_CANDIDATES {
                    self.unordered_value.omitted_candidates += 1;
                    continue;
                }
                self.unordered_value.candidates.push(OrderCandidate {
                    case_id: case_id.map(str::to_string),
                    source_case_id: exchange.case_id.clone(),
                    command: record.native.command.clone(),
                    selector: RedisUnorderedSelector {
                        host: record.native.target_host.clone(),
                        port: record.native.target_port,
                        key: RedisValueKeySelector::Exact { value: key.into() },
                        field: field.clone(),
                    },
                    remaining_fields: fields
                        .iter()
                        .filter(|f| !f.overlaps(field))
                        .cloned()
                        .collect(),
                    recorded_exchange_fingerprint: fingerprint(record),
                    target_value_fingerprint: digest(actual),
                });
            }
        }
    }
}
fn discover_fields(expected: &[u8], actual: &[u8]) -> Vec<RedisUnorderedField> {
    if expected == actual {
        return Vec::new();
    }
    let parsed = (json::parse(expected), json::parse(actual));
    if parsed.0.is_some() != parsed.1.is_some() {
        return Vec::new();
    }
    if let (Some(mut a), Some(mut b)) = parsed {
        let mut pointers = Vec::new();
        // Root arrays use the empty JSON Pointer.
        if a.is_array() && b.is_array() && a != b {
            let (mut left, mut right) = (a.clone(), b.clone());
            normalize_json(&mut left, &mut right, "");
            if left == right {
                pointers.push(String::new());
            }
        }
        if pointers.is_empty() {
            crate::replay::json_order::order_paths(&a, &b, "", &mut pointers);
        }
        for p in &pointers {
            normalize_json(&mut a, &mut b, p);
        }
        return if a == b {
            pointers
                .into_iter()
                .map(|pointer| RedisUnorderedField::Json { pointer })
                .collect()
        } else {
            Vec::new()
        };
    }
    protobuf::unordered_evidence::candidates(expected, actual)
        .into_iter()
        .flat_map(|(path, types)| {
            types
                .into_iter()
                .map(move |element_type| RedisUnorderedField::Protobuf {
                    field_path: path.clone(),
                    element_type,
                    display_path: "value.collection (confirm from source schema)".into(),
                })
        })
        .collect()
}

pub(crate) fn discover(report_path: &Path) -> Result<Value> {
    #[derive(Deserialize)]
    struct Report {
        finalized: bool,
        #[serde(default)]
        redis: RedisReport,
    }
    #[derive(Default, Deserialize)]
    struct RedisReport {
        unordered_value: Option<OrderEvidence>,
    }
    let bytes = fs::read(report_path)?;
    let report: Report = serde_json::from_slice(&bytes)?;
    ensure!(
        report.finalized,
        "Redis unordered requires finalized Replay evidence"
    );
    let unavailable = report.redis.unordered_value.is_none();
    let evidence = report.redis.unordered_value.unwrap_or_default();
    Ok(
        json!({"candidates": evidence.candidates, "omitted_candidates": evidence.omitted_candidates,
        "evidence_revision": digest(&bytes), "requires_fresh_replay": unavailable,
        "does_not_prove": "Source evidence must establish unordered semantics and Protobuf element types; candidates do not change dependency ownership."}),
    )
}
#[cfg(test)]
mod tests;
