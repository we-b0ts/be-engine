//! Bounded read-only observations of complete HTTP array-order differences.
use super::*;
use anyhow::ensure;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use traffic_codec_json::canonical as canonical_json;

const MAX_CANDIDATES: usize = 64;
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in crate::protocols::replay::http) struct OrderEvidence {
    pub candidates: Vec<OrderCandidate>,
    pub omitted_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::protocols::replay::http) struct OrderCandidate {
    scheme: HttpReplayScheme,
    case_id: Option<String>,
    source_case_id: Option<String>,
    pub selector: HttpUnorderedLocation,
    element_count: usize,
    remaining_unordered_pointers: Vec<String>,
    recorded_request_fingerprint: String,
    array_fingerprint: String,
}

/// Only loaded, unconsumed, same-case/Global requests can supply a witness.
pub(in crate::protocols::replay::http) fn capture(
    state: &ReplayState,
    scheme: HttpReplayScheme,
    target: &TargetKey,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> OrderEvidence {
    let mut evidence = OrderEvidence::default();
    if body.len() > MAX_BODY_BYTES {
        return evidence;
    }
    let Ok(actual) = serde_json::from_slice::<Value>(body) else {
        return evidence;
    };
    for exchange in &state.protocols.http_exchanges {
        if !exchange.status.is_available()
            || exchange.shared_origin.is_some()
            || !active_http_case_matches(state.active_case_id.as_deref(), exchange)
            || exchange.identity.scheme != scheme
            || exchange.identity.target != *target
            || !exchange
                .record
                .native
                .method
                .eq_ignore_ascii_case(method.as_str())
            || uri_mismatch_reason(&exchange.record.native.uri, &uri.to_string(), &[]).is_some()
            || exchange.record.native.error.is_some()
            || exchange.record.native.response_status.is_none()
        {
            continue;
        }
        let Ok(recorded_body) = decode_body(&exchange.record.native.request_body) else {
            continue;
        };
        if recorded_body.len() > MAX_BODY_BYTES {
            continue;
        }
        let Ok(recorded) = serde_json::from_slice::<Value>(&recorded_body) else {
            continue;
        };
        let mut pointers = Vec::new();
        order_paths(&recorded, &actual, "", &mut pointers);
        let mut left = recorded.clone();
        let mut right = actual.clone();
        for pointer in &pointers {
            normalize_arrays(&mut left, &mut right, pointer);
        }
        // A witness pairs the complete request, allowing only these array reorderings.
        if left != right {
            continue;
        }
        for pointer in &pointers {
            if evidence.candidates.len() == MAX_CANDIDATES {
                evidence.omitted_candidates += 1;
                continue;
            }
            let array = recorded.pointer(pointer).unwrap().as_array().unwrap();
            evidence.candidates.push(OrderCandidate {
                scheme,
                case_id: state.active_case_id.clone(),
                source_case_id: exchange.case_id.clone(),
                selector: HttpUnorderedLocation {
                    host: target.host.clone(),
                    port: target.port,
                    method: method.to_string(),
                    path: uri.path().to_string(),
                    pointer: pointer.clone(),
                },
                element_count: array.len(),
                remaining_unordered_pointers: pointers
                    .iter()
                    .filter(|p| *p != pointer)
                    .cloned()
                    .collect(),
                recorded_request_fingerprint: super::super::identity::recorded_fingerprint(
                    &exchange.record,
                )
                .unwrap(),
                array_fingerprint: array_fingerprint(array),
            });
        }
    }
    evidence
}

fn array_fingerprint(array: &[Value]) -> String {
    let mut array = array.to_vec();
    array.sort_by_cached_key(canonical_json);
    digest(&serde_json::to_vec(&array).unwrap())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Deserialize)]
struct Report {
    finalized: bool,
    #[serde(default)]
    unmatched_http_requests: Vec<Unmatched>,
}
#[derive(Deserialize)]
struct Unmatched {
    #[serde(default)]
    unordered_json: Option<OrderEvidence>,
}

pub(crate) fn discover(report_path: &Path) -> Result<Value> {
    let bytes = fs::read(report_path)?;
    let report: Report = serde_json::from_slice(&bytes)?;
    ensure!(
        report.finalized,
        "HTTP unordered evidence requires finalized Replay"
    );
    let unavailable = report
        .unmatched_http_requests
        .iter()
        .any(|r| r.unordered_json.is_none());
    let mut candidates = Vec::new();
    let mut omitted = 0;
    for item in report
        .unmatched_http_requests
        .into_iter()
        .filter_map(|r| r.unordered_json)
    {
        omitted += item.omitted_candidates;
        for candidate in item.candidates {
            if candidates.len() < MAX_CANDIDATES {
                candidates.push(candidate);
            } else {
                omitted += 1;
            }
        }
    }
    Ok(
        json!({"candidates": candidates, "omitted_candidates": omitted,
        "evidence_revision": digest(&bytes), "requires_fresh_replay": unavailable,
        "does_not_prove": "order-only request differences require source proof of unordered semantics"}),
    )
}
