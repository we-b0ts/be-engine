//! Bounded request-time witnesses and stale-safe, read-only candidate verification.
use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const MAX_CANDIDATES: usize = 64;
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in crate::replay::http) struct OrderEvidence {
    pub candidates: Vec<OrderCandidate>,
    pub omitted_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::replay::http) struct OrderCandidate {
    scheme: HttpReplayScheme,
    case_id: Option<String>,
    source_case_id: Option<String>,
    pub selector: HttpUnorderedSelector,
    element_count: usize,
    remaining_unordered_pointers: Vec<String>,
    recorded_request_fingerprint: String,
    array_fingerprint: String,
}

/// Only loaded, unconsumed, same-case/Global requests can supply a witness.
pub(in crate::replay::http) fn capture(
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
    for exchange in &state.http_exchanges {
        if exchange.consumed
            || exchange.shared_origin.is_some()
            || !active_http_case_matches(state.active_case_id.as_deref(), exchange)
            || exchange.identity.scheme != scheme
            || exchange.identity.target != *target
            || !exchange.record.method.eq_ignore_ascii_case(method.as_str())
            || uri_mismatch_reason(&exchange.record.uri, &uri.to_string(), &[]).is_some()
            || exchange.record.error.is_some()
            || exchange.record.response_status.is_none()
        {
            continue;
        }
        let Ok(recorded_body) = decode_body(&exchange.record.request_body) else {
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
                selector: HttpUnorderedSelector {
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

pub(crate) fn verify(
    source: &Path,
    report_path: &Path,
    selector: &HttpUnorderedSelector,
) -> Result<Value> {
    let evidence = discover(report_path)?;
    ensure!(
        evidence["omitted_candidates"] == 0,
        "HTTP unordered evidence is bounded; narrow and rerun Replay before planning"
    );
    let candidates: Vec<OrderCandidate> = serde_json::from_value(evidence["candidates"].clone())?;
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|c| selector.selects(&c.selector))
        .collect();
    ensure!(
        !candidates.is_empty(),
        "no verified HTTP unordered candidate for this endpoint and JSON Pointer; old reports require fresh Replay"
    );
    let (root, files) = super::super::recording::files(source)?;
    let mut verified = vec![false; candidates.len()];
    let mut records = Vec::new();
    for file in files {
        let source_case_id = super::super::recording::case_id(&file)?;
        if !candidates
            .iter()
            .any(|c| c.source_case_id.as_deref().unwrap_or("Global") == source_case_id)
        {
            continue;
        }
        super::super::recording::visit(&file, |line, record| {
            if !selector.endpoint().matches(&record) {
                return Ok(());
            }
            let fingerprint = super::super::identity::recorded_fingerprint(&record)?;
            for (index, candidate) in candidates.iter().enumerate() {
                if identity_from_record(&record)?.scheme != candidate.scheme
                    || candidate.source_case_id.as_deref().unwrap_or("Global") != source_case_id
                    || fingerprint != candidate.recorded_request_fingerprint
                {
                    continue;
                }
                ensure!(
                    record.error.is_none() && record.response_status.is_some(),
                    "HTTP unordered source exchange is not replayable"
                );
                let body: Value = serde_json::from_slice(&decode_body(&record.request_body)?)?;
                let array = body
                    .pointer(&candidate.selector.pointer)
                    .and_then(Value::as_array)
                    .context("HTTP unordered source array disappeared")?;
                ensure!(
                    array.len() == candidate.element_count
                        && array_fingerprint(array) == candidate.array_fingerprint,
                    "HTTP unordered source array changed"
                );
                let response = record
                    .response_body
                    .as_ref()
                    .map(decode_body)
                    .transpose()?
                    .unwrap_or_default();
                records.push(json!({"path": file.strip_prefix(&root)?, "line": line,
                    "response_status":record.response_status, "response_fingerprint":digest(&response),
                    "response_headers_fingerprint":digest(&serde_json::to_vec(&record.response_headers)?)}));
                verified[index] = true;
            }
            Ok(())
        })?;
    }
    ensure!(
        verified.iter().all(|v| *v),
        "HTTP unordered source evidence changed or is missing"
    );
    Ok(
        json!({"candidates":candidates, "records":records, "evidence_revision":evidence["evidence_revision"]}),
    )
}
