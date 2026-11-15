//! Mechanical one-segment witnesses; templates and generation semantics need source review.
use super::*;
use crate::policy::runtime::config::fingerprint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathRequestWitness {
    pub target_path_fingerprint: String,
    pub target_request_started_at: DateTime<Utc>,
}

impl DynamicValues {
    pub(crate) fn observe_http_path(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        source: HttpInput<'_>,
        actual: HttpInput<'_>,
    ) {
        if !self.routes.contains_key(case) || source.body != actual.body {
            return;
        }
        let (Ok(source_uri), Ok(actual_uri), Some(started_at)) = (
            source.uri.parse::<hyper::Uri>(),
            actual.uri.parse::<hyper::Uri>(),
            actual.request_started_at,
        ) else {
            return;
        };
        let left: Vec<_> = source_uri
            .path()
            .strip_prefix('/')
            .unwrap_or_default()
            .split('/')
            .collect();
        let right: Vec<_> = actual_uri
            .path()
            .strip_prefix('/')
            .unwrap_or_default()
            .split('/')
            .collect();
        if left.len() != right.len() || left.len() > 64 {
            return;
        }
        let differences: Vec<_> = left
            .iter()
            .zip(&right)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        let [index] = differences.as_slice() else {
            return;
        };
        let mut replaced = right.clone();
        replaced[*index] = left[*index];
        let mut replaced_uri = format!("/{}", replaced.join("/"));
        if let Some(query) = actual_uri.query() {
            replaced_uri.push('?');
            replaced_uri.push_str(query);
        }
        if crate::protocols::replay::http::uri_mismatch_reason(source.uri, &replaced_uri, &[])
            .is_some()
        {
            return;
        }
        let (Ok(a), Ok(b), Ok(payload)) = (
            path_segment::extract(source.uri, *index),
            path_segment::extract(actual.uri, *index),
            source::path_payload(source.uri, source.body),
        ) else {
            return;
        };
        if a == b {
            return;
        }
        let mut selector = left.clone();
        selector[*index] = "*";
        let candidate = CaptureCandidate {
            case_id: case.into(),
            value_type: DynamicValueType::String,
            capture: DynamicValueCapture::Http {
                target: DynamicValueTarget {
                    host: target.host.clone(),
                    port: target.port,
                },
                method: method.into(),
                path: format!("/{}", selector.join("/")),
                json_pointer: None,
                // The witness identifies a location, not a proposed compatibility rule.
                path_segment: Some(PathSegmentCapture {
                    index: *index,
                    template: "{value}".into(),
                    fields: BTreeMap::from([("value".into(), PathSegmentField::Exact)]),
                }),
            },
            source_payload_fingerprint: fingerprint(&payload),
            source_value_fingerprint: fingerprint(a.as_bytes()),
            target_value_fingerprint: fingerprint(b.as_bytes()),
            target_uuid: false,
            target_uuid_v4: false,
            path_witness: Some(PathRequestWitness {
                target_path_fingerprint: fingerprint(actual_uri.path().as_bytes()),
                target_request_started_at: started_at,
            }),
        };
        let mut items = self.candidates.lock().expect("capture candidates");
        if !items.contains(&candidate)
            && items.iter().filter(|item| item.case_id == case).count() < 64
        {
            items.push(candidate);
        }
    }
}
