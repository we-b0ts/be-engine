use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const EVIDENCE_VERSION: u8 = 1;
const MAX_CLUSTERS: usize = 24;
const MAX_CASE_IDS: usize = 8;
const MAX_OPERATIONS: usize = 8;
const MAX_TEXT_CHARS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplayDependencyEvidence {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) egress_rejections: Vec<crate::ReplayEgressRejections>,
    #[serde(default)]
    pub(crate) omitted_egress_cases: usize,
    pub(crate) version: u8,
    pub(crate) case_event_counts: BTreeMap<String, BTreeMap<String, usize>>,
    pub(crate) clusters: Vec<ReplayDependencyCluster>,
    pub(crate) omitted_clusters: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplayDependencyCluster {
    pub(crate) protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) endpoint: Option<ReplayDependencyEndpoint>,
    pub(crate) reason: String,
    pub(crate) count: usize,
    pub(crate) case_count: usize,
    pub(crate) case_ids: Vec<String>,
    pub(crate) omitted_case_ids: usize,
    pub(crate) operations: BTreeMap<String, usize>,
    pub(crate) omitted_operations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) representative: Option<ReplayDependencyRepresentative>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReplayDependencyEndpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplayDependencyRepresentative {
    pub(crate) case_id: String,
    pub(crate) difference: ReplayDependencyDifference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplayDependencyDifference {
    pub(crate) kind: String,
    pub(crate) expected: ReplayDependencyObservation,
    pub(crate) actual: ReplayDependencyObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplayDependencyObservation {
    pub(crate) presence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signature: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClusterKey {
    protocol: String,
    endpoint: String,
    reason: String,
}

#[derive(Debug)]
struct ClusterBuilder {
    endpoint: Option<ReplayDependencyEndpoint>,
    count: usize,
    case_ids: BTreeSet<String>,
    operations: BTreeMap<String, usize>,
    representative: Option<ReplayDependencyRepresentative>,
}

#[derive(Debug, Clone, Copy)]
enum DifferenceDirection {
    UnusedRecorded,
    TargetOnly,
}

#[derive(Debug, Clone, Copy)]
struct EventArray {
    protocol: &'static str,
    field: &'static str,
    reason: &'static str,
    direction: DifferenceDirection,
}

const MYSQL_EVENTS: &[EventArray] = &[
    EventArray {
        protocol: "mysql",
        field: "unmatched_queries",
        reason: "unmatched_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "mysql",
        field: "unsupported_commands",
        reason: "unsupported_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "mysql",
        field: "unused_case_exchanges",
        reason: "unused_recorded",
        direction: DifferenceDirection::UnusedRecorded,
    },
];

const HTTP_EVENTS: &[EventArray] = &[
    EventArray {
        protocol: "http",
        field: "unmatched_http_requests",
        reason: "unmatched_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "http",
        field: "unsupported_http_exchanges",
        reason: "unsupported_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "http",
        field: "unused_case_http_exchanges",
        reason: "unused_recorded",
        direction: DifferenceDirection::UnusedRecorded,
    },
];

const NETWORK_EVENTS: &[EventArray] = &[EventArray {
    protocol: "network",
    field: "unrecorded_targets",
    reason: "unrecorded_endpoint",
    direction: DifferenceDirection::TargetOnly,
}];

const COMMAND_EVENTS: &[EventArray] = &[
    EventArray {
        protocol: "",
        field: "unmatched",
        reason: "unmatched_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "",
        field: "unsupported",
        reason: "unsupported_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "",
        field: "unsafe_events",
        reason: "unsafe_target",
        direction: DifferenceDirection::TargetOnly,
    },
    EventArray {
        protocol: "",
        field: "unused_case",
        reason: "unused_recorded",
        direction: DifferenceDirection::UnusedRecorded,
    },
];

pub(crate) fn dependency_evidence_path(report_path: &Path) -> PathBuf {
    let stem = report_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("replay-report");
    report_path.with_file_name(format!("{stem}-dependency-evidence.json"))
}

pub(crate) fn read_dependency_evidence(report_path: &Path) -> Result<ReplayDependencyEvidence> {
    let evidence_path = dependency_evidence_path(report_path);
    let file = File::open(&evidence_path).with_context(|| {
        format!(
            "bounded replay dependency evidence is unavailable at {}; rerun focused E2E with the current runner",
            evidence_path.display()
        )
    })?;
    let evidence: ReplayDependencyEvidence = serde_json::from_reader(BufReader::new(file))
        .with_context(|| {
            format!(
                "invalid replay dependency evidence {}",
                evidence_path.display()
            )
        })?;
    anyhow::ensure!(
        evidence.version == EVIDENCE_VERSION,
        "unsupported replay dependency evidence version {} in {}",
        evidence.version,
        evidence_path.display()
    );
    Ok(evidence)
}

pub(super) fn build_dependency_evidence(report: &Value) -> ReplayDependencyEvidence {
    let mut builders = BTreeMap::<ClusterKey, ClusterBuilder>::new();
    collect_arrays(report, NETWORK_EVENTS.iter().copied(), true, &mut builders);
    collect_arrays(report, MYSQL_EVENTS.iter().copied(), false, &mut builders);
    collect_arrays(report, HTTP_EVENTS.iter().copied(), false, &mut builders);
    for protocol in ["redis", "memcached", "kafka", "motan"] {
        let Some(protocol_report) = report.get(protocol) else {
            continue;
        };
        let arrays = COMMAND_EVENTS
            .iter()
            .map(|event| EventArray { protocol, ..*event });
        collect_arrays(protocol_report, arrays, false, &mut builders);
    }

    let mut case_event_counts = BTreeMap::<String, BTreeMap<String, usize>>::new();
    let mut clusters = builders
        .into_iter()
        .map(|(key, builder)| {
            *case_event_counts
                .entry(key.protocol.clone())
                .or_default()
                .entry(key.reason.clone())
                .or_default() += builder.count;
            finish_cluster(key, builder)
        })
        .collect::<Vec<_>>();
    clusters.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.protocol.cmp(&right.protocol))
            .then_with(|| left.reason.cmp(&right.reason))
            .then_with(|| {
                endpoint_key(left.endpoint.as_ref()).cmp(&endpoint_key(right.endpoint.as_ref()))
            })
    });
    let omitted_clusters = clusters.len().saturating_sub(MAX_CLUSTERS);
    clusters.truncate(MAX_CLUSTERS);
    let mut samples = report
        .get("egress_rejections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|sample| {
            serde_json::from_value::<crate::ReplayEgressRejections>(sample.clone()).ok()
        })
        .filter(|sample| sample.rejected_packets != Some(0))
        .collect::<Vec<_>>();
    samples.sort_by(|left, right| {
        right
            .rejected_packets
            .cmp(&left.rejected_packets)
            .then_with(|| left.case_id.cmp(&right.case_id))
    });
    let omitted_egress_cases = samples.len().saturating_sub(20);
    samples.truncate(20);
    ReplayDependencyEvidence {
        egress_rejections: samples,
        omitted_egress_cases,
        version: EVIDENCE_VERSION,
        case_event_counts,
        clusters,
        omitted_clusters,
    }
}

pub(super) fn report_has_case_dirty_events(report: &Value) -> bool {
    report
        .get("unrecorded_targets")
        .and_then(Value::as_array)
        .is_some_and(|targets| !targets.is_empty())
        || arrays_have_case_event(report, MYSQL_EVENTS)
        || arrays_have_case_event(report, HTTP_EVENTS)
        || ["redis", "memcached", "kafka", "motan"]
            .into_iter()
            .filter_map(|protocol| report.get(protocol))
            .any(|protocol_report| arrays_have_case_event(protocol_report, COMMAND_EVENTS))
}

fn arrays_have_case_event(report: &Value, arrays: &[EventArray]) -> bool {
    arrays.iter().any(|array| {
        report
            .get(array.field)
            .and_then(Value::as_array)
            .is_some_and(|events| {
                events
                    .iter()
                    .any(|event| event.get("case_id").and_then(Value::as_str).is_some())
            })
    })
}

fn collect_arrays(
    report: &Value,
    arrays: impl IntoIterator<Item = EventArray>,
    include_unscoped: bool,
    builders: &mut BTreeMap<ClusterKey, ClusterBuilder>,
) {
    for array in arrays {
        let Some(events) = report.get(array.field).and_then(Value::as_array) else {
            continue;
        };
        for event in events {
            let case_id = event
                .get("case_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if case_id.is_none() && !include_unscoped {
                continue;
            }
            let endpoint = dependency_endpoint(event.get("target"));
            let key = ClusterKey {
                protocol: array.protocol.to_string(),
                endpoint: endpoint_key(endpoint.as_ref()),
                reason: array.reason.to_string(),
            };
            let builder = builders.entry(key).or_insert_with(|| ClusterBuilder {
                endpoint: endpoint.clone(),
                count: 0,
                case_ids: BTreeSet::new(),
                operations: BTreeMap::new(),
                representative: None,
            });
            builder.count += 1;
            if let Some(case_id) = &case_id {
                builder.case_ids.insert(case_id.clone());
            }
            *builder
                .operations
                .entry(operation_label(event))
                .or_default() += 1;
            if let Some(case_id) = case_id {
                builder
                    .representative
                    .get_or_insert(ReplayDependencyRepresentative {
                        case_id,
                        difference: difference(array.direction, signature(event)),
                    });
            }
        }
    }
}

fn finish_cluster(key: ClusterKey, builder: ClusterBuilder) -> ReplayDependencyCluster {
    let case_count = builder.case_ids.len();
    let omitted_case_ids = case_count.saturating_sub(MAX_CASE_IDS);
    let case_ids = builder
        .case_ids
        .into_iter()
        .take(MAX_CASE_IDS)
        .collect::<Vec<_>>();
    let operation_count = builder.operations.len();
    let mut operations = builder.operations.into_iter().collect::<Vec<_>>();
    operations.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    operations.truncate(MAX_OPERATIONS);
    ReplayDependencyCluster {
        protocol: key.protocol,
        endpoint: builder.endpoint,
        reason: key.reason,
        count: builder.count,
        case_count,
        case_ids,
        omitted_case_ids,
        operations: operations.into_iter().collect(),
        omitted_operations: operation_count.saturating_sub(MAX_OPERATIONS),
        representative: builder.representative,
    }
}

fn dependency_endpoint(value: Option<&Value>) -> Option<ReplayDependencyEndpoint> {
    let value = value?;
    let host = value.get("host")?.as_str()?.trim().to_ascii_lowercase();
    let port = u16::try_from(value.get("port")?.as_u64()?).ok()?;
    Some(ReplayDependencyEndpoint { host, port })
}

fn endpoint_key(endpoint: Option<&ReplayDependencyEndpoint>) -> String {
    endpoint.map_or_else(
        || "<unknown>".to_string(),
        |endpoint| format!("{}:{}", endpoint.host, endpoint.port),
    )
}

fn operation_label(event: &Value) -> String {
    let mut parts = Vec::new();
    for field in ["command", "method", "operation", "topic"] {
        if let Some(value) = event.get(field).and_then(Value::as_str) {
            parts.push(value);
        }
    }
    if let Some(uri) = event.get("uri").and_then(Value::as_str) {
        parts.push(uri);
    }
    if parts.is_empty() {
        "unknown".to_string()
    } else {
        bounded(&parts.join(" "))
    }
}

fn signature(event: &Value) -> Value {
    let mut signature = serde_json::Map::new();
    for field in [
        "command",
        "method",
        "uri",
        "operation",
        "topic",
        "database",
        "sql",
        "status",
        "reason",
        "diagnostic",
    ] {
        if let Some(value) = event.get(field) {
            signature.insert(field.to_string(), bounded_value(value));
        }
    }
    Value::Object(signature)
}

fn bounded_value(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(bounded(value)),
        Value::Array(values) => Value::Array(values.iter().take(8).map(bounded_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .take(16)
                .map(|(key, value)| (key.clone(), bounded_value(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn bounded(value: &str) -> String {
    let mut chars = value.chars();
    let bounded = chars.by_ref().take(MAX_TEXT_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else {
        bounded
    }
}

fn difference(direction: DifferenceDirection, signature: Value) -> ReplayDependencyDifference {
    let present = ReplayDependencyObservation {
        presence: "present".to_string(),
        signature: Some(signature),
    };
    let missing = ReplayDependencyObservation {
        presence: "missing".to_string(),
        signature: None,
    };
    match direction {
        DifferenceDirection::UnusedRecorded => ReplayDependencyDifference {
            kind: "unused_recorded".to_string(),
            expected: present,
            actual: missing,
        },
        DifferenceDirection::TargetOnly => ReplayDependencyDifference {
            kind: "target_only".to_string(),
            expected: missing,
            actual: present,
        },
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keeps_only_case_scoped_dirty_events_and_ignores_global_arrays() {
        let report = json!({
            "memcached": {
                "unmatched": [
                    {"case_id":null,"target":{"host":"startup.internal","port":11211},"command":"get"},
                    {"case_id":"case-a","target":{"host":"CACHE.INTERNAL","port":11211},"command":"get"}
                ],
                "unused_case": [
                    {"case_id":"case-b","target":{"host":"cache.internal","port":11211},"command":"get"}
                ],
                "unused_global": [
                    {"target":{"host":"cache.internal","port":11211},"command":"get"}
                ]
            },
            "unused_global_http_exchanges": [
                {"target":{"host":"global.internal","port":80},"method":"GET","uri":"/health"}
            ]
        });

        let evidence = build_dependency_evidence(&report);

        assert_eq!(evidence.clusters.len(), 2);
        assert_eq!(
            evidence.case_event_counts["memcached"]["unmatched_target"],
            1
        );
        assert_eq!(
            evidence.case_event_counts["memcached"]["unused_recorded"],
            1
        );
        assert!(evidence.clusters.iter().all(|cluster| {
            cluster
                .endpoint
                .as_ref()
                .is_none_or(|endpoint| endpoint.host != "startup.internal")
        }));
        assert!(report_has_case_dirty_events(&report));
    }

    #[test]
    fn unscoped_target_activity_is_reference_context_not_dirty() {
        let report = json!({
            "unmatched_http_requests": [
                {"case_id":null,"target":{"host":"startup.internal","port":80},"method":"GET","uri":"/warmup"}
            ]
        });

        assert!(!report_has_case_dirty_events(&report));
        assert!(build_dependency_evidence(&report).clusters.is_empty());
    }

    #[test]
    fn unscoped_unrecorded_endpoint_remains_bounded_run_evidence() {
        let report = json!({
            "unrecorded_targets": [
                {"target":{"host":"BREEZE.RECORDING","port":9301},"reason":"访问了录制时没有访问过的域名:port"}
            ]
        });

        let evidence = build_dependency_evidence(&report);

        assert!(report_has_case_dirty_events(&report));
        assert_eq!(
            evidence.case_event_counts["network"]["unrecorded_endpoint"],
            1
        );
        assert_eq!(evidence.clusters.len(), 1);
        assert_eq!(evidence.clusters[0].case_count, 0);
        assert!(evidence.clusters[0].representative.is_none());
        assert_eq!(
            evidence.clusters[0].endpoint.as_ref().unwrap().host,
            "breeze.recording"
        );
    }

    #[test]
    fn bounded_query_reads_the_sidecar_without_opening_the_full_report() {
        let temp = tempfile::tempdir().unwrap();
        let report_path = temp.path().join("replay-report.json");
        let evidence = build_dependency_evidence(&json!({
            "unmatched_http_requests": [
                {"case_id":"case-a","target":{"host":"api.internal","port":80},"method":"GET","uri":"/missing"}
            ]
        }));
        std::fs::write(
            dependency_evidence_path(&report_path),
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();

        let loaded = read_dependency_evidence(&report_path).unwrap();

        assert_eq!(loaded.clusters.len(), 1);
        assert!(!report_path.exists());
    }
}

#[cfg(test)]
mod egress_tests {
    use super::*;
    #[test]
    fn rejection_counts_are_evidence_without_creating_dirty_events() {
        let now = chrono::Utc::now();
        let report = serde_json::json!({"egress_rejections":[{"case_id":"case-a","observed_from":now,"observed_until":now,"rejected_packets":4}]});
        assert!(!report_has_case_dirty_events(&report));
        let evidence = build_dependency_evidence(&report);
        assert_eq!(evidence.egress_rejections[0].rejected_packets, Some(4));
        assert!(evidence.clusters.is_empty());
        assert!(evidence.case_event_counts.is_empty());
    }
}
