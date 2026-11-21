//! Read-only dependency evidence refresh.
//! Ownership changes are independently proved in dependency_review; actual
//! Replay reports never move unused observations into another owner's pool.
#[cfg(any(test, feature = "test-support"))]
use super::evidence::build_dependency_evidence;
#[cfg(any(test, feature = "test-support"))]
use crate::config::SourceTrafficPolicyConfig;
#[cfg(any(test, feature = "test-support"))]
use crate::replay::report::dependency_evidence_path;
#[cfg(any(test, feature = "test-support"))]
use anyhow::{Result, ensure};
#[cfg(any(test, feature = "test-support"))]
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(any(test, feature = "test-support"))]
use serde_json::Value;
#[cfg(any(test, feature = "test-support"))]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(test, feature = "test-support"))]
use std::fs;
#[cfg(any(test, feature = "test-support"))]
#[cfg(any(test, feature = "test-support"))]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize)]
#[cfg(any(test, feature = "test-support"))]
pub struct BackgroundReclassification {
    pub rules_fingerprint: String,
    pub matched_unused_case: usize,
    pub by_protocol: BTreeMap<String, usize>,
    pub remaining_dirty_case_ids: BTreeSet<String>,
}

pub fn parse_background_dependency_evidence<T: DeserializeOwned>(
    raw: &str,
) -> serde_json::Result<T> {
    serde_json::from_str(raw)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reclassify_background_dependencies(
    policy: &Path,
    report_path: &Path,
    cases: &BTreeMap<String, PathBuf>,
) -> Result<BackgroundReclassification> {
    let mut report: Value = serde_json::from_slice(&fs::read(report_path)?)?;
    reclassify_background_report(policy, report_path, &mut report, cases)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reclassify_background_report(
    policy: &Path,
    report_path: &Path,
    report: &mut Value,
    _cases: &BTreeMap<String, PathBuf>,
) -> Result<BackgroundReclassification> {
    ensure!(
        report["version"] == 7,
        "dependency evidence refresh requires current Replay report version 7"
    );
    let (_, fingerprints) = SourceTrafficPolicyConfig::load_with_fingerprints(policy)?;
    let evidence = build_dependency_evidence(report);
    let path = dependency_evidence_path(report_path);
    let payload = serde_json::to_vec_pretty(&evidence)?;
    if path.exists() {
        crate::config::edit::write_atomic(&path, &payload)?;
    } else {
        crate::config::edit::create_atomic(&path, &payload)?;
    }
    Ok(BackgroundReclassification {
        rules_fingerprint: fingerprints.classification,
        remaining_dirty_case_ids: dirty_case_ids(report),
        ..Default::default()
    })
}

#[cfg(any(test, feature = "test-support"))]
fn dirty_case_ids(report: &Value) -> BTreeSet<String> {
    let mut case_ids = BTreeSet::new();
    for field in [
        "case_execution_failures",
        "unmatched_queries",
        "unsupported_commands",
        "unused_case_exchanges",
        "unmatched_http_requests",
        "unsupported_http_exchanges",
        "http_request_header_mismatches",
        "dependency_pre_matches",
        "unused_case_http_exchanges",
    ] {
        collect_case_ids(report, field, &mut case_ids);
    }
    for protocol in ["redis", "memcached", "kafka", "motan"] {
        let Some(protocol_report) = report.get(protocol) else {
            continue;
        };
        for field in ["unmatched", "unsupported", "unsafe_events", "unused_case"] {
            collect_case_ids(protocol_report, field, &mut case_ids);
        }
    }
    case_ids
}

#[cfg(any(test, feature = "test-support"))]
fn collect_case_ids(report: &Value, field: &str, output: &mut BTreeSet<String>) {
    let Some(events) = report.get(field).and_then(Value::as_array) else {
        return;
    };
    output.extend(
        events
            .iter()
            .filter_map(|event| event.get("case_id").and_then(Value::as_str))
            .map(ToOwned::to_owned),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refresh_preserves_actual_report_and_does_not_waive_unused_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let policy = temp.path().join("policy.yaml");
        fs::write(
            &policy,
            crate::config::native_policy::empty_policy().unwrap(),
        )
        .unwrap();
        let path = temp.path().join("replay.json");
        let mut report = json!({"version":7,"cases":[{"case_id":"a"}],
            "unused_case_http_exchanges":[{"case_id":"a","index":0,"method":"GET","uri":"/task"}]});
        let bytes = serde_json::to_vec(&report).unwrap();
        fs::write(&path, &bytes).unwrap();
        let result =
            reclassify_background_report(&policy, &path, &mut report, &BTreeMap::new()).unwrap();
        assert_eq!(result.matched_unused_case, 0);
        assert!(result.remaining_dirty_case_ids.contains("a"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(serde_json::to_vec(&report).unwrap(), bytes);
    }

    #[test]
    fn previous_report_generation_is_rejected_without_owner_migration() {
        let mut report = serde_json::json!({"version":6});
        assert!(
            reclassify_background_report(
                Path::new("missing"),
                Path::new("missing"),
                &mut report,
                &BTreeMap::new()
            )
            .is_err()
        );
    }
}
