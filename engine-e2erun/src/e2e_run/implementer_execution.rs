//! Project one retained API attempt into implementer diagnostics.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Value, json};
use traffic_recording_store::source::scoped;

use super::E2eRunContext;
use super::model::{ActiveRunState, CaseExecution};
use super::{evidence, result};
use crate::replay::report::read_dependency_evidence;

const DEPENDENCY_GROUP_LIMIT: usize = 8;
const GROUP_CASE_LIMIT: usize = 6;
const RESPONSE_GROUP_LIMIT: usize = 6;
const RESPONSE_CASE_LIMIT: usize = 6;

pub fn query_implementer_execution(
    context: E2eRunContext,
    api: &str,
    attempt: u64,
) -> Result<Value> {
    let (state, latest_dir) = evidence::finalized_focused_evidence(context, api)?;
    let execution = evidence::execution_context(&state, attempt)?;
    Ok(implementer_execution(&state, &latest_dir, execution))
}

fn implementer_execution(state: &ActiveRunState, latest_dir: &Path, mut execution: Value) -> Value {
    let cases: BTreeMap<_, _> = state
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();
    let mut artifact_cases = BTreeSet::new();
    let mut response_cases = Vec::new();
    let response_differences = result::response_differences(
        state
            .cases
            .iter()
            .filter(|case| case.execution_failure.is_none()),
        |cluster, cases| {
            let representative = &cluster.representative_case_id;
            response_cases.push(
                std::iter::once(representative.clone())
                    .chain(cases.into_iter().filter(|case| case != representative))
                    .take(RESPONSE_CASE_LIMIT)
                    .collect::<Vec<_>>(),
            );
        },
    );
    let response_failures = response_differences
        .failure_clusters
        .iter()
        .zip(&response_cases)
        .take(RESPONSE_GROUP_LIMIT)
        .filter_map(|(cluster, samples)| {
            let case = cases.get(cluster.representative_case_id.as_str())?;
            let observation = result::representative_difference(case, cluster, Path::to_path_buf)?;
            artifact_cases.insert(case.case_id.as_str());
            artifact_cases.extend(samples.iter().map(String::as_str));
            Some(json!({
                "case_id":case.case_id,
                "pointer":observation.pointer,
                "pointer_pattern":cluster.pointer_pattern,
                "difference_kind":observation.difference_kind,
                "affected_cases":cluster.affected_cases,
                "cases":samples,
                "omitted_cases":cluster.affected_cases.saturating_sub(samples.len()),
                "occurrences":cluster.occurrences,
                "expected":observation.expected,
                "received":observation.actual,
                "unavailable_reason":observation.unavailable_reason,
            }))
        })
        .collect::<Vec<_>>();
    let dependency_groups = dependency_groups(&state.cases);
    let unused_groups = sidecar_unused_groups(state, &cases);
    let total_groups = dependency_groups.len() + unused_groups.len();
    let dependency_failures = dependency_groups
        .iter()
        .map(|(key, group)| {
            json!({
                "kind":key.kind,
                "protocol":key.protocol,
                "command":key.command,
                "reason":key.reason,
                "affected_cases":group.affected_cases,
                "occurrences":group.occurrences,
                "cases":group.cases,
                "omitted_cases":group.affected_cases.saturating_sub(group.cases.len()),
                "case_id":group.case_id,
                "observed_primary_status":group.observed_primary_status,
                "representative":group.representative,
            })
        })
        .chain(unused_groups)
        .take(DEPENDENCY_GROUP_LIMIT)
        .collect::<Vec<_>>();
    artifact_cases.extend(
        dependency_failures
            .iter()
            .flat_map(|row| row["cases"].as_array().into_iter().flatten())
            .filter_map(|case_id| cases.get(case_id.as_str()?))
            .map(|case| case.case_id.as_str()),
    );
    let artifacts: BTreeMap<_, _> = artifact_cases
        .into_iter()
        .filter_map(|id| cases.get(id).map(|case| (id, case_artifacts(case))))
        .collect();
    execution["counts"] = json!(result::case_counts(&state.cases));
    execution["response_failures"] = json!(response_failures);
    execution["response_failures_summary"] = json!({
        "total_differences":response_differences.total_differences,
        "indexed_differences":response_differences.indexed_differences,
        "omitted_differences":response_differences.omitted_differences,
        "omitted_groups":response_differences.omitted_failure_clusters
            + response_differences.failure_clusters.len().saturating_sub(response_failures.len()),
    });
    execution["dependency_failures"] = json!(dependency_failures);
    execution["dependency_failures_summary"] = json!({
        "groups":total_groups,
        "omitted_groups":total_groups.saturating_sub(DEPENDENCY_GROUP_LIMIT),
    });
    execution["case_artifacts"] = json!(artifacts);
    execution["reports"] = json!(reports(state, latest_dir));
    execution
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DependencyKey<'a> {
    kind: &'a str,
    protocol: Option<&'a str>,
    command: Option<&'a str>,
    reason: &'a str,
    host: Option<&'a str>,
    port: Option<u64>,
    difference: Option<(&'a str, &'a str)>,
}

struct DependencyGroup<'a> {
    case_id: &'a str,
    representative: &'a Value,
    observed_primary_status: Option<u64>,
    cases: Vec<&'a str>,
    affected_cases: usize,
    last_case_id: Option<&'a str>,
    occurrences: usize,
}

fn dependency_groups(cases: &[CaseExecution]) -> Vec<(DependencyKey<'_>, DependencyGroup<'_>)> {
    let mut groups = BTreeMap::new();
    for case in cases {
        let Some(failure) = case.execution_failure.as_ref() else {
            continue;
        };
        let rows = failure["failures"]
            .as_array()
            .filter(|rows| !rows.is_empty())
            .map_or_else(|| std::slice::from_ref(failure), Vec::as_slice);
        for row in rows {
            let event = row.get("event").unwrap_or(row);
            let key = DependencyKey {
                kind: label(row, event, "kind").unwrap_or("dependency_failure"),
                protocol: label(row, event, "protocol"),
                command: label(row, event, "command")
                    .or_else(|| event["command_mismatch"]["received"].as_str()),
                reason: label(row, event, "reason").unwrap_or(""),
                host: event["target"]["host"].as_str(),
                port: event["target"]["port"].as_u64(),
                difference: unique_difference(event),
            };
            let group = groups.entry(key).or_insert_with(|| DependencyGroup {
                case_id: &case.case_id,
                representative: row,
                observed_primary_status: failure["observed_primary_status"].as_u64(),
                cases: Vec::new(),
                affected_cases: 0,
                last_case_id: None,
                occurrences: 0,
            });
            group.occurrences += 1;
            // All rows from a given Case are visited together.
            if group.last_case_id != Some(case.case_id.as_str()) {
                group.last_case_id = Some(&case.case_id);
                group.affected_cases += 1;
                if group.cases.len() < GROUP_CASE_LIMIT {
                    group.cases.push(&case.case_id);
                }
            }
        }
    }
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by(|(left_key, left), (right_key, right)| {
        right
            .affected_cases
            .cmp(&left.affected_cases)
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left_key.cmp(right_key))
    });
    groups
}

fn label<'a>(row: &'a Value, event: &'a Value, key: &str) -> Option<&'a str> {
    event[key].as_str().or_else(|| row[key].as_str())
}

fn unique_difference(event: &Value) -> Option<(&str, &str)> {
    let [candidate] = event["candidate_comparisons"].as_array()?.as_slice() else {
        return None;
    };
    if event["candidate_comparisons_omitted"].as_u64().unwrap_or(0) != 0
        || candidate["differences_omitted"].as_u64().unwrap_or(0) != 0
    {
        return None;
    }
    let [difference] = candidate["differences"].as_array()?.as_slice() else {
        return None;
    };
    Some((
        difference["pointer"].as_str()?,
        difference["reason"].as_str()?,
    ))
}

fn sidecar_unused_groups(
    state: &ActiveRunState,
    cases: &BTreeMap<&str, &CaseExecution>,
) -> Vec<Value> {
    let is_unused_only = |id: &str| {
        cases.get(id).is_some_and(|case| {
            case.replay_clean == Some(false) && case.execution_failure.is_none()
        })
    };
    if !cases.keys().any(|id| is_unused_only(id)) {
        return Vec::new();
    }
    let Ok(evidence) = read_dependency_evidence(&state.replay_report) else {
        return Vec::new();
    };
    evidence
        .clusters
        .into_iter()
        .filter_map(|cluster| {
            let sample = cluster.representative?;
            if sample.difference.kind != "unused_recorded"
                || cluster.omitted_case_ids > 0
                || cluster.case_ids.len() != cluster.case_count
                || !cluster.case_ids.contains(&sample.case_id)
                || !cluster.case_ids.iter().all(|id| is_unused_only(id))
            {
                return None;
            }
            let signature = sample
                .difference
                .expected
                .signature
                .as_ref()
                .and_then(Value::as_object);
            let reference = signature.and_then(|object| {
                object
                    .get("source_reference")
                    .or_else(|| object.get("protocol_ref"))
            });
            let compact_signature = signature
                .map(|object| {
                    [
                        "command",
                        "method",
                        "operation",
                        "status",
                        "index",
                        "connection_id",
                        "query_sequence",
                        "dependency_sequence",
                        "source_exchange_id",
                    ]
                    .into_iter()
                    .filter_map(|key| object.get(key).map(|value| (key.to_owned(), value.clone())))
                    .collect::<serde_json::Map<String, Value>>()
                })
                .filter(|object| !object.is_empty());
            Some(json!({
                "kind":"dependency_unconsumed",
                "protocol":cluster.protocol,
                "command":signature.and_then(|object| object.get("command")),
                "reason":cluster.reason,
                "affected_cases":cluster.case_count,
                "occurrences":cluster.count,
                "cases":cluster.case_ids,
                "case_id":sample.case_id,
                "representative":{
                    "event":{"target":cluster.endpoint},
                    "source_signature":compact_signature,
                    "source_reference":reference,
                },
            }))
        })
        .collect()
}

fn case_artifacts(case: &CaseExecution) -> Value {
    let label = case
        .case_dir
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| {
            value
                .strip_prefix("case-")
                .is_some_and(|number| number.parse::<u64>().is_ok())
        })
        .unwrap_or(&case.case_id);
    let mut artifacts = json!({"case_id":label,"case_dir":case.case_dir});
    for (key, path) in [
        ("request_path", case.case_dir.join("request.json")),
        ("dependency_scope_path", scoped::case_path(&case.case_dir)),
    ] {
        if path.is_file() {
            artifacts[key] = json!(path);
        }
    }
    if let Some(assertion) = &case.response_assertion {
        artifacts["assertion_report_path"] = json!(assertion.detail_report);
        artifacts["expected_response_path"] = json!(assertion.expected_response);
        artifacts["received_response_path"] = json!(assertion.actual_response);
    }
    artifacts
}

fn reports(state: &ActiveRunState, latest_dir: &Path) -> BTreeMap<&'static str, PathBuf> {
    let latest_reports = latest_dir.join("reports");
    let reports_dir = state.replay_report.parent().unwrap_or(&latest_reports);
    [
        (
            "dependency_evidence",
            crate::replay::report::dependency_evidence_path(&state.replay_report),
        ),
        ("target_stderr", reports_dir.join("target.stderr.log")),
        ("replay_stderr", reports_dir.join("replay.stderr.log")),
        ("replay_stdout", reports_dir.join("replay.stdout.log")),
        ("target_state", reports_dir.join("target-state.json")),
    ]
    .into_iter()
    .filter(|(_, path)| path.is_file())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};

    const API: &str = "GET /api/pet";

    fn state(root: &Path, count: usize) -> ActiveRunState {
        let inventory = CaseGroupInventory {
            case_source: root.to_path_buf(),
            source_revision: "source".into(),
            case_inventory_id: "inventory".into(),
            groups: vec![CanonicalCaseGroup {
                group_id: API.into(),
                method: "GET".into(),
                source_route: "/api/pet".into(),
                pattern: None,
                case_inventory_id: "inventory".into(),
                cases: (0..count)
                    .map(|index| CanonicalCase {
                        case_id: format!("id-{index:03}"),
                        case_dir: root.join(format!("case-{index}")),
                        recorded_at: None,
                    })
                    .collect(),
            }],
        };
        ActiveRunState::new("run".into(), 1, &inventory, &root.join("latest"))
    }

    fn dependency_failure(case: &CaseExecution) -> Value {
        let failure = json!({
            "kind":"native_request_or_delivery_failed",
            "protocol":"mysql",
            "event":{
                "reason":"MySQL command mismatch: expected COM_QUERY, received COM_STMT_PREPARE",
                "command_mismatch":{"expected":"COM_QUERY","received":"COM_STMT_PREPARE"},
            },
        });
        json!({
            "case_id":case.case_id,
            "kind":"dependency_unmatched",
            "observed_primary_status":500,
            "failures":[failure,failure],
        })
    }

    #[test]
    fn mixed_failures_group_dependencies_and_keep_independent_response_differences() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = state(temp.path(), 2);
        for case in &mut state.cases {
            std::fs::create_dir(&case.case_dir).unwrap();
            let request = case.case_dir.join("request.json");
            let expected = case.case_dir.join("expected-response.json");
            let received = case.case_dir.join("actual-response.json");
            std::fs::write(
                &request,
                br#"{"method":"GET","headers":{"authorization":["private"]}}"#,
            )
            .unwrap();
            std::fs::write(&expected, br#"{"status":200}"#).unwrap();
            std::fs::write(&received, br#"{"status":500}"#).unwrap();
            case.assertion_passed = Some(false);
            case.response_assertion = Some(
                serde_json::from_value(json!({
                    "passed":false,
                    "method":"GET",
                    "path":"/api/pet",
                    "gateway_protocol":"http",
                    "body_codec":"json",
                    "difference_count":1,
                    "difference_index":[{"pointer":"$status","kind":"status_mismatch",
                        "expected_status":200,"actual_status":500}],
                    "detail_report":case.case_dir.join("assertion.json"),
                    "detail_fingerprint":"detail",
                    "request":request,
                    "expected_response":expected,
                    "actual_response":received,
                    "policy_path":"policy.yaml",
                    "policy_fingerprint":"policy",
                }))
                .unwrap(),
            );
        }
        state.cases[0].execution_failure = Some(dependency_failure(&state.cases[0]));

        let execution = evidence::execution_context(&state, 1).unwrap();
        let facts = implementer_execution(&state, &temp.path().join("latest"), execution);
        assert_eq!(facts["counts"]["response_nonpassing"], 2);
        assert_eq!(facts["dependency_failures"].as_array().unwrap().len(), 1);
        let group = &facts["dependency_failures"][0];
        assert_eq!(group["affected_cases"], 1);
        assert_eq!(group["occurrences"], 2);
        assert_eq!(group["observed_primary_status"], 500);
        assert_eq!(
            group["representative"]["event"]["command_mismatch"]["received"],
            "COM_STMT_PREPARE"
        );
        assert_eq!(facts["response_failures"].as_array().unwrap().len(), 1);
        let response = &facts["response_failures"][0];
        assert_eq!(response["case_id"], "id-001");
        assert_eq!(response["cases"], json!(["id-001"]));
        assert_eq!(response["expected"]["value"], 200);
        assert_eq!(response["received"]["value"], 500);
        assert_eq!(facts["case_artifacts"]["id-000"]["case_id"], "case-0");
        assert_eq!(
            facts["case_artifacts"]["id-001"]["case_dir"],
            json!(temp.path().join("case-1"))
        );
        assert_eq!(
            facts["case_artifacts"]["id-001"]["request_path"],
            json!(temp.path().join("case-1/request.json"))
        );
        assert!(!facts.to_string().contains("authorization"));
    }

    #[test]
    fn dependency_counts_cover_cases_beyond_the_display_samples() {
        let mut state = state(Path::new("/cases"), GROUP_CASE_LIMIT + 1);
        for case in &mut state.cases {
            case.execution_failure = Some(dependency_failure(case));
        }
        let execution = evidence::execution_context(&state, 1).unwrap();
        let facts = implementer_execution(&state, Path::new("/latest"), execution);
        let group = &facts["dependency_failures"][0];
        assert_eq!(group["affected_cases"], GROUP_CASE_LIMIT + 1);
        assert_eq!(group["occurrences"], 2 * (GROUP_CASE_LIMIT + 1));
        assert_eq!(group["cases"].as_array().unwrap().len(), GROUP_CASE_LIMIT);
        assert_eq!(group["omitted_cases"], 1);
    }

    #[test]
    fn dependency_groups_keep_distinct_endpoints_and_value_positions() {
        let mut state = state(Path::new("/cases"), 3);
        for (case, (host, pointer)) in state.cases.iter_mut().zip([
            ("db-a", "/params/0"),
            ("db-a", "/params/1"),
            ("db-b", "/params/0"),
        ]) {
            case.execution_failure = Some(json!({
                "failures":[{
                    "event":{"protocol":"mysql","reason":"no replay match",
                        "target":{"host":host,"port":3306},
                        "candidate_comparisons":[{
                            "differences":[{"pointer":pointer,"reason":"value differs"}],
                        }],
                    },
                }],
            }));
        }
        assert_eq!(dependency_groups(&state.cases).len(), 3);
    }

    #[test]
    fn sidecar_projects_only_complete_case_scoped_unused_groups_without_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = state(temp.path(), 2);
        for case in &mut state.cases {
            case.replay_clean = Some(false);
        }
        state.cases[1].execution_failure = Some(dependency_failure(&state.cases[1]));
        let reference = json!({"protocol":"mysql","sequence":13});
        let cluster = |case_ids: &[&str], omitted: usize, count: usize| {
            json!({
                "protocol":"mysql","reason":"unused_recorded","count":count,
                "case_count":case_ids.len()+omitted,"case_ids":case_ids,"omitted_case_ids":omitted,
                "operations":{},"omitted_operations":0,
                "representative":{
                    "case_id":"id-000",
                    "difference":{
                        "kind":"unused_recorded",
                        "expected":{"presence":"present","signature":{"index":4,
                            "protocol_ref":reference,"sql":"private-argument"}},
                        "actual":{"presence":"missing"},
                    },
                },
            })
        };
        let sidecar = crate::replay::report::dependency_evidence_path(&state.replay_report);
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(
            sidecar,
            json!({
                "version":1,"case_event_counts":{},"omitted_clusters":0,
                "clusters":[cluster(&["id-000"],0,2),cluster(&["id-000","id-001"],0,3),
                    cluster(&["id-000","outside"],0,4),cluster(&["id-000"],1,5)],
            })
            .to_string(),
        )
        .unwrap();

        let execution = evidence::execution_context(&state, 1).unwrap();
        let facts = implementer_execution(&state, &temp.path().join("latest"), execution);
        let groups = facts["dependency_failures"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        let unused = &groups[1];
        assert_eq!(unused["kind"], "dependency_unconsumed");
        assert_eq!(unused["occurrences"], 2);
        assert_eq!(unused["affected_cases"], 1);
        assert_eq!(unused["representative"]["source_reference"], reference);
        assert_eq!(
            unused["representative"]["source_signature"],
            json!({"index":4})
        );
        assert_eq!(
            facts["case_artifacts"]["id-000"]["case_dir"],
            json!(temp.path().join("case-0"))
        );
        assert!(!facts.to_string().contains("private-argument"));
    }
}
