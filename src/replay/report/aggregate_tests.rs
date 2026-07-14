use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use tempfile::TempDir;

use super::aggregate::aggregate_replay_reports;

#[test]
fn aggregates_version_two_and_three_reports() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("20260714041519").join("pluto");
    write_report(
        &source,
        "api-one",
        report_value(2, &source.join("api-one"), &[("case-a", "ended")], 2),
    );
    let mut second = report_value(3, &source.join("api-two"), &[("case-b", "ended")], 1);
    second
        .as_object_mut()
        .unwrap()
        .insert("redis".to_owned(), protocol_value(1, 2, 0, 0, 0, 0, 0));
    second
        .as_object_mut()
        .unwrap()
        .insert("memcached".to_owned(), protocol_value(0, 0, 0, 0, 0, 0, 0));
    second
        .as_object_mut()
        .unwrap()
        .insert("kafka".to_owned(), protocol_value(0, 0, 0, 0, 0, 0, 0));
    write_report(&source, "api-two", second);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert_eq!(aggregate.counts.reports, 2);
    assert_eq!(aggregate.counts.published_cases, 2);
    assert_eq!(aggregate.counts.reported_cases, 2);
    assert_eq!(aggregate.counts.unreported_cases, 0);
    assert_eq!(aggregate.counts.case_statuses["ended"], 2);
    assert_eq!(aggregate.counts.events.mysql.matched_queries, 3);
    assert_eq!(aggregate.counts.events.redis.connections, 1);
    assert_eq!(aggregate.counts.events.redis.matched, 2);
    assert!(aggregate.complete);
    assert!(!aggregate.dirty);
    assert_eq!(aggregate.cases[0].case_id, "case-a");
    assert_eq!(aggregate.cases[1].case_id, "case-b");
}

#[test]
fn rejects_duplicate_case_ids_in_case_source() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    write_report(
        &source,
        "api-one",
        report_value(2, &source.join("api-one"), &[("same", "ended")], 0),
    );
    write_report(
        &source,
        "api-two",
        report_value(2, &source.join("api-two"), &[("same", "ended")], 0),
    );

    let error = aggregate_replay_reports(&source).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("duplicate published replay case id")
    );
}

#[test]
fn reports_published_cases_without_replay_output() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    write_case(&source.join("api").join("case-a"), true);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert_eq!(aggregate.counts.reports, 0);
    assert_eq!(aggregate.counts.published_cases, 1);
    assert_eq!(aggregate.counts.reported_cases, 0);
    assert_eq!(aggregate.counts.unreported_cases, 1);
    assert_eq!(aggregate.unreported_cases[0].case_id, "case-a");
    assert!(aggregate.unreported_cases[0].dependencies_present);
    assert!(!aggregate.complete);
}

#[test]
fn marks_pending_and_unused_evidence_in_summary() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value(2, &source.join("api"), &[("case-a", "pending")], 0);
    report["unused_case_http_exchanges"] = json!([{}]);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(!aggregate.is_complete());
    assert!(aggregate.is_dirty());
    assert_eq!(aggregate.counts.case_statuses["pending"], 1);
}

fn write_report(source: &Path, group: &str, value: Value) -> PathBuf {
    let group_dir = source.join(group);
    for case in value["cases"].as_array().unwrap() {
        let case_id = case["case_id"].as_str().unwrap();
        write_case(&group_dir.join(case_id), true);
    }
    let replay_dir = group_dir.join(".replay");
    fs::create_dir_all(&replay_dir).unwrap();
    let path = replay_dir.join("replay-report.json");
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    path
}

fn write_case(case_dir: &Path, dependencies: bool) {
    fs::create_dir_all(case_dir).unwrap();
    fs::write(case_dir.join("request.json"), b"{}").unwrap();
    fs::write(case_dir.join("expected-response.json"), b"{}").unwrap();
    if dependencies {
        fs::write(case_dir.join("dependencies.jsonl"), b"").unwrap();
    }
}

fn report_value(
    version: u64,
    case_dir: &Path,
    cases: &[(&str, &str)],
    matched_queries: usize,
) -> Value {
    fs::create_dir_all(case_dir).unwrap();
    let mut report = json!({
        "version": version,
        "case_dir": case_dir,
        "cases": cases.iter().map(|(case_id, status)| json!({
            "case_id": case_id,
            "status": status,
        })).collect::<Vec<_>>(),
        "connections": 1,
        "builtin_queries": [],
        "matched_queries": [],
        "unmatched_queries": [],
        "unsupported_commands": [],
        "metadata_warnings": [],
        "unused_bootstrap_exchanges": [],
        "unused_case_exchanges": [],
        "matched_http_exchanges": [],
        "unmatched_http_requests": [],
        "unsupported_http_exchanges": [],
        "unused_bootstrap_http_exchanges": [],
        "unused_case_http_exchanges": [],
    });
    report["matched_queries"] = Value::Array(
        (0..matched_queries)
            .map(|index| json!({"index": index}))
            .collect(),
    );
    report
}

fn protocol_value(
    connections: usize,
    matched: usize,
    unmatched: usize,
    unsupported: usize,
    unsafe_events: usize,
    unused_case: usize,
    unused_bootstrap: usize,
) -> Value {
    let mut value = Map::new();
    value.insert("connections".to_owned(), json!(connections));
    for (name, count) in [
        ("matched", matched),
        ("unmatched", unmatched),
        ("unsupported", unsupported),
        ("unsafe_events", unsafe_events),
        ("unused_case", unused_case),
        ("unused_bootstrap", unused_bootstrap),
    ] {
        value.insert(
            name.to_owned(),
            Value::Array((0..count).map(|index| json!({"index": index})).collect()),
        );
    }
    Value::Object(value)
}
