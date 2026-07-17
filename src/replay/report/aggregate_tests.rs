use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use tempfile::TempDir;

use super::aggregate::{
    ReplayAggregateOptions, aggregate_replay_reports, aggregate_replay_reports_with_options,
};

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

#[test]
fn marks_unused_applicable_replay_policy_rule_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v4(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000099",
        true,
    );
    report["replay_policy"] = json!({
        "version": 1,
        "path": "/target/config/replay.yaml",
        "fingerprint": "fnv1a64:0123456789abcdef",
        "expected_response": "assertions_only",
        "rules": [],
        "unused_applicable_rule_ids": ["audit-id"]
    });
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.dirty);
    let policy = aggregate.reports[0].replay_policy.as_ref().unwrap();
    assert_eq!(policy.expected_response, "assertions_only");
    assert_eq!(policy.unused_applicable_rule_ids, vec!["audit-id"]);
}

#[test]
fn rejects_replay_policy_that_does_not_declare_assertion_only_expected_response() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v4(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000098",
        true,
    );
    report["replay_policy"] = json!({
        "version": 1,
        "path": "/target/config/replay.yaml",
        "fingerprint": "fnv1a64:0123456789abcdef",
        "expected_response": "fixture_input",
        "rules": [],
        "unused_applicable_rule_ids": []
    });
    write_report(&source, "api", report);

    let error = aggregate_replay_reports(&source).unwrap_err();

    assert!(error.to_string().contains("must be assertions_only"));
}

#[test]
fn selects_exact_cases_and_final_sessions() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let session_a = "00000000-0000-4000-8000-000000000001";
    let session_b = "00000000-0000-4000-8000-000000000002";
    write_session_report(
        &source,
        "api",
        "attempt-a",
        report_value_v4(
            &source.join("api"),
            &[("case-a", "ended"), ("case-b", "ended")],
            session_a,
            true,
        ),
    );
    write_session_report(
        &source,
        "api",
        "attempt-b",
        report_value_v4(&source.join("api"), &[("case-b", "ended")], session_b, true),
    );
    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-b".to_string()]),
        session_ids: BTreeSet::from([session_b.to_string()]),
    };

    let aggregate = aggregate_replay_reports_with_options(&source, &options).unwrap();

    assert!(aggregate.complete);
    assert!(!aggregate.dirty);
    assert_eq!(aggregate.counts.reports, 1);
    assert_eq!(aggregate.selected_case_ids, vec!["case-b"]);
    assert_eq!(aggregate.selected_session_ids, vec![session_b]);
    assert_eq!(aggregate.reports[0].session_id.as_deref(), Some(session_b));
}

#[test]
fn rerun_requires_an_explicit_session_selection() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let first = "00000000-0000-4000-8000-000000000011";
    let second = "00000000-0000-4000-8000-000000000012";
    write_session_report(
        &source,
        "api",
        "attempt-one",
        report_value_v4(&source.join("api"), &[("case-a", "ended")], first, true),
    );
    write_session_report(
        &source,
        "api",
        "attempt-two",
        report_value_v4(&source.join("api"), &[("case-a", "ended")], second, true),
    );

    let error = aggregate_replay_reports(&source).unwrap_err();
    assert!(error.to_string().contains("duplicate replay case id"));

    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-a".to_string()]),
        session_ids: BTreeSet::from([second.to_string()]),
    };
    let aggregate = aggregate_replay_reports_with_options(&source, &options).unwrap();
    assert!(aggregate.complete);
    assert_eq!(aggregate.selected_session_ids, vec![second]);
}

#[test]
fn version_four_report_must_be_finalized_to_be_complete() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    write_session_report(
        &source,
        "api",
        "unfinished",
        report_value_v4(
            &source.join("api"),
            &[("case-a", "ended")],
            "00000000-0000-4000-8000-000000000021",
            false,
        ),
    );

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(!aggregate.complete);
    assert_eq!(aggregate.reports[0].finalized, Some(false));
}

#[test]
fn version_five_uses_total_success_counts_beyond_retained_details() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v4(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000051",
        true,
    );
    report["version"] = json!(5);
    report["success_detail_limit"] = json!(100);
    report["builtin_queries"] = json!([{"index": 0}]);
    report["builtin_query_count"] = json!(6_592);
    report["matched_queries"] = json!([{"index": 0}, {"index": 1}]);
    report["matched_query_count"] = json!(2_295);
    report["matched_http_exchanges"] = json!([{"index": 0}]);
    report["matched_http_exchange_count"] = json!(202);
    for protocol in ["redis", "memcached", "kafka"] {
        report[protocol]["matched_count"] = json!(0);
    }
    write_session_report(&source, "api", "v5", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.complete);
    assert_eq!(aggregate.counts.events.mysql.builtin_queries, 6_592);
    assert_eq!(aggregate.counts.events.mysql.matched_queries, 2_295);
    assert_eq!(aggregate.counts.events.http.matched_exchanges, 202);
}

#[test]
fn selected_session_must_cover_the_selected_cases() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let session = "00000000-0000-4000-8000-000000000031";
    write_session_report(
        &source,
        "api",
        "other-case",
        report_value_v4(&source.join("api"), &[("case-a", "ended")], session, true),
    );
    write_case(&source.join("api").join("case-b"), true);
    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-b".to_string()]),
        session_ids: BTreeSet::from([session.to_string()]),
    };

    let error = aggregate_replay_reports_with_options(&source, &options).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("session ids were not found for the selected cases")
    );
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

fn write_session_report(source: &Path, group: &str, attempt: &str, value: Value) -> PathBuf {
    let group_dir = source.join(group);
    for case in value["cases"].as_array().unwrap() {
        let case_id = case["case_id"].as_str().unwrap();
        write_case(&group_dir.join(case_id), true);
    }
    let replay_dir = group_dir.join(".replay").join("sessions").join(attempt);
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

fn report_value_v4(
    case_dir: &Path,
    cases: &[(&str, &str)],
    session_id: &str,
    finalized: bool,
) -> Value {
    let mut report = report_value(4, case_dir, cases, 0);
    report["session_id"] = json!(session_id);
    report["started_at"] = json!("2026-07-14T00:00:00Z");
    report["finalized"] = json!(finalized);
    if finalized {
        report["finalized_at"] = json!("2026-07-14T00:01:00Z");
    }
    report["selected_case_ids"] =
        Value::Array(cases.iter().map(|(case_id, _)| json!(case_id)).collect());
    report["redis"] = protocol_value(0, 0, 0, 0, 0, 0, 0);
    report["memcached"] = protocol_value(0, 0, 0, 0, 0, 0, 0);
    report["kafka"] = protocol_value(0, 0, 0, 0, 0, 0, 0);
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
