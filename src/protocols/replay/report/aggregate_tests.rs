use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use tempfile::TempDir;

use super::aggregate::{
    ReplayAggregateOptions, aggregate_replay_reports, aggregate_replay_reports_with_options,
    aggregate_runner_replay_report, aggregate_runner_replay_report_value,
};

#[test]
fn registered_native_protocol_counts_aggregate_without_historical_sections() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value(7, &source.join("api"), &[("case-a", "ended")], 0);
    for protocol in ["redis", "memcached", "motan", "kafka"] {
        report.as_object_mut().unwrap().remove(protocol);
    }
    report["dependency_protocols"] = json!({
        "custom-rpc": {"matched_count":3,"unmatched_count":0,"unmatched":[],
            "unused_case":[],"unused_global":[],"unused_global_count":0}
    });
    write_report(&source, "api", report.clone());
    let aggregate = aggregate_replay_reports(&source).unwrap();
    assert!(aggregate.is_complete());
    assert!(!aggregate.is_dirty());
    assert_eq!(
        aggregate.counts.events.dependency_protocols["custom-rpc"].matched,
        3
    );
    report["dependency_protocols"]["custom-rpc"]["matched_count"] = json!("invalid");
    write_report(&source, "api", report);
    assert!(aggregate_replay_reports(&source).is_err());
}

#[test]
fn startup_debt_is_diagnostic_during_independent_api_acceptance() {
    for status in ["verified", "phase_unverified"] {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("recording");
        let mut report = report_value(7, &source.join("api"), &[("case-a", "ended")], 0);
        let startup = json!({
            "status":status,
            "boundary_case_id":"case-a",
            "business_inventory":{"mysql":10,"redis":2},
            "unstarted_business_dependencies":{"mysql":10,"redis":2}
        });
        report["startup_phase"] = startup.clone();
        write_report(&source, "api", report.clone());
        let aggregate = aggregate_replay_reports(&source).unwrap();
        assert!(aggregate.is_complete());
        assert!(!aggregate.is_dirty(), "{status}");
        assert!(
            serde_json::to_value(&aggregate.reports[0])
                .unwrap()
                .get("startup_phase")
                .is_none()
        );
        assert_eq!(report["startup_phase"], startup);

        report["unused_case_exchanges"] = json!([{"case_id":"case-a"}]);
        write_report(&source, "api", report);
        assert!(aggregate_replay_reports(&source).unwrap().is_dirty());
    }
}

#[test]
fn connection_failure_inventory_survives_summary_and_dependency_evidence() {
    for (field, dirty) in [
        ("unused_case", true),
        ("failed_case", true),
        ("matched", false),
    ] {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("recording");
        let mut report = report_value(7, &source.join("api"), &[("case-a", "ended")], 0);
        report["connect_failures"] = json!({"matched_count":2,"unused_case":[],"failed_case":[]});
        if dirty {
            report["connect_failures"][field] = json!([{"case_id":"case-a","id":uuid::Uuid::new_v4(),"target":{"host":"cache.test","port":6379}}]);
        }
        assert_eq!(
            crate::protocols::replay::report::evidence::build_dependency_evidence(&report)
                .case_event_counts
                .is_empty(),
            !dirty
        );
        write_report(&source, "api", report);
        let aggregate = aggregate_replay_reports(&source).unwrap();
        assert_eq!(aggregate.is_dirty(), dirty);
        assert_eq!(
            aggregate.counts.events.network.matched_connection_failures,
            2
        );
        assert_eq!(
            aggregate.counts.events.network.unused_connection_failures,
            usize::from(field == "unused_case")
        );
        assert_eq!(
            aggregate.counts.events.network.failed_connection_failures,
            usize::from(field == "failed_case")
        );
    }
}

#[test]
fn mysql_transaction_semantics_are_reported_without_relabeling_historical_reports() {
    for semantics in [None, Some("first_write_through_end_v1")] {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("recording");
        let mut report = report_value(7, &source.join("api"), &[("case-a", "ended")], 0);
        if let Some(semantics) = semantics {
            report["mysql_transaction_semantics"] = json!(semantics);
        }
        write_report(&source, "api", report);
        let aggregate = aggregate_replay_reports(&source).unwrap();
        assert!(aggregate.is_complete());
        assert!(!aggregate.is_dirty());
        assert_eq!(
            aggregate.reports[0].mysql_transaction_semantics.as_deref(),
            semantics
        );
    }
}

#[test]
fn rejects_pre_global_report_versions() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("20260714041519").join("pluto");
    write_report(
        &source,
        "api-one",
        report_value(5, &source.join("api-one"), &[("case-a", "ended")], 2),
    );

    let error = aggregate_replay_reports(&source).unwrap_err();

    assert!(error.to_string().contains("supported version is 7"));
}

#[test]
fn rejects_duplicate_case_ids_in_case_source() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    write_report(
        &source,
        "api-one",
        report_value(7, &source.join("api-one"), &[("same", "ended")], 0),
    );
    write_report(
        &source,
        "api-two",
        report_value(7, &source.join("api-two"), &[("same", "ended")], 0),
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
    let mut report = report_value(7, &source.join("api"), &[("case-a", "pending")], 0);
    report["unused_case_http_exchanges"] = json!([{"case_id":"case-a"}]);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(!aggregate.is_complete());
    assert!(aggregate.is_dirty());
    assert_eq!(aggregate.counts.case_statuses["pending"], 1);
}

#[test]
fn matched_header_mismatch_is_dirty_and_observations_only_are_clean() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value(7, &source.join("api"), &[("case-a", "ended")], 0);
    let event = json!({"case_id": "case-a", "header": "tenant-id"});
    report["http_request_header_mismatches"] = json!([event]);
    report["http_request_header_observations"] = json!([event]);
    report["http_request_header_observation_count"] = json!(12);
    write_report(&source, "api", report.clone());
    let aggregate = aggregate_replay_reports(&source).unwrap();
    assert!(aggregate.is_dirty());
    assert_eq!(aggregate.counts.events.http.request_header_mismatches, 1);
    assert_eq!(aggregate.counts.events.http.request_header_observations, 12);
    report["http_request_header_mismatches"] = json!([]);
    write_report(&source, "api", report);
    assert!(!aggregate_replay_reports(&source).unwrap().is_dirty());
}

#[test]
fn retains_unused_global_as_diagnostic_without_marking_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000088",
        true,
    );
    report["unused_global_exchanges"] = json!([{}]);
    report["unused_global_http_exchanges"] = json!([{}]);
    report["redis"] = protocol_value(0, 0, 0, 0, 0, 0, 1);
    report["memcached"] = protocol_value(0, 0, 0, 0, 0, 0, 1);
    report["kafka"] = protocol_value(0, 0, 0, 0, 0, 0, 1);
    report["motan"] = protocol_value(0, 0, 0, 0, 0, 0, 1);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.is_complete());
    assert!(!aggregate.is_dirty());
    assert_eq!(aggregate.counts.events.mysql.unused_global_exchanges, 1);
    assert_eq!(aggregate.counts.events.http.unused_global_exchanges, 1);
    assert_eq!(aggregate.counts.events.redis.unused_global, 1);
    assert_eq!(aggregate.counts.events.memcached.unused_global, 1);
    assert_eq!(aggregate.counts.events.kafka.unused_global, 1);
    assert_eq!(aggregate.counts.events.motan.unused_global, 1);
}

#[test]
fn unscoped_target_activity_is_counted_but_does_not_mark_cases_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000086",
        true,
    );
    report["unmatched_http_requests"] = json!([{
        "case_id": null,
        "target": {"host":"startup.internal","port":80},
        "method":"GET",
        "uri":"/warmup"
    }]);
    report["memcached"] = protocol_value(0, 0, 0, 0, 0, 0, 0);
    report["memcached"]["unmatched"] = json!([{
        "case_id": null,
        "target": {"host":"cache.internal","port":11211},
        "command":"get"
    }]);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.is_complete());
    assert!(!aggregate.is_dirty());
    assert_eq!(aggregate.counts.events.http.unmatched_requests, 1);
    assert_eq!(aggregate.counts.events.memcached.unmatched, 1);
}

#[test]
fn unrecorded_endpoint_is_counted_and_marks_replay_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000085",
        true,
    );
    report["unrecorded_targets"] = json!([{
        "case_id": "case-a",
        "target": {"host":"breeze.recording","port":9301},
        "reason":"访问了录制时没有访问过的域名:port"
    }]);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.is_complete());
    assert!(aggregate.is_dirty());
    assert_eq!(aggregate.counts.events.network.unrecorded_targets, 1);
}

#[test]
fn aggregates_motan_counts_and_marks_unused_case_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000087",
        true,
    );
    report["motan"] = protocol_value(2, 3, 1, 0, 0, 1, 1);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.is_dirty());
    assert_eq!(aggregate.counts.events.motan.connections, 2);
    assert_eq!(aggregate.counts.events.motan.matched, 3);
    assert_eq!(aggregate.counts.events.motan.unmatched, 1);
    assert_eq!(aggregate.counts.events.motan.unused_case, 1);
    assert_eq!(aggregate.counts.events.motan.unused_global, 1);
}

#[test]
fn retains_allowed_unused_case_http_as_diagnostic_without_marking_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000089",
        true,
    );
    report["allowed_unused_case_http_exchanges"] = json!([{
        "target": {"host": "cs.aliyuncs.com", "port": 443}
    }]);
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.is_complete());
    assert!(!aggregate.is_dirty());
    assert_eq!(
        aggregate.counts.events.http.allowed_unused_case_exchanges,
        1
    );
}

#[test]
fn marks_unused_applicable_replay_policy_rule_dirty() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
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
        "dependency_rules": [],
        "unused_applicable_dependency_rule_ids": ["audit-id"]
    });
    write_report(&source, "api", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.dirty);
    let policy = aggregate.reports[0].replay_policy.as_ref().unwrap();
    assert_eq!(policy.expected_response, "assertions_only");
    assert_eq!(
        policy.unused_applicable_dependency_rule_ids,
        vec!["audit-id"]
    );
}

#[test]
fn rejects_replay_policy_that_does_not_declare_assertion_only_expected_response() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
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
        "dependency_rules": [],
        "unused_applicable_dependency_rule_ids": []
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
        report_value_v7(
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
        report_value_v7(&source.join("api"), &[("case-b", "ended")], session_b, true),
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
fn exact_report_aggregation_ignores_unrelated_historical_reports() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let session = "00000000-0000-4000-8000-000000000003";
    let selected = write_session_report(
        &source,
        "api",
        "selected",
        report_value_v7(&source.join("api"), &[("case-a", "ended")], session, true),
    );
    let unrelated = source
        .join("api")
        .join(".replay")
        .join("sessions")
        .join("historical")
        .join("replay-report.json");
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::write(&unrelated, b"not json").unwrap();
    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-a".to_string()]),
        session_ids: BTreeSet::from([session.to_string()]),
    };

    let aggregate = aggregate_runner_replay_report(&source, &selected, &source, &options).unwrap();

    assert!(aggregate.complete);
    assert_eq!(aggregate.counts.reports, 1);
    assert_eq!(aggregate.reports[0].path, selected.display().to_string());
}

#[test]
fn runner_snapshot_aggregates_shared_session_and_preserves_sibling_dirty_evidence() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let snapshot = temp.path().join("runtime/focused/latest");
    fs::create_dir_all(&snapshot).unwrap();
    let mut report = report_value_v7(
        &source,
        &[("case-a", "ended"), ("case-b", "ended")],
        "session",
        true,
    );
    report["unused_case_http_exchanges"] = json!([{"case_id":"case-b"}]);
    write_case(&source.join("case-a"), true);
    write_case(&source.join("case-b"), true);
    let retained = snapshot.join("replay-report.json");
    fs::write(&retained, report.to_string()).unwrap();
    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-a".into()]),
        session_ids: BTreeSet::from(["session".into()]),
    };
    let aggregate =
        aggregate_runner_replay_report(&source, &retained, &snapshot, &options).unwrap();
    assert!(aggregate.complete);
    assert!(aggregate.dirty);
    assert_eq!(aggregate.counts.reported_cases, 2);
    assert_eq!(aggregate.counts.events.http.unused_case_exchanges, 1);
    assert_eq!(aggregate.selected_case_ids, ["case-a", "case-b"]);

    let mut stale = options.clone();
    stale.session_ids = BTreeSet::from(["other-session".into()]);
    assert!(aggregate_runner_replay_report(&source, &retained, &snapshot, &stale).is_err());
    let mut missing = options.clone();
    missing.case_ids.insert("missing".into());
    assert!(aggregate_runner_replay_report(&source, &retained, &snapshot, &missing).is_err());

    let foreign = temp.path().join("other-recording");
    fs::create_dir(&foreign).unwrap();
    report["case_dir"] = json!(foreign);
    fs::write(&retained, report.to_string()).unwrap();
    assert!(
        aggregate_runner_replay_report(&source, &retained, &snapshot, &options)
            .unwrap_err()
            .to_string()
            .contains("outside case source")
    );
    report["case_dir"] = json!(source);
    report["cases"][1]["case_id"] = json!("foreign-case");
    report["selected_case_ids"] = json!(["case-a", "foreign-case"]);
    fs::write(&retained, report.to_string()).unwrap();
    assert!(aggregate_runner_replay_report(&source, &retained, &snapshot, &options).is_err());
}

#[test]
fn runner_report_path_must_stay_in_recording_or_selected_snapshot() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let snapshot = temp.path().join("snapshot");
    fs::create_dir(&snapshot).unwrap();
    let report = report_value_v7(&source, &[("case-a", "ended")], "session", true);
    write_case(&source.join("case-a"), true);
    let outside = temp.path().join("replay-report.json");
    fs::write(&outside, report.to_string()).unwrap();
    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-a".into()]),
        session_ids: BTreeSet::from(["session".into()]),
    };
    assert!(aggregate_runner_replay_report(&source, &outside, &snapshot, &options).is_err());
    let linked = snapshot.join("replay-report.json");
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    assert!(aggregate_runner_replay_report(&source, &linked, &snapshot, &options).is_err());
    // Public discovery retains its original confinement, even via a symlink.
    let discovered = source.join("replay-report.json");
    std::os::unix::fs::symlink(&outside, &discovered).unwrap();
    assert!(aggregate_replay_reports(&source).is_err());
}

#[test]
fn loaded_runner_report_preserves_shared_session_evidence_without_reading_another_copy() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let snapshot = temp.path().join("snapshot");
    fs::create_dir(&snapshot).unwrap();
    write_case(&source.join("case-a"), true);
    write_case(&source.join("case-b"), true);
    let mut report = report_value_v7(
        &source,
        &[("case-a", "ended"), ("case-b", "ended")],
        "session",
        true,
    );
    report["unused_case_http_exchanges"] = json!([{"case_id":"case-b"}]);
    let path = snapshot.join("replay-report.json");
    fs::write(&path, report.to_string()).unwrap();
    let options = ReplayAggregateOptions {
        case_ids: BTreeSet::from(["case-a".into()]),
        session_ids: BTreeSet::from(["session".into()]),
    };
    let from_file = aggregate_runner_replay_report(&source, &path, &snapshot, &options).unwrap();
    // The caller owns the already loaded snapshot. Reading the file a second
    // time would fail; confinement and membership checks must still run.
    fs::write(&path, b"not JSON").unwrap();
    let from_value =
        aggregate_runner_replay_report_value(&source, &path, &snapshot, &report, &options).unwrap();
    assert_eq!(
        serde_json::to_value(from_value).unwrap(),
        serde_json::to_value(from_file).unwrap()
    );
    assert!(aggregate_runner_replay_report(&source, &path, &snapshot, &options).is_err());

    for field in ["version", "case_dir", "finalized_at", "selected_case_ids"] {
        let mut invalid = report.clone();
        invalid[field] = Value::Null;
        assert!(
            aggregate_runner_replay_report_value(&source, &path, &snapshot, &invalid, &options)
                .is_err(),
            "{field}"
        );
    }
    let mut foreign_case = report.clone();
    foreign_case["cases"][1]["case_id"] = json!("foreign");
    foreign_case["selected_case_ids"] = json!(["case-a", "foreign"]);
    assert!(
        aggregate_runner_replay_report_value(&source, &path, &snapshot, &foreign_case, &options)
            .is_err()
    );
    let mut stale = options.clone();
    stale.session_ids = BTreeSet::from(["other-session".into()]);
    assert!(
        aggregate_runner_replay_report_value(&source, &path, &snapshot, &report, &stale).is_err()
    );
    let mut missing = options.clone();
    missing.case_ids.insert("missing".into());
    assert!(
        aggregate_runner_replay_report_value(&source, &path, &snapshot, &report, &missing).is_err()
    );
    let outside = temp.path().join("outside.json");
    fs::write(&outside, "{}").unwrap();
    assert!(
        aggregate_runner_replay_report_value(&source, &outside, &snapshot, &report, &options)
            .is_err()
    );
    let linked = snapshot.join("linked-report.json");
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    assert!(
        aggregate_runner_replay_report_value(&source, &linked, &snapshot, &report, &options)
            .is_err()
    );
    fs::remove_file(&path).unwrap();
    assert!(
        aggregate_runner_replay_report_value(&source, &path, &snapshot, &report, &options).is_err()
    );
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
        report_value_v7(&source.join("api"), &[("case-a", "ended")], first, true),
    );
    write_session_report(
        &source,
        "api",
        "attempt-two",
        report_value_v7(&source.join("api"), &[("case-a", "ended")], second, true),
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
fn unfinalized_report_is_not_complete() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    write_session_report(
        &source,
        "api",
        "unfinished",
        report_value_v7(
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
fn version_seven_uses_total_success_counts_beyond_retained_details() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended")],
        "00000000-0000-4000-8000-000000000051",
        true,
    );
    report["success_detail_limit"] = json!(100);
    report["builtin_queries"] = json!([{"index": 0}]);
    report["builtin_query_count"] = json!(6_592);
    report["matched_queries"] = json!([{"index": 0}, {"index": 1}]);
    report["matched_query_count"] = json!(2_295);
    report["matched_http_exchanges"] = json!([{"index": 0}]);
    report["matched_http_exchange_count"] = json!(202);
    report["motan"] = protocol_value(0, 1, 0, 0, 0, 0, 0);
    for protocol in ["redis", "memcached", "kafka", "motan"] {
        report[protocol]["matched_count"] = json!(0);
    }
    report["motan"]["matched_count"] = json!(7);
    write_session_report(&source, "api", "v6", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.complete);
    assert_eq!(aggregate.counts.events.mysql.builtin_queries, 6_592);
    assert_eq!(aggregate.counts.events.mysql.matched_queries, 2_295);
    assert_eq!(aggregate.counts.events.http.matched_exchanges, 202);
    assert_eq!(aggregate.counts.events.motan.matched, 7);
}

#[test]
fn version_seven_accepts_success_details_bounded_per_case() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("recording");
    let mut report = report_value_v7(
        &source.join("api"),
        &[("case-a", "ended"), ("case-b", "ended")],
        "00000000-0000-4000-8000-000000000052",
        true,
    );
    report["success_detail_scope"] = json!("case");
    report["matched_queries"] = Value::Array(
        (0..100)
            .map(|index| json!({"case_id":"case-a","index":index}))
            .chain((0..75).map(|index| json!({"case_id":"case-b","index":index})))
            .collect(),
    );
    report["matched_query_count"] = json!(225);
    write_session_report(&source, "api", "per-case", report);

    let aggregate = aggregate_replay_reports(&source).unwrap();

    assert!(aggregate.complete);
    assert_eq!(aggregate.counts.events.mysql.matched_queries, 225);
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
        report_value_v7(&source.join("api"), &[("case-a", "ended")], session, true),
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
        "session_id": "00000000-0000-4000-8000-000000000001",
        "started_at": "2026-07-14T00:00:00Z",
        "finalized_at": "2026-07-14T00:01:00Z",
        "finalized": true,
        "case_dir": case_dir,
        "cases": cases.iter().map(|(case_id, status)| json!({
            "case_id": case_id,
            "status": status,
        })).collect::<Vec<_>>(),
        "selected_case_ids": cases.iter().map(|(case_id, _)| json!(case_id)).collect::<Vec<_>>(),
        "success_detail_limit": 100,
        "connections": 1,
        "builtin_query_count": 0,
        "builtin_queries": [],
        "matched_query_count": matched_queries,
        "matched_queries": [],
        "unmatched_queries": [],
        "unsupported_commands": [],
        "metadata_warnings": [],
        "unused_global_exchanges": [],
        "unused_case_exchanges": [],
        "matched_http_exchange_count": 0,
        "matched_http_exchanges": [],
        "unmatched_http_requests": [],
        "unsupported_http_exchanges": [],
        "unused_global_http_exchanges": [],
        "unused_case_http_exchanges": [],
        "allowed_unused_case_http_exchanges": [],
    });
    report["matched_queries"] = Value::Array(
        (0..matched_queries)
            .map(|index| json!({"index": index}))
            .collect(),
    );
    for protocol in ["redis", "memcached", "kafka", "motan"] {
        report[protocol] = protocol_value(0, 0, 0, 0, 0, 0, 0);
        report[protocol]["matched_count"] = json!(0);
    }
    report
}

fn report_value_v7(
    case_dir: &Path,
    cases: &[(&str, &str)],
    session_id: &str,
    finalized: bool,
) -> Value {
    let mut report = report_value(7, case_dir, cases, 0);
    report["session_id"] = json!(session_id);
    report["started_at"] = json!("2026-07-14T00:00:00Z");
    report["finalized"] = json!(finalized);
    if finalized {
        report["finalized_at"] = json!("2026-07-14T00:01:00Z");
    }
    report["selected_case_ids"] =
        Value::Array(cases.iter().map(|(case_id, _)| json!(case_id)).collect());
    report
}

fn protocol_value(
    connections: usize,
    matched: usize,
    unmatched: usize,
    unsupported: usize,
    unsafe_events: usize,
    unused_case: usize,
    unused_global: usize,
) -> Value {
    let mut value = Map::new();
    value.insert("connections".to_owned(), json!(connections));
    value.insert("matched_count".to_owned(), json!(matched));
    for (name, count) in [
        ("matched", matched),
        ("unmatched", unmatched),
        ("unsupported", unsupported),
        ("unsafe_events", unsafe_events),
        ("unused_case", unused_case),
        ("unused_global", unused_global),
    ] {
        value.insert(
            name.to_owned(),
            Value::Array(
                (0..count)
                    .map(|index| {
                        if name == "unused_global" {
                            json!({"index": index})
                        } else {
                            json!({"index": index, "case_id": "case-a"})
                        }
                    })
                    .collect(),
            ),
        );
    }
    Value::Object(value)
}
