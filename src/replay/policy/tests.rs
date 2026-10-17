use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chrono::{TimeZone, Utc};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::config::{ExpectedResponseUsage, validate_replay_policy};
use super::matcher::{
    HttpPolicyContext, MemcachedPolicyContext, MysqlPolicyContext, ReplayPolicyRuntime,
};
use crate::replay::{
    RecordedMysqlValue, ReplayCase, ReplayCaseStatus, ReplaySessionIdentity, TargetKey,
};

const CASE_ID: &str = "case-1";

mod case_conditions;
mod mysql_matching_benchmark;
mod mysql_relative_time;
mod mysql_tables;

fn anchor_sql_times(runtime: &ReplayPolicyRuntime, target: chrono::DateTime<Utc>) {
    runtime.request_contracts.set_request_times(
        CASE_ID,
        crate::replay::assertion::RequestTimes {
            source: Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()),
            target: Some(target),
        },
    );
}

#[test]
fn compact_sql_time_rule_matches_across_api_paths_but_not_databases() {
    let fixture = policy_fixture(
        "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: last-use\n  protocol: mysql\n  mysql:\n    database: pluto_audit\n    sql: UPDATE api_keys SET last_used_at=? WHERE id=?\n    sql_values: {0: {time: replay_now, tolerance: 5s}}\n",
    );
    let now = Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 0).unwrap();
    for (method, path) in [("GET", "/responses/7"), ("POST", "/documents/content")] {
        fs::write(
            fixture.cases[CASE_ID].dir.join("request.json"),
            json!({"method":method,"uri":path,"timestamp":"2020-01-01T00:00:00Z"}).to_string(),
        )
        .unwrap();
        let runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
        anchor_sql_times(&runtime, now);
        for database in ["pluto_audit", "other_database"] {
            let mut identity = mysql_identity();
            identity.database = Some(database.into());
            let context = MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_STMT_EXECUTE",
                recorded_sql: Some(
                    "UPDATE api_keys SET last_used_at='2020-01-01 00:00:00.123456' WHERE id=7",
                ),
                sql: Some(
                    "UPDATE api_keys SET last_used_at='2026-09-07 12:00:01.123456' WHERE id=7",
                ),
                recorded: None,
                actual: None,
            };
            let decision = runtime.preview_mysql_sql_values(&context);
            if database == "pluto_audit" {
                assert!(decision.unwrap().is_ok(), "{path}");
            } else {
                assert!(decision.is_none());
            }
        }
    }
}

#[test]
fn sql_time_rule_validates_scalar_and_nested_json_locations_atomically() {
    let fixture = policy_fixture(
        r#"
version: 3
expected_response: assertions_only
dependency_rules:
- id: kind-times
  protocol: mysql
  mysql:
    database: pluto_audit
    sql: UPDATE kinds SET json=?, updated_at=? WHERE id=?
    sql_values:
      0:
        json:
          /spec/observedAt: {time: replay_now, tolerance: 5s, format: "%+"}
      1: {time: replay_now, tolerance: 5s}
"#,
    );
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    let sql = "UPDATE kinds SET json=?, updated_at=? WHERE id=?";
    let recorded = values(&[
        json!(r#"{"name":"stable","spec":{"observedAt":"2020-01-01T00:00:00+00:00"}}"#),
        json!("2020-01-01 00:00:00.000000"),
        json!(7),
    ]);
    let actual = values(&[
        json!(r#"{"spec":{"observedAt":"2026-09-07T12:00:01+00:00"},"name":"stable"}"#),
        json!("2026-09-07 12:00:01.000000"),
        json!(7),
    ]);
    let now = Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 1).unwrap();
    anchor_sql_times(&runtime, now);
    let context = |actual| MysqlPolicyContext {
        case_id: Some(CASE_ID),
        identity: &identity,
        command: "COM_STMT_EXECUTE",
        recorded_sql: Some(sql),
        sql: Some(sql),
        recorded: Some(&recorded),
        actual: Some(actual),
    };

    let decision = runtime
        .preview_mysql_sql_values(&context(&actual))
        .unwrap()
        .unwrap();
    runtime.commit(Some(CASE_ID), decision);
    assert_eq!(runtime.report().dependency_rules[0].time_validations, 2);

    let changed_stable_json = values(&[
        json!(r#"{"name":"changed","spec":{"observedAt":"2026-09-07T12:00:01+00:00"}}"#),
        json!("2026-09-07 12:00:01.000000"),
        json!(7),
    ]);
    assert!(
        runtime
            .preview_mysql_sql_values(&context(&changed_stable_json))
            .unwrap()
            .unwrap_err()
            .contains("stable MySQL JSON fields differ")
    );

    let stale_scalar = values(&[
        json!(r#"{"name":"stable","spec":{"observedAt":"2026-09-07T12:00:01+00:00"}}"#),
        json!("2020-01-01 00:00:00.000000"),
        json!(7),
    ]);
    assert!(
        runtime
            .preview_mysql_sql_values(&context(&stale_scalar))
            .unwrap()
            .unwrap_err()
            .contains("fixed tolerance")
    );
}

#[test]
fn validates_unified_policy_example() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("policy.example.yaml");
    let report = validate_replay_policy(&path).unwrap();

    assert_eq!(report.version, 1);
    assert!(report.runner_owned_response_assertions);
}

#[test]
fn rejects_removed_version_two_policy_contract() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("policy.yaml");
    fs::write(
        &path,
        "version: 2\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let error = validate_replay_policy(&path).unwrap_err();
    assert!(format!("{error:#}").contains("traffic-policy/v1"));
}

#[test]
fn rejects_legacy_rules_key() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("policy.yaml");
    fs::write(
        &path,
        "version: 3\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let error = validate_replay_policy(&path).unwrap_err();
    assert!(format!("{error:#}").contains("traffic-policy/v1"));
}

#[test]
fn validates_assertion_only_policy_contract() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("replay.yaml");
    crate::replay::write_policy_fixture(
        &path,
        r#"
version: 1
expected_response: assertions_only
dependency_rules: []
"#,
    )
    .unwrap();

    let report = validate_replay_policy(&path).unwrap();
    assert_eq!(report.version, 1);
    assert_eq!(
        report.expected_response,
        ExpectedResponseUsage::AssertionsOnly
    );
    assert!(report.dependency_rule_ids.is_empty());
    assert!(report.fingerprint.starts_with("sha256:"));
}

#[test]
fn loads_motan_case_without_http_request_metadata() {
    let fixture = policy_fixture(
        r#"
version: 1
expected_response: assertions_only
dependency_rules: []
"#,
    );
    fs::write(
        fixture.cases[CASE_ID].dir.join("case.json"),
        r#"{"version":1,"kind":"motan_rpc"}"#,
    )
    .unwrap();
    fs::write(
        fixture.cases[CASE_ID].dir.join("request.json"),
        r#"{"protocol_version":"motan2","request_id":42}"#,
    )
    .unwrap();

    ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
}

#[test]
fn rejects_policy_without_expected_response_contract() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("replay.yaml");
    fs::write(&path, "version: 1\ndependency_rules: []\n").unwrap();

    let error = validate_replay_policy(&path).unwrap_err();
    assert!(error.to_string().contains("traffic-policy/v1"));
}

#[test]
fn binds_and_references_runtime_mysql_uuid() {
    let fixture = policy_fixture(mysql_policy());
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    observe_mysql_policy_exchanges(&mut runtime, &identity);
    let now = Utc.with_ymd_and_hms(2026, 7, 15, 4, 30, 0).unwrap();
    runtime.request_contracts.set_request_times(
        CASE_ID,
        crate::replay::assertion::RequestTimes {
            source: Some(now),
            target: Some(now),
        },
    );
    let recorded_insert = values(&[
        json!("11111111-1111-4111-8111-111111111111"),
        json!("2026-07-15 12:30:00"),
    ]);
    let actual_insert = values(&[
        json!("22222222-2222-4222-8222-222222222222"),
        json!("2026-07-15 12:30:01"),
    ]);
    let insert_context = MysqlPolicyContext {
        case_id: Some(CASE_ID),
        identity: &identity,
        command: "COM_STMT_EXECUTE",
        recorded_sql: Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
        sql: Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
        recorded: Some(&recorded_insert),
        actual: Some(&actual_insert),
    };
    let changed_table = MysqlPolicyContext {
        case_id: Some(CASE_ID),
        identity: &identity,
        command: "COM_STMT_EXECUTE",
        recorded_sql: insert_context.recorded_sql,
        sql: Some("INSERT INTO request_log_202606 (uuid, request_time) VALUES (?, ?)"),
        recorded: Some(&recorded_insert),
        actual: Some(&actual_insert),
    };
    assert!(
        preview_mysql_contract(&runtime, &changed_table, now)
            .unwrap_err()
            .contains("physical")
    );
    assert!(runtime.allows_mysql_sql_difference(&insert_context));
    let insert = preview_mysql_contract(&runtime, &insert_context, now).unwrap();
    runtime.commit(Some(CASE_ID), insert);

    let recorded_update = values(&[json!("11111111-1111-4111-8111-111111111111")]);
    let actual_update = values(&[json!("22222222-2222-4222-8222-222222222222")]);
    let update = preview_mysql_contract(
        &runtime,
        &MysqlPolicyContext {
            case_id: Some(CASE_ID),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some("UPDATE request_log_202607 SET response_status=200 WHERE uuid=?"),
            sql: Some("UPDATE request_log_202607 SET response_status=200 WHERE uuid=?"),
            recorded: Some(&recorded_update),
            actual: Some(&actual_update),
        },
        now,
    )
    .unwrap();
    runtime.commit(Some(CASE_ID), update);

    let report = runtime.report();
    assert!(report.unused_applicable_dependency_rule_ids.is_empty());
    assert_eq!(report.dependency_rules[0].binds, 1);
    assert_eq!(report.dependency_rules[0].time_validations, 1);
    assert_eq!(report.dependency_rules[1].references, 1);
}

#[test]
fn rejects_changed_reference_and_out_of_window_time() {
    let fixture = policy_fixture(mysql_policy());
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    observe_mysql_policy_exchanges(&mut runtime, &identity);
    let now = Utc.with_ymd_and_hms(2026, 7, 15, 4, 30, 0).unwrap();
    runtime.request_contracts.set_request_times(
        CASE_ID,
        crate::replay::assertion::RequestTimes {
            source: Some(now),
            target: Some(now),
        },
    );
    let recorded_insert = values(&[
        json!("11111111-1111-4111-8111-111111111111"),
        json!("2026-07-15 12:30:00"),
    ]);
    let bad_time = values(&[
        json!("22222222-2222-4222-8222-222222222222"),
        json!("2026-07-15 13:30:00"),
    ]);
    assert!(
        preview_mysql_contract(
            &runtime,
            &MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_STMT_EXECUTE",
                recorded_sql: Some(
                    "INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)",
                ),
                sql: Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)",),
                recorded: Some(&recorded_insert),
                actual: Some(&bad_time),
            },
            now,
        )
        .unwrap_err()
        .contains("SQL value contract failed")
    );

    let actual_insert = values(&[
        json!("22222222-2222-4222-8222-222222222222"),
        json!("2026-07-15 12:30:00"),
    ]);
    let mut wrong_kind = actual_insert.clone();
    wrong_kind[0].kind = "bytes".to_string();
    assert!(
        preview_mysql_contract(
            &runtime,
            &MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_STMT_EXECUTE",
                recorded_sql: Some(
                    "INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)",
                ),
                sql: Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)",),
                recorded: Some(&recorded_insert),
                actual: Some(&wrong_kind),
            },
            now,
        )
        .unwrap_err()
        .contains("parameter kind changed")
    );
    let decision = preview_mysql_contract(
        &runtime,
        &MysqlPolicyContext {
            case_id: Some(CASE_ID),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
            sql: Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
            recorded: Some(&recorded_insert),
            actual: Some(&actual_insert),
        },
        now,
    )
    .unwrap();
    runtime.commit(Some(CASE_ID), decision);
    let wrong_update = values(&[json!("33333333-3333-4333-8333-333333333333")]);
    let recorded_update = values(&[json!("11111111-1111-4111-8111-111111111111")]);
    assert!(
        preview_mysql_contract(
            &runtime,
            &MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_STMT_EXECUTE",
                recorded_sql: Some(
                    "UPDATE request_log_202607 SET response_status=200 WHERE uuid=?",
                ),
                sql: Some("UPDATE request_log_202607 SET response_status=200 WHERE uuid=?"),
                recorded: Some(&recorded_update),
                actual: Some(&wrong_update),
            },
            now,
        )
        .unwrap_err()
        .contains("did not match its bound value")
    );
}

#[test]
fn validates_memcached_protobuf_timestamp_without_exposing_literals() {
    let fixture = policy_fixture(memcached_policy());
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let target = TargetKey {
        host: "cache.internal".to_string(),
        port: 11211,
    };
    runtime.observe_recorded_memcached_exchange(Some(CASE_ID), &target, "set", Some(b"u42"));
    let recorded_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let actual_at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let recorded = protobuf_user_info(1_699_999_995, b"stable");
    let actual = protobuf_user_info(1_799_999_995, b"stable");
    let decision = runtime
        .preview_memcached(&MemcachedPolicyContext {
            case_id: Some(CASE_ID),
            target: &target,
            command: "set",
            key: Some(b"u42"),
            recorded_value: Some(&recorded),
            actual_value: Some(&actual),
            recorded_observed_at: recorded_at,
            recorded_duration_ms: 0,
            actual_observed_at: actual_at,
        })
        .unwrap();
    runtime.commit(Some(CASE_ID), decision);

    let report = runtime.report();
    assert_eq!(report.dependency_rules[0].matches, 1);
    assert_eq!(report.dependency_rules[0].time_validations, 1);
    assert!(report.unused_applicable_dependency_rule_ids.is_empty());
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("1699999995"));
    assert!(!serialized.contains("1800000005"));

    let other_host_same_port = TargetKey {
        host: "another-cache.internal".to_string(),
        port: 11211,
    };
    assert!(
        runtime
            .preview_memcached(&MemcachedPolicyContext {
                case_id: Some(CASE_ID),
                target: &other_host_same_port,
                command: "set",
                key: Some(b"u42"),
                recorded_value: Some(&recorded),
                actual_value: Some(&actual),
                recorded_observed_at: recorded_at,
                recorded_duration_ms: 0,
                actual_observed_at: actual_at,
            })
            .is_err()
    );

    let same_host_other_port = TargetKey {
        host: "cache.internal".to_string(),
        port: 11212,
    };
    let changed_stable_value = protobuf_user_info(1_800_000_005, b"changed");
    assert!(
        runtime
            .preview_memcached(&MemcachedPolicyContext {
                case_id: Some(CASE_ID),
                target: &same_host_other_port,
                command: "set",
                key: Some(b"u42"),
                recorded_value: Some(&recorded),
                actual_value: Some(&changed_stable_value),
                recorded_observed_at: recorded_at,
                recorded_duration_ms: 0,
                actual_observed_at: actual_at,
            })
            .unwrap_err()
            .contains("value did not match")
    );
}

#[test]
fn rejects_memcached_contract_without_an_executable_resource_and_value_slot() {
    for invalid in 0..4 {
        let fixture = policy_fixture(memcached_policy());
        let mut policy =
            crate::policy::parse_policy(&fs::read_to_string(&fixture.policy_path).unwrap())
                .unwrap();
        let rule = policy.rules[0].as_value_mut().unwrap();
        match invalid {
            0 => rule.selector.resource = None,
            1 => rule.selector.resource.as_mut().unwrap().endpoint.port = 0,
            2 => rule.selector.operation = Some("APPEND".into()),
            _ => rule.selector.key = Some(crate::policy::KeySelector::default()),
        }
        fs::write(
            &fixture.policy_path,
            serde_yaml::to_string(&policy).unwrap(),
        )
        .unwrap();
        assert!(ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).is_err());
    }
}

#[test]
fn validates_scoped_http_query_fields() {
    let fixture = policy_fixture(http_policy());
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 7, 15, 4, 30, 0).unwrap();
    runtime.request_contracts.set_request_times(
        CASE_ID,
        crate::replay::assertion::RequestTimes {
            source: Some(now),
            target: Some(now),
        },
    );
    runtime.observe_recorded_http_exchange(
        Some(CASE_ID),
        &TargetKey {
            host: "ecs.aliyuncs.com".to_string(),
            port: 443,
        },
        "GET",
        "/?Action=DescribeInstances&SignatureNonce=recorded",
    );
    let decision = runtime
        .preview_http(
            &HttpPolicyContext {
                case_id: Some(CASE_ID),
                target: &TargetKey {
                    host: "ecs.aliyuncs.com".to_string(),
                    port: 443,
                },
                method: "GET",
                recorded_uri: "/?Action=DescribeInstances&SignatureNonce=11111111111141118111111111111111&Timestamp=2026-07-15T04%3A29%3A59Z&Signature=old",
                actual_uri: "/?Action=DescribeInstances&SignatureNonce=22222222222242228222222222222222&Timestamp=2026-07-15T04%3A30%3A01Z&Signature=new",
            },
            Utc.with_ymd_and_hms(2026, 7, 15, 4, 30, 0).unwrap(),
        )
        .unwrap();
    assert_eq!(
        decision.dynamic_query_params,
        vec!["Signature", "SignatureNonce", "Timestamp"]
    );
    assert!(
        runtime
            .reject_http_ignore_overlap(&["SignatureNonce".to_string()])
            .unwrap_err()
            .to_string()
            .contains("both replay-policy fields and global ignores")
    );
}

#[test]
fn unscoped_rules_are_applicable_only_with_matching_recorded_dependencies() {
    let fixture = policy_fixture(mysql_policy());
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();

    assert!(
        runtime
            .report()
            .dependency_rules
            .iter()
            .all(|rule| !rule.applicable)
    );
    runtime.observe_recorded_mysql_exchange(
        None,
        &identity,
        "COM_STMT_EXECUTE",
        Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
    );
    assert!(
        runtime
            .report()
            .dependency_rules
            .iter()
            .all(|rule| !rule.applicable)
    );
    runtime.observe_recorded_mysql_exchange(
        Some(CASE_ID),
        &identity,
        "COM_STMT_EXECUTE",
        Some("SELECT 1"),
    );
    assert!(
        runtime
            .report()
            .dependency_rules
            .iter()
            .all(|rule| !rule.applicable)
    );

    runtime.observe_recorded_mysql_exchange(
        Some(CASE_ID),
        &identity,
        "COM_STMT_EXECUTE",
        Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
    );
    let report = runtime.report();
    assert!(report.dependency_rules[0].applicable);
    assert!(!report.dependency_rules[1].applicable);
    assert_eq!(
        report.unused_applicable_dependency_rule_ids,
        vec!["audit-insert"]
    );
}

#[test]
fn scoped_and_unscoped_rules_compose_on_disjoint_mysql_params() {
    let fixture = policy_fixture(composed_mysql_policy());
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    let sql = "UPDATE request_log_202607 SET elapsed=?, response_data=? WHERE uuid=?";
    runtime.observe_recorded_mysql_exchange(
        Some(CASE_ID),
        &identity,
        "COM_STMT_EXECUTE",
        Some(sql),
    );
    let recorded = values(&[json!(10), json!("old"), json!("request-id")]);
    let actual = values(&[json!(20), json!("new"), json!("request-id")]);

    let decision = preview_mysql_contract(
        &runtime,
        &MysqlPolicyContext {
            case_id: Some(CASE_ID),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some(sql),
            sql: Some(sql),
            recorded: Some(&recorded),
            actual: Some(&actual),
        },
        Utc::now(),
    )
    .unwrap();
    runtime.commit(Some(CASE_ID), decision);

    let report = runtime.report();
    assert_eq!(report.dependency_rules[0].matches, 1);
    assert_eq!(report.dependency_rules[1].matches, 1);
    assert!(report.unused_applicable_dependency_rule_ids.is_empty());
}

fn preview_mysql_contract(
    runtime: &ReplayPolicyRuntime,
    context: &MysqlPolicyContext<'_>,
    observed: chrono::DateTime<Utc>,
) -> Result<super::matcher::DependencyRuleDecision, String> {
    let record = serde_json::from_value(json!({
        "connection_id":uuid::Uuid::nil(), "query_sequence":1,
        "target_host":context.identity.target.as_ref().unwrap().host,
        "target_port":context.identity.target.as_ref().unwrap().port,
        "database":context.identity.database, "username":context.identity.username,
        "command":context.command,"sql":context.recorded_sql,"params":context.recorded,
        "response":{"status":"ok"},"outcome":"response","parse_warnings":[]
    }))
    .unwrap();
    runtime
        .request_contracts
        .preview_mysql_values(
            context.case_id,
            context.identity,
            &record,
            context.command,
            context.sql,
            context.actual,
            observed,
            runtime,
        )
        .expect("explicit native SQL contract must select its Source physical statement")
}

struct PolicyFixture {
    policy_path: std::path::PathBuf,
    cases: BTreeMap<String, ReplayCase>,
    _temp: TempDir,
}

fn policy_fixture(policy: &str) -> PolicyFixture {
    let temp = TempDir::new().unwrap();
    let case_dir = temp.path().join(CASE_ID);
    fs::create_dir_all(&case_dir).unwrap();
    fs::write(
        case_dir.join("request.json"),
        r#"{
  "timestamp": "2020-01-01T00:00:00Z",
  "client_addr": "127.0.0.1:12345",
  "method": "GET",
  "uri": "/api/resource/token",
  "authority": "pluto.example",
  "matched_rule": "pluto",
  "upstream": "http://127.0.0.1:8080",
  "headers": {"accept": ["application/json"]},
  "body": {"encoding": "utf8", "data": ""},
  "future_extension": {"version": 2}
}"#,
    )
    .unwrap();
    fs::write(case_dir.join("expected-response.json"), "{}").unwrap();
    fs::write(case_dir.join("dependencies.jsonl"), "").unwrap();
    let policy_path = temp.path().join("replay.yaml");
    let mut synthetic: serde_yaml::Value = serde_yaml::from_str(policy).unwrap();
    for rule in synthetic["dependency_rules"]
        .as_sequence_mut()
        .into_iter()
        .flatten()
    {
        if rule["protocol"].as_str() == Some("mysql") && rule["target"].is_null() {
            rule["target"] =
                serde_yaml::from_str("{host: audit.example.test, port: 3306}").unwrap();
            rule["mysql"]["command"] = serde_yaml::Value::String("COM_STMT_EXECUTE".into());
        }
        if rule["protocol"].as_str() == Some("memcached") && rule["target"].is_null() {
            rule["target"] = serde_yaml::from_str("{host: cache.internal, port: 11211}").unwrap();
        }
    }
    crate::replay::write_policy_fixture(&policy_path, serde_yaml::to_string(&synthetic).unwrap())
        .unwrap();
    let cases = BTreeMap::from([(
        CASE_ID.to_string(),
        ReplayCase {
            id: CASE_ID.to_string(),
            dir: case_dir.clone(),
            dependencies_path: case_dir.join("dependencies.jsonl"),
            status: ReplayCaseStatus::Active,
        },
    )]);
    PolicyFixture {
        policy_path,
        cases,
        _temp: temp,
    }
}

fn mysql_policy() -> &'static str {
    r#"
version: 1
expected_response: assertions_only
dependency_rules:
  - id: audit-insert
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      sql: "INSERT INTO {{table}} (uuid, request_time) VALUES (?, ?)"
      tables: [request_log_202606, request_log_202607]
      database: pluto_audit
      username: audit_user
      params:
        0:
          bind: audit_id
          validate: uuid_v4
        1:
          time:
            relative_to: replay_now
            tolerance: 5s
            format: "%Y-%m-%d %H:%M:%S"
            timezone: "+08:00"
  - id: audit-update
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      sql: "UPDATE {{table}} SET response_status=200 WHERE uuid=?"
      tables: [request_log_202606, request_log_202607]
      database: pluto_audit
      username: audit_user
      params:
        0:
          ref: audit_id
"#
}

fn http_policy() -> &'static str {
    r#"
version: 1
expected_response: assertions_only
dependency_rules:
  - id: aliyun-signature
    protocol: http
    target:
      host: ecs.aliyuncs.com
      port: 443
    http:
      method: GET
      path: /
      query:
        Signature:
          validate: non_empty
        SignatureNonce:
          validate: uuid_v4
        Timestamp:
          time:
            relative_to: replay_now
            tolerance: 5s
"#
}

fn memcached_policy() -> &'static str {
    r#"
version: 1
expected_response: assertions_only
dependency_rules:
  - id: user-info-loading-time
    protocol: memcached
    memcached:
      resource:
        kind: cache_service
        port: 11211
      command: set
      key:
        prefix: u
        suffix: ''
      protobuf:
        timestamp_fields:
          50:
            mechanism: unix_seconds
            source_evidence: UserInfoServiceBase.java:438 current time
"#
}

fn protobuf_user_info(timestamp: u64, stable: &[u8]) -> Vec<u8> {
    let mut value = vec![0x08, 0x07, 0x90, 0x03];
    encode_varint(timestamp, &mut value);
    value.extend_from_slice(&[0x12, stable.len() as u8]);
    value.extend_from_slice(stable);
    value
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn composed_mysql_policy() -> &'static str {
    r#"
version: 1
expected_response: assertions_only
dependency_rules:
  - id: audit-update
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      sql: "UPDATE {{table}} SET elapsed=?, response_data=? WHERE uuid=?"
      tables: [request_log_202606, request_log_202607]
      database: pluto_audit
      username: audit_user
      params:
        0:
          bind: audit_elapsed
  - id: resource-token-audit-response
    case:
      method: GET
      path: /api/resource/token
    protocol: mysql
    target:
      host: audit.example.test
      port: 3306
    mysql:
      command: COM_STMT_EXECUTE
      sql: "UPDATE {{table}} SET elapsed=?, response_data=? WHERE uuid=?"
      tables: [request_log_202606, request_log_202607]
      database: pluto_audit
      username: audit_user
      params:
        1:
          validate: non_empty
"#
}

fn observe_mysql_policy_exchanges(
    runtime: &mut ReplayPolicyRuntime,
    identity: &ReplaySessionIdentity,
) {
    runtime.observe_recorded_mysql_exchange(
        Some(CASE_ID),
        identity,
        "COM_STMT_EXECUTE",
        Some("INSERT INTO request_log_202607 (uuid, request_time) VALUES (?, ?)"),
    );
    runtime.observe_recorded_mysql_exchange(
        Some(CASE_ID),
        identity,
        "COM_STMT_EXECUTE",
        Some("UPDATE request_log_202607 SET response_status=200 WHERE uuid=?"),
    );
}

fn mysql_identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "audit.example.test".to_string(),
            port: 3306,
        }),
        database: Some("pluto_audit".to_string()),
        username: Some("audit_user".to_string()),
    }
}

fn values(values: &[Value]) -> Vec<RecordedMysqlValue> {
    values
        .iter()
        .map(|value| RecordedMysqlValue {
            kind: match value {
                Value::String(_) => "string",
                Value::Number(_) => "integer",
                _ => "unknown",
            }
            .to_string(),
            value: Some(value.clone()),
            raw: None,
        })
        .collect()
}
