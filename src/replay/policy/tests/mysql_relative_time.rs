use super::*;
use crate::replay::assertion::RequestTimes;

fn fixture() -> PolicyFixture {
    policy_fixture(
        "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: relative-time\n  protocol: mysql\n  mysql:\n    database: pluto_audit\n    sql: UPDATE subtasks_0155 SET updated_at=? WHERE id=?\n    sql_values: {0: {time: preserve_relative}}\n",
    )
}

#[test]
fn sql_time_compares_relative_differences_with_fixed_microsecond_boundary() {
    let fixture = fixture();
    let runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    let source_request = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    let target_request = Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 0).unwrap();
    anchor_sql_times(&runtime, target_request);
    // A common civil timezone and a moving cutoff both cancel. The target's
    // absolute distance from replay_now is deliberately many hours here.
    for hours in [-24, -8, 0, 8] {
        let source = format!(
            "UPDATE subtasks_0155 SET updated_at='{}' WHERE id=7",
            (source_request + chrono::Duration::hours(hours)).format("%Y-%m-%d %H:%M:%S%.6f")
        );
        for (micros, passes) in [
            (0, true),
            (5_000_000, true),
            (-5_000_000, true),
            (5_000_001, false),
            (-5_000_001, false),
        ] {
            let actual = format!(
                "UPDATE subtasks_0155 SET updated_at='{}' WHERE id=7",
                (target_request
                    + chrono::Duration::hours(hours)
                    + chrono::Duration::microseconds(micros))
                .format("%Y-%m-%d %H:%M:%S%.6f")
            );
            let context = MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_QUERY",
                recorded_sql: Some(&source),
                sql: Some(&actual),
                recorded: None,
                actual: None,
            };
            assert_eq!(
                runtime.preview_mysql_sql_values(&context).unwrap().is_ok(),
                passes,
                "hours={hours}, micros={micros}"
            );
        }
    }
}

#[test]
fn sql_time_requires_both_request_anchors_and_does_not_reuse_a_previous_case_anchor() {
    let fixture = fixture();
    let mut runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    let source = "UPDATE subtasks_0155 SET updated_at='2020-01-01 08:00:00' WHERE id=7";
    let actual = "UPDATE subtasks_0155 SET updated_at='2026-09-07 20:00:00' WHERE id=7";
    let context = MysqlPolicyContext {
        case_id: Some(CASE_ID),
        identity: &identity,
        command: "COM_QUERY",
        recorded_sql: Some(source),
        sql: Some(actual),
        recorded: None,
        actual: None,
    };
    let target = Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 0).unwrap();
    anchor_sql_times(&runtime, target);
    let times = runtime.request_contracts.request_times(CASE_ID);
    for missing in [
        RequestTimes {
            source: None,
            ..times
        },
        RequestTimes {
            target: None,
            ..times
        },
    ] {
        runtime
            .request_contracts
            .set_request_times(CASE_ID, missing);
        assert!(runtime.preview_mysql_sql_values(&context).unwrap().is_err());
    }
    anchor_sql_times(&runtime, target);
    assert!(runtime.preview_mysql_sql_values(&context).unwrap().is_ok());
    runtime.begin_case(CASE_ID);
    assert!(runtime.preview_mysql_sql_values(&context).unwrap().is_err());
}

#[test]
fn sql_time_rejects_configurable_tolerance_and_normalizes_legacy_options() {
    for tolerance in ["0s", "2s", "6s", "1h"] {
        let yaml = format!("time: preserve_relative\ntolerance: {tolerance}");
        assert!(serde_yaml::from_str::<super::super::config::MysqlTimeValueRule>(&yaml).is_err());
    }
    let rule: super::super::config::MysqlTimeValueRule =
        serde_yaml::from_str("time: replay_now\ntolerance: 5s\ntimezone: '+08:00'\noffset: -24h")
            .unwrap();
    let encoded = serde_yaml::to_string(&rule).unwrap();
    assert!(encoded.contains("time: preserve_relative"));
    for omitted in ["tolerance", "timezone", "offset"] {
        assert!(!encoded.contains(omitted));
    }
}
