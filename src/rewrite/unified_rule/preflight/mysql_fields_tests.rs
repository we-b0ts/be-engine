//! The recorded default schema remains evidence, independent of the declaration.
use super::*;
use crate::policy::{CompiledPolicy, compile_policy, parse_policy};
use crate::value_contract::time::ClockPair;
use serde_json::json;

fn policy(surface: Surface, delivery: bool) -> CompiledPolicy {
    let mut declaration = json!({"id":"physical-time","surface":surface,
        "match":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"tables":["tasks"]},
        "slot":{"sql_field":"updated_at"},"codec":"scalar","contract":{"":{"relative_time":"sql_datetime"}},
        "proof":{"source":"models.py:clock","fact":"Only this physical schema owns the generated time"}});
    if delivery {
        declaration["delivery"] = json!({"rebase_time":[""]});
    }
    compile_policy(
        &parse_policy(&json!({"format":"traffic-policy/v2","rules":[declaration]}).to_string())
            .unwrap(),
    )
    .unwrap()
}

fn clocks() -> AnchorClocks {
    let pair = ClockPair {
        source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
        target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
    };
    AnchorClocks {
        case: pair,
        dependency: pair,
        delivery: pair,
    }
}

fn event(sql: &str, response: Value) -> Value {
    json!({"event_type":"mysql_exchange","target_host":"db.test","target_port":3306,"database":"other",
        "connection_id":uuid::Uuid::nil(),"query_sequence":1,"command":"COM_QUERY","sql":sql,
        "timestamp":"2020-01-01T00:00:00Z","duration_ms":0,"response":response,
        "outcome":"response","replay_safe":true})
}

#[test]
fn mixed_schema_request_source_witness_and_preflight_preserve_the_other_schema() {
    let policy = policy(Surface::DependencyRequest, false);
    let rule = &policy.rules[0];
    let sql = "SELECT a.id FROM app.tasks a JOIN tasks b ON a.id=b.id WHERE a.updated_at='2020-01-01 00:00:01' AND b.updated_at='2020-01-01 00:00:02'";
    let event = event(sql, json!({"status":"ok"}));
    assert!(selects(rule, &event).unwrap());
    let source = source_witness(Surface::DependencyRequest, &event, Path::new(".")).unwrap();
    let extracted = crate::replay::mysql_witness_values(
        &source,
        Surface::DependencyRequest,
        rule,
        Some("other"),
    )
    .unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].1, b"\"2020-01-01 00:00:01\"");
    assert!(
        crate::replay::mysql_witness_values(&source, Surface::DependencyRequest, rule, None)
            .unwrap()
            .is_empty()
    );
    let mut own_clocks = clocks();
    own_clocks.case.target = own_clocks.case.source;
    own_clocks.dependency.target = own_clocks.dependency.source;
    own_clocks.delivery.target = own_clocks.delivery.source;
    assert!(
        compare_source(
            Surface::DependencyRequest,
            &event,
            &source,
            &[rule],
            &[],
            own_clocks
        )
        .unwrap()
        .contains(&rule.rule.id)
    );
    let target_sql = sql.replace("a.updated_at='2020-01-01", "a.updated_at='2026-01-01");
    let mut target: Value = serde_json::from_slice(&source).unwrap();
    target["request_started_at"] = json!("2026-01-01T00:00:00Z");
    target["sql"] = json!(target_sql);
    assert_eq!(
        compare_pair(
            Surface::DependencyRequest,
            &event,
            &source,
            &serde_json::to_vec(&target).unwrap(),
            &[rule],
            &[],
            clocks()
        )
        .unwrap(),
        1
    );
    target["sql"] =
        json!(target_sql.replace("b.updated_at='2020-01-01", "b.updated_at='2026-01-01"));
    assert!(
        compare_pair(
            Surface::DependencyRequest,
            &event,
            &source,
            &serde_json::to_vec(&target).unwrap(),
            &[rule],
            &[],
            clocks()
        )
        .is_err()
    );
}

#[test]
fn mixed_schema_response_fallback_and_delivery_use_the_recorded_default_schema() {
    let policy = policy(Surface::DependencyResponse, true);
    let rule = &policy.rules[0];
    let sql = "SELECT a.updated_at AS left_time, b.updated_at AS right_time FROM app.tasks a JOIN tasks b ON a.id=b.id";
    let response = json!({"status":"resultset","columns":[
        {"name":"left_time","table":"tasks","column":"updated_at","family":"datetime","sql_type":"DATETIME"},
        {"name":"right_time","table":"tasks","column":"updated_at","family":"datetime","sql_type":"DATETIME"}],
        "rows":[[{"kind":"datetime","value":"2020-01-01 00:00:01"},{"kind":"datetime","value":"2020-01-01 00:00:02"}]],
        "row_count":1,"rows_truncated":false});
    let event = event(sql, response);
    assert!(selects(rule, &event).unwrap());
    let source = source_witness(Surface::DependencyResponse, &event, Path::new(".")).unwrap();
    let extracted = crate::replay::mysql_witness_values(
        &source,
        Surface::DependencyResponse,
        rule,
        Some("other"),
    )
    .unwrap();
    assert_eq!(
        extracted,
        vec![(b"0:0".to_vec(), b"\"2020-01-01 00:00:01\"".to_vec())]
    );
    assert!(
        crate::replay::mysql_witness_values(&source, Surface::DependencyResponse, rule, None)
            .unwrap()
            .is_empty()
    );
    let mut target: Value = serde_json::from_slice(&source).unwrap();
    target["request"]["request_started_at"] = json!("2026-01-01T00:00:00Z");
    target["response_delivered_at"] = json!("2026-01-01T00:00:00Z");
    target["response"]["rows"][0][0]["value"] = json!("2026-01-01 00:00:01");
    assert_eq!(
        compare_pair(
            Surface::DependencyResponse,
            &event,
            &source,
            &serde_json::to_vec(&target).unwrap(),
            &[rule],
            &[],
            clocks()
        )
        .unwrap(),
        1
    );
    target["response"]["rows"][0][1]["value"] = json!("2026-01-01 00:00:02");
    assert!(
        compare_pair(
            Surface::DependencyResponse,
            &event,
            &source,
            &serde_json::to_vec(&target).unwrap(),
            &[rule],
            &[],
            clocks()
        )
        .is_err()
    );
}
