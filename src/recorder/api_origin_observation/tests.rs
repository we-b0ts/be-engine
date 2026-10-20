use super::*;
use crate::recorder::{MysqlExchangeResponse, MysqlValue};
use chrono::Utc;
use serde_json::{Value, json};

mod transaction;

fn source() -> Value {
    json!({
        "kind": "api", "method": "POST", "path": "/jobs",
        "request_body_json": {"/background": true},
        "capture": {"job_id": {
            "protocol": "mysql", "target_host": "db.test", "target_port": 3306,
            "database": "app", "username": "writer", "operation": "INSERT",
            "table_patterns": ["jobs_*"], "row_match": {"role": "ASSISTANT"}, "column": "id"
        }}
    })
}

fn redis_rule(command: &str) -> BackgroundDependencyRuleConfig {
    serde_json::from_value(json!({
        "protocol": "redis", "name": format!("job-{}", command.to_ascii_lowercase()),
        "ports": [6379], "command": command, "key_templates": ["cancel:{job_id}"],
        "arguments": if command == "LRANGE" { vec!["0", "-1"] } else { vec![] },
        "trigger_source": source(), "source_revision": "0123456789abcdef",
        "source_evidence": "jobs.py:create starts detached work; cleanup reads and removes its task key"
    })).unwrap()
}

fn mysql_rule() -> BackgroundDependencyRuleConfig {
    serde_json::from_value(json!({
        "protocol": "mysql", "name": "job-read", "trigger_source": source(),
        "identity_value_index": 0,
        "selector": {"target_host": "db.test", "target_port": 3306, "database": "app",
            "username": "writer", "sql": "SELECT id FROM {{table}} WHERE id=? AND role='ASSISTANT' LIMIT 1",
            "table_patterns": ["jobs_*"]},
        "source_revision": "0123456789abcdef", "source_evidence": "jobs.py:load reads its detached job"
    })).unwrap()
}

fn scope(rules: &[BackgroundDependencyRuleConfig]) -> ApiOriginScope {
    ApiOriginScope::for_primary(
        rules,
        &Method::POST,
        &"/jobs".parse().unwrap(),
        br#"{"background":true}"#,
    )
    .unwrap()
}

fn redis(
    scope: &ApiOriginScope,
    port: u16,
    command: &str,
    args: &[&str],
) -> Option<SelectionScope> {
    let args = args
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect::<Vec<_>>();
    scope.select_request(&DependencyRequest::Redis {
        target_port: port,
        command,
        args: &args,
    })
}

fn mysql(scope: &ApiOriginScope, connection_id: Uuid, sql: &str) -> Option<SelectionScope> {
    scope.select_request(&DependencyRequest::Mysql {
        connection_id,
        target_host: Some("db.test"),
        target_port: Some(3306),
        database: Some("app"),
        username: Some("writer"),
        command: "COM_QUERY",
        sql: Some(sql),
    })
}

fn exchange(sql: &str, connection_id: Uuid, sequence: u64) -> MysqlExchangeEvent {
    MysqlExchangeEvent {
        id: Uuid::new_v4(),
        connection_id,
        query_sequence: sequence,
        timestamp: Utc::now(),
        client_addr: None,
        route_name: None,
        target_host: Some("db.test".into()),
        target_port: Some(3306),
        target_addr: None,
        upstream_addr: None,
        username: Some("writer".into()),
        database: Some("app".into()),
        command: "COM_QUERY".into(),
        sql: Some(sql.into()),
        statement_id: None,
        params: None,
        server_status_before: Some(2),
        response: MysqlExchangeResponse {
            wire_prefix: Vec::new(),
            server_status: Some(2),
            status: "ok".into(),
            error_code: None,
            error_message: None,
            affected_rows: Some(1),
            last_insert_id: None,
            columns: Vec::new(),
            rows: Vec::new(),
            row_count: 0,
            rows_truncated: false,
        },
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: 1,
        parse_warnings: Vec::new(),
    }
}

fn insert(identity: u64) -> MysqlExchangeEvent {
    exchange(
        &format!("INSERT INTO jobs_0001 (id, role) VALUES ({identity}, 'ASSISTANT')"),
        Uuid::new_v4(),
        1,
    )
}

fn observe(scope: &ApiOriginScope, exchange: MysqlExchangeEvent) {
    scope.observe_completed(&RecorderEvent::MysqlExchange(exchange));
}

#[test]
fn only_the_exact_api_and_typed_request_body_enable_the_scope() {
    let rules = [redis_rule("GET")];
    for (method, path, body) in [
        (Method::GET, "/jobs", r#"{"background":true}"#),
        (Method::POST, "/jobs/1", r#"{"background":true}"#),
        (Method::POST, "/jobs", r#"{"background":false}"#),
        (Method::POST, "/jobs?background=true", "{}"),
        (Method::POST, "/jobs", r#"{"background":"true"}"#),
        (
            Method::POST,
            "/jobs",
            r#"{"background":true,"background":false}"#,
        ),
        (Method::POST, "/jobs", "invalid"),
    ] {
        assert!(
            ApiOriginScope::for_primary(&rules, &method, &path.parse().unwrap(), body.as_bytes())
                .is_none(),
            "unexpected API-origin match for {method} {path}"
        );
    }
    assert!(
        ApiOriginScope::for_primary(
            &rules,
            &Method::POST,
            &"/jobs?ignored=true".parse().unwrap(),
            br#"{"background":true,"other":1}"#,
        )
        .is_some()
    );
}

#[test]
fn primary_conditions_select_only_their_own_rules_and_allow_bodyless_origins() {
    let mut other = redis_rule("DEL");
    if let BackgroundDependencyRuleConfig::Redis { trigger_source, .. } = &mut other {
        trigger_source
            .as_mut()
            .unwrap()
            .request_body_json
            .insert("/background".into(), false.into());
    }
    let selected = scope(&[redis_rule("GET"), other]);
    assert_eq!(selected.snapshot().len(), 1);
    assert!(redis(&selected, 6379, "DEL", &["cancel:12"]).is_none());

    let mut rule = redis_rule("GET");
    if let BackgroundDependencyRuleConfig::Redis { trigger_source, .. } = &mut rule {
        trigger_source.as_mut().unwrap().request_body_json.clear();
    }
    assert!(
        ApiOriginScope::for_primary(&[rule], &Method::POST, &"/jobs".parse().unwrap(), b"")
            .is_some()
    );
}

#[test]
fn missing_capture_keeps_the_complete_redis_selector_and_reports_its_scope() {
    let scope = scope(&[redis_rule("LRANGE")]);
    assert_eq!(
        redis(&scope, 6379, "LRANGE", &["cancel:12", "0", "-1"]),
        Some(SelectionScope::SelectorOnly)
    );
    for (port, command, args) in [
        (6380, "LRANGE", vec!["cancel:12", "0", "-1"]),
        (6379, "GET", vec!["cancel:12"]),
        (6379, "LRANGE", vec!["other:12", "0", "-1"]),
        (6379, "LRANGE", vec!["cancel:12", "0", "1"]),
        (6379, "LRANGE", vec!["cancel:012", "0", "-1"]),
        (6379, "LRANGE", vec!["cancel:0", "0", "-1"]),
        (6379, "LRANGE", vec!["cancel:12", "0"]),
        (6379, "PING", vec![]),
    ] {
        assert!(redis(&scope, port, command, &args).is_none());
    }
    let snapshot = scope.snapshot();
    assert_eq!(snapshot[0].capture_state, CaptureState::Missing);
    assert_eq!(snapshot[0].selected_selector_only, 1);
    assert_eq!(snapshot[0].selected_bound, 0);
}

#[test]
fn the_current_insert_binds_all_rules_sharing_the_origin_without_leaking_identity() {
    let scope = scope(&[redis_rule("GET"), mysql_rule()]);
    observe(&scope, insert(987_654_321));
    assert_eq!(
        redis(&scope, 6379, "GET", &["cancel:987654321"]),
        Some(SelectionScope::BoundIdentity)
    );
    assert!(redis(&scope, 6379, "GET", &["cancel:12"]).is_none());
    let sql = "SELECT id FROM jobs_0001 WHERE id=987654321 AND role='ASSISTANT' LIMIT 1";
    assert_eq!(
        mysql(&scope, Uuid::new_v4(), sql),
        Some(SelectionScope::BoundIdentity)
    );
    assert!(mysql(&scope, Uuid::new_v4(), &sql.replace("987654321", "12")).is_none());
    assert!(
        scope
            .snapshot()
            .iter()
            .all(|s| s.capture_state == CaptureState::Bound)
    );
    assert!(!format!("{scope:?}").contains("987654321"));
    assert!(
        !serde_json::to_string(&scope.snapshot())
            .unwrap()
            .contains("987654321")
    );
}

#[test]
fn incomplete_wrong_endpoint_or_failed_inserts_never_bind_the_scope() {
    let scope = scope(&[redis_rule("GET")]);
    let valid = insert(12);
    let mut wrong = valid.clone();
    wrong.target_host = Some("other.test".into());
    observe(&scope, wrong);
    let mut wrong = valid.clone();
    wrong.username = Some("reader".into());
    observe(&scope, wrong);
    let mut wrong = valid.clone();
    wrong.response.affected_rows = Some(2);
    observe(&scope, wrong);
    let mut wrong = valid.clone();
    wrong.response.status = "error".into();
    observe(&scope, wrong);
    let mut wrong = valid.clone();
    wrong.parse_warnings.push("incomplete packet".into());
    observe(&scope, wrong);
    let mut wrong = valid.clone();
    wrong.command = "COM_STMT_EXECUTE".into();
    observe(&scope, wrong);
    let mut wrong = valid.clone();
    wrong.sql =
        Some("INSERT INTO jobs_0001 (id,role) VALUES (12,'ASSISTANT'),(13,'ASSISTANT')".into());
    observe(&scope, wrong);
    let mut wrong = valid;
    wrong.sql = Some("INSERT INTO jobs_0001 (id,role) VALUES (12,'USER')".into());
    observe(&scope, wrong);
    assert_eq!(scope.snapshot()[0].capture_state, CaptureState::Missing);
    assert_eq!(
        redis(&scope, 6379, "GET", &["cancel:13"]),
        Some(SelectionScope::SelectorOnly)
    );
}

#[test]
fn duplicate_observation_is_idempotent_but_two_physical_captures_are_ambiguous() {
    let scope = scope(&[redis_rule("GET")]);
    let exchange = insert(12);
    observe(&scope, exchange.clone());
    observe(&scope, exchange);
    assert_eq!(scope.snapshot()[0].capture_state, CaptureState::Bound);
    observe(&scope, insert(12));
    assert_eq!(scope.snapshot()[0].capture_state, CaptureState::Ambiguous);
    assert_eq!(
        redis(&scope, 6379, "GET", &["cancel:13"]),
        Some(SelectionScope::SelectorOnly)
    );
    observe(&scope, insert(14));
    assert_eq!(scope.snapshot()[0].capture_state, CaptureState::Ambiguous);
}

#[test]
fn independent_primary_scopes_never_share_captured_identities() {
    let first = scope(&[redis_rule("GET")]);
    let second = scope(&[redis_rule("GET")]);
    observe(&first, insert(12));
    observe(&second, insert(13));
    assert!(redis(&first, 6379, "GET", &["cancel:13"]).is_none());
    assert!(redis(&second, 6379, "GET", &["cancel:12"]).is_none());
    assert_eq!(
        redis(&first.clone(), 6379, "GET", &["cancel:12"]),
        Some(SelectionScope::BoundIdentity)
    );
}

#[test]
fn mysql_reuses_endpoint_database_user_table_predicates_and_identity_slots() {
    let scope = scope(&[mysql_rule()]);
    let sql = "SELECT id FROM jobs_0001 WHERE id=120 AND role='ASSISTANT' LIMIT 1";
    observe(&scope, insert(120));
    assert_eq!(
        mysql(&scope, Uuid::new_v4(), sql),
        Some(SelectionScope::BoundIdentity)
    );
    assert_eq!(
        mysql(&scope, Uuid::new_v4(), &sql.replace("120", "12e1")),
        Some(SelectionScope::BoundIdentity)
    );
    for sql in [
        sql.replace("jobs_0001", "users_0001"),
        sql.replace("ASSISTANT", "USER"),
        sql.replace("id=120", "id=121"),
        sql.replace("LIMIT 1", "LIMIT 2"),
        sql.replace("id=120", "id=?"),
        format!("{sql} OR id=120"),
    ] {
        assert!(mysql(&scope, Uuid::new_v4(), &sql).is_none());
    }
    for (host, port, database, username) in [
        ("other.test", 3306, "app", "writer"),
        ("db.test", 3307, "app", "writer"),
        ("db.test", 3306, "other", "writer"),
        ("db.test", 3306, "app", "reader"),
    ] {
        assert!(
            scope
                .select_request(&DependencyRequest::Mysql {
                    connection_id: Uuid::new_v4(),
                    target_host: Some(host),
                    target_port: Some(port),
                    database: Some(database),
                    username: Some(username),
                    command: "COM_QUERY",
                    sql: Some(sql),
                })
                .is_none()
        );
    }
}

#[test]
fn multi_key_del_and_lua_require_the_complete_declared_envelopes() {
    let mut del = redis_rule("DEL");
    if let BackgroundDependencyRuleConfig::Redis {
        key_templates,
        key_sequence,
        ..
    } = &mut del
    {
        key_templates.clear();
        *key_sequence = vec!["cancel:{job_id}".into(), "result:{job_id}".into()];
    }
    let del = scope(&[del]);
    observe(&del, insert(12));
    assert_eq!(
        redis(&del, 6379, "DEL", &["cancel:12", "result:12"]),
        Some(SelectionScope::BoundIdentity)
    );
    assert!(redis(&del, 6379, "DEL", &["cancel:12", "result:13"]).is_none());
    assert!(redis(&del, 6379, "DEL", &["result:12", "cancel:12"]).is_none());

    let mut script = redis_rule("EVALSHA");
    if let BackgroundDependencyRuleConfig::Redis {
        script,
        key_templates,
        ..
    } = &mut script
    {
        key_templates.clear();
        *script = Some(
            serde_json::from_value(json!({
                "sha1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "keys": [{"prefix": "queue", "suffix": "", "numeric_middle": false}],
                "argv_count": 2, "identity_argv_index": 1
            }))
            .unwrap(),
        );
    }
    let lua = scope(&[script]);
    observe(&lua, insert(12));
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        redis(
            &lua,
            6379,
            "EVALSHA",
            &[digest, "1", "queue", "payload", "12"]
        ),
        Some(SelectionScope::BoundIdentity)
    );
    for args in [
        vec![digest, "1", "queue", "payload", "13"],
        vec![digest, "0", "queue", "payload", "12"],
        vec![digest, "1", "queue:extra", "payload", "12"],
        vec![digest, "1", "queue", "12"],
    ] {
        assert!(redis(&lua, 6379, "EVALSHA", &args).is_none());
    }
    assert!(redis(&lua, 6379, "SCRIPT", &["EXISTS", digest]).is_none());
}
