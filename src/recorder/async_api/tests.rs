use super::*;
use crate::policy::{AsyncMysqlEnd, AsyncRedisEnd};
use crate::recorder::{
    MysqlExchangeEvent, MysqlExchangeResponse, RedisExchangeEvent, capture_body,
};
use hyper::Method;
use serde_json::json;
use uuid::Uuid;

fn scope(end: Vec<AsyncEnd>) -> ResourceScope {
    ResourceScope {
        rule: AsyncApiRule {
            when: BTreeMap::from([("/background".into(), json!(true))]),
            when_response: Default::default(),
            unless_response: Default::default(),
            ownership: None,
            end,
        },
        progress: Default::default(),
    }
}

pub(crate) fn redis(operation: &str, key: &[u8]) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        target_host: "redis.test".into(),
        target_port: 6379,
        target_addr: "redis.test:6379".into(),
        upstream_addr: "127.0.0.1:6379".into(),
        resp_version: 2,
        database: 2,
        username: None,
        command: operation.into(),
        args: vec![capture_body(key, 4096)],
        response_kind: "integer".into(),
        response: capture_body(b":1\r\n", 4096),
        rpc_callback_capture: None,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 0,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

fn mysql(actual: &str, parameters: Option<Vec<MysqlValue>>) -> RecorderEvent {
    RecorderEvent::MysqlExchange(MysqlExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        query_sequence: 1,
        request_started_at: chrono::Utc::now(),
        timestamp: chrono::Utc::now(),
        client_addr: None,
        route_name: None,
        target_host: Some("mysql.test".into()),
        target_port: Some(3306),
        target_addr: None,
        upstream_addr: None,
        username: None,
        database: Some("tasks".into()),
        command: if parameters.is_some() {
            "COM_STMT_EXECUTE"
        } else {
            "COM_QUERY"
        }
        .into(),
        sql: Some(actual.into()),
        statement_id: None,
        params: parameters,
        server_status_before: None,
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
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 0,
        parse_warnings: Vec::new(),
    })
}

fn end() -> AsyncEnd {
    AsyncEnd::Mysql(AsyncMysqlEnd {
        sql: "UPDATE tasks SET status = 'completed' WHERE id = ?".into(),
        database: Some("tasks".into()),
        endpoint: Some(Endpoint {
            host: "mysql.test".into(),
            port: 3306,
        }),
    })
}

#[test]
fn source_request_selects_exact_api_and_literal_background_condition() {
    let scope = scope(vec![end()]);
    let rules = BTreeMap::from([(
        "POST /api/v1/responses".into(),
        crate::policy::AsyncApiRules(vec![scope.rule]),
    )]);
    for (method, uri, body, expected) in [
        (
            Method::POST,
            "/api/v1/responses",
            br#"{"background":true}"#.as_slice(),
            true,
        ),
        (
            Method::POST,
            "/api/v1/responses?stream=false",
            br#"{"background":true}"#,
            true,
        ),
        (
            Method::POST,
            "/api/v1/response",
            br#"{"background":true}"#,
            false,
        ),
        (
            Method::GET,
            "/api/v1/responses",
            br#"{"background":true}"#,
            false,
        ),
        (
            Method::POST,
            "/api/v1/responses",
            br#"{"background":false}"#,
            false,
        ),
        (
            Method::POST,
            "/api/v1/responses",
            br#"{"background":true,"background":false}"#,
            false,
        ),
    ] {
        assert_eq!(
            AsyncScope::for_primary(&rules, &method, &uri.parse().unwrap(), body).is_some(),
            expected
        );
    }
}

#[test]
fn mysql_terminal_requires_the_complete_sql_and_materialized_prepared_scalar() {
    let scope = scope(vec![end()]);
    let value = MysqlValue {
        kind: "integer".into(),
        value: Some(json!(42)),
        raw: None,
    };
    for event in [
        mysql("update tasks set status='completed' where id=42", None),
        mysql(
            "UPDATE tasks SET status=? WHERE id=?",
            Some(vec![
                MysqlValue {
                    kind: "string".into(),
                    value: Some(json!("completed")),
                    raw: None,
                },
                value.clone(),
            ]),
        ),
    ] {
        assert_eq!(
            scope.observe(&event).unwrap().end_reason,
            AsyncEndReason::Resource
        );
    }
    for event in [
        mysql("update tasks set status='started' where id=42", None),
        mysql("update tasks set status='completed' where id=id", None),
        mysql(
            "update tasks set status='completed' where id=42 OR 1=1",
            None,
        ),
        mysql("update tasks set status='completed' where id=?", None),
        mysql(
            "update tasks set status='completed' where id=?",
            Some(vec![]),
        ),
        mysql(
            "update tasks set status='completed' where id=?",
            Some(vec![value.clone(), value]),
        ),
        mysql("update other set status='completed' where id=42", None),
    ] {
        assert!(scope.observe(&event).is_none(), "{event:?}");
    }
    let mut wrong_database = mysql("update tasks set status='completed' where id=42", None);
    if let RecorderEvent::MysqlExchange(event) = &mut wrong_database {
        event.database = Some("other".into());
    }
    assert!(scope.observe(&wrong_database).is_none());
}

#[test]
fn mysql_terminal_matches_one_numeric_scalar_across_text_and_prepared_encodings() {
    let scope = scope(vec![end()]);
    for literal in ["-42", "+42", "4.2e1", "NULL", "TRUE"] {
        let query = format!("UPDATE tasks SET status='completed' WHERE id={literal}");
        assert!(scope.observe(&mysql(&query, None)).is_some(), "{query}");
    }
    let prepared = mysql(
        "UPDATE tasks SET status='completed' WHERE id=?",
        Some(vec![MysqlValue {
            kind: "integer".into(),
            value: Some(json!(-42)),
            raw: None,
        }]),
    );
    assert!(scope.observe(&prepared).is_some());
    // A placeholder covers one materialized scalar rather than an expression,
    // identifier, SQL fragment or changed surrounding predicate.
    for expression in ["42+1", "-id", "(42)", "COALESCE(id,42)"] {
        let query = format!("UPDATE tasks SET status='completed' WHERE id={expression}");
        assert!(scope.observe(&mysql(&query, None)).is_none(), "{query}");
    }
}

#[test]
fn redis_terminal_uses_physical_scope_and_any_end_resource_can_finish() {
    let scope = scope(vec![
        end(),
        AsyncEnd::Redis(AsyncRedisEnd {
            operation: "DEL".into(),
            occurrence: 1,
            key: "done:*".into(),
            database: Some(2),
            endpoint: Some(Endpoint {
                host: "redis.test".into(),
                port: 6379,
            }),
        }),
    ]);
    assert!(scope.observe(&redis("DEL", b"initial:42")).is_none());
    assert!(scope.observe(&redis("GET", b"done:42")).is_none());
    let signal = scope.observe(&redis("del", b"done:42")).unwrap();
    assert_eq!(signal.resource_index, Some(1));
    let mut event = redis("DEL", b"done:42");
    if let RecorderEvent::RedisExchange(event) = &mut event {
        event.database = 3;
    }
    assert!(scope.observe(&event).is_none());
}

#[test]
fn recoverable_dependency_errors_do_not_end_observation() {
    let scope = scope(vec![end()]);
    let mut event = redis("GET", b"unrelated");
    if let RecorderEvent::RedisExchange(event) = &mut event {
        event.response_kind = "error".into();
    }
    assert!(scope.observe(&event).is_none());
}

#[test]
fn mysql_terminal_in_a_transaction_waits_for_the_real_commit() {
    let live_scope = scope(vec![end()]);
    let mut update = mysql("UPDATE tasks SET status='completed' WHERE id=42", None);
    if let RecorderEvent::MysqlExchange(event) = &mut update {
        event.query_sequence = 7;
        event.server_status_before = Some(1);
        event.response.server_status = Some(1);
    }
    assert!(live_scope.observe(&update).is_none());
    let mut commit = update.clone();
    if let RecorderEvent::MysqlExchange(event) = &mut commit {
        event.query_sequence = 8;
        event.sql = Some("COMMIT".into());
        event.response.server_status = Some(2);
    }
    assert_eq!(
        live_scope.observe(&commit).unwrap().end_reason,
        AsyncEndReason::Resource
    );
    let scope = scope(vec![end()]);
    assert!(
        scope
            .observe_recorded(&serde_json::to_value(&update).unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        scope
            .observe_recorded(&serde_json::to_value(&commit).unwrap())
            .unwrap()
            .unwrap()
            .end_reason,
        AsyncEndReason::Resource
    );
}

#[test]
fn rollback_and_failed_commit_cannot_confirm_an_earlier_terminal_write() {
    for rollback in [true, false] {
        let scope = scope(vec![end()]);
        let mut update = mysql("UPDATE tasks SET status='completed' WHERE id=42", None);
        if let RecorderEvent::MysqlExchange(event) = &mut update {
            event.query_sequence = 1;
            event.server_status_before = Some(1);
            event.response.server_status = Some(1);
        }
        assert!(scope.observe(&update).is_none());
        let mut boundary = update.clone();
        if let RecorderEvent::MysqlExchange(event) = &mut boundary {
            event.query_sequence = 2;
            event.sql = Some(if rollback { "ROLLBACK" } else { "COMMIT" }.into());
            event.response.server_status = Some(2);
            if !rollback {
                event.response.error_code = Some(1213);
                event.response.status = "error".into();
            }
        }
        assert!(scope.observe(&boundary).is_none());
    }
}

fn client_info_error() -> RecorderEvent {
    let mut event = redis("CLIENT", b"SETINFO");
    if let RecorderEvent::RedisExchange(exchange) = &mut event {
        exchange.args.extend([
            capture_body(b"LIB-NAME", 4096),
            capture_body(b"redis-py", 4096),
        ]);
        exchange.session_setup = true;
        exchange.response_kind = "error".into();
        exchange.response = capture_body(b"-ERR unknown subcommand 'SETINFO'\r\n", 4096);
    }
    event
}

#[test]
fn optional_redis_client_metadata_error_does_not_replace_two_del_completion() {
    let scope = scope(vec![AsyncEnd::Redis(AsyncRedisEnd {
        operation: "DEL".into(),
        occurrence: 2,
        key: "chat:cancel:*".into(),
        database: None,
        endpoint: None,
    })]);
    let metadata = client_info_error();
    assert!(!crate::recorder::should_append_case_dependency(&metadata));
    assert!(scope.observe(&metadata).is_none());
    assert!(scope.observe(&redis("DEL", b"chat:cancel:42")).is_none());
    let signal = scope.observe(&redis("DEL", b"chat:cancel:42")).unwrap();
    assert_eq!(signal.end_reason, AsyncEndReason::Resource);
}

#[test]
fn complete_setup_errors_allow_retries_while_truncation_requires_isolation() {
    for variant in [
        "AUTH",
        "SELECT",
        "HELLO",
        "unknown_attribute",
        "truncated",
        "unsafe",
        "terminated",
        "snapshot_hit",
    ] {
        let scope = scope(vec![end()]);
        let mut event = client_info_error();
        if let RecorderEvent::RedisExchange(exchange) = &mut event {
            match variant {
                "AUTH" | "SELECT" | "HELLO" => exchange.command = variant.into(),
                "unknown_attribute" => exchange.args[1] = capture_body(b"OTHER", 4096),
                "truncated" => exchange.response.truncated = true,
                "unsafe" => exchange.replay_safe = false,
                "terminated" => exchange.outcome = DependencyExchangeOutcome::ClientTerminated,
                "snapshot_hit" => {
                    exchange.command = "GET".into();
                    exchange.args = vec![capture_body(b"business:key", 4096)];
                    exchange.session_setup = false;
                    exchange.cache_snapshot_hit = true;
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(
            crate::recorder::should_append_case_dependency(&event),
            variant != "snapshot_hit"
        );
        if variant == "truncated" {
            assert_eq!(
                scope.observe(&event).unwrap().end_reason,
                AsyncEndReason::DependencyFailure
            );
        } else {
            assert!(scope.observe(&event).is_none(), "{variant}");
        }
    }
}

#[test]
fn redis_occurrences_are_successful_unique_exchanges_for_the_same_physical_key() {
    let scope = scope(vec![AsyncEnd::Redis(AsyncRedisEnd {
        operation: "DEL".into(),
        occurrence: 2,
        key: "done:*".into(),
        database: None,
        endpoint: None,
    })]);
    let first = redis("DEL", b"done:42");
    assert!(scope.observe(&first).is_none());
    // A mirrored event has the same immutable id and cannot manufacture another
    // access. Nor can a second task, database or physical endpoint finish it.
    assert!(scope.observe(&first).is_none());
    assert!(scope.observe(&redis("DEL", b"done:43")).is_none());
    let mut another_database = redis("DEL", b"done:42");
    if let RecorderEvent::RedisExchange(event) = &mut another_database {
        event.database = 3;
    }
    assert!(scope.observe(&another_database).is_none());
    let mut another_endpoint = redis("DEL", b"done:42");
    if let RecorderEvent::RedisExchange(event) = &mut another_endpoint {
        event.target_port = 6380;
    }
    assert!(scope.observe(&another_endpoint).is_none());
    let signal = scope.observe(&redis("DEL", b"done:42")).unwrap();
    assert_eq!(signal.end_reason, AsyncEndReason::Resource);
}

#[test]
fn redis_occurrence_progress_bounds_all_observations_and_does_not_retain_keys() {
    let scope = scope(vec![AsyncEnd::Redis(AsyncRedisEnd {
        operation: "DEL".into(),
        occurrence: 2,
        key: "done:*".into(),
        database: None,
        endpoint: None,
    })]);
    let first = redis("DEL", b"done:42");
    assert!(scope.observe(&first).is_none());
    assert!(scope.observe(&first).is_none());
    {
        let mut progress = scope.progress.lock().unwrap();
        assert_eq!(progress.observations, 1);
        assert_eq!(progress.resources.len(), 1);
        assert_eq!(
            progress.resources.first_key_value().unwrap().0.key_digest,
            <[u8; 32]>::from(Sha256::digest(b"done:42"))
        );
        // Exhaustion cannot create a guessed completion, and caps aggregate
        // entries rather than allowing one full UUID set for every key.
        progress.observations = MAX_OCCURRENCE_OBSERVATIONS;
    }
    assert!(scope.observe(&redis("DEL", b"done:42")).is_none());
    assert!(scope.observe(&redis("DEL", b"done:43")).is_none());
    assert_eq!(scope.progress.lock().unwrap().resources.len(), 1);
}

#[test]
fn immutable_recorded_terminal_uses_the_same_occurrence_and_prepared_sql_semantics() {
    let scope = scope(vec![
        end(),
        AsyncEnd::Redis(AsyncRedisEnd {
            operation: "DEL".into(),
            occurrence: 2,
            key: "done:*".into(),
            database: None,
            endpoint: None,
        }),
    ]);
    let first = serde_json::to_value(redis("DEL", b"done:42")).unwrap();
    assert!(scope.observe_recorded(&first).unwrap().is_none());
    assert!(scope.observe_recorded(&first).unwrap().is_none());
    assert!(
        scope
            .observe_recorded(&serde_json::to_value(redis("DEL", b"done:43")).unwrap())
            .unwrap()
            .is_none()
    );
    let second = serde_json::to_value(redis("DEL", b"done:42")).unwrap();
    assert_eq!(
        scope
            .observe_recorded(&second)
            .unwrap()
            .unwrap()
            .resource_index,
        Some(1)
    );
    let query = mysql(
        "UPDATE tasks SET status=? WHERE id=?",
        Some(vec![
            MysqlValue {
                kind: "string".into(),
                value: Some(json!("completed")),
                raw: None,
            },
            MysqlValue {
                kind: "integer".into(),
                value: Some(json!(42)),
                raw: None,
            },
        ]),
    );
    assert_eq!(
        scope
            .observe_recorded(&serde_json::to_value(query).unwrap())
            .unwrap()
            .unwrap()
            .resource_index,
        Some(0)
    );
}

#[test]
fn redis_terminal_matches_only_protocol_keys_including_multikey_and_script_slots() {
    let del = scope(vec![AsyncEnd::Redis(AsyncRedisEnd {
        operation: "DEL".into(),
        occurrence: 1,
        key: "done:*".into(),
        database: None,
        endpoint: None,
    })]);
    let mut multiple = redis("DEL", b"unrelated");
    if let RecorderEvent::RedisExchange(event) = &mut multiple {
        event.args.push(capture_body(b"done:42", 1024));
    }
    assert!(del.observe(&multiple).is_some());
    let script = scope(vec![AsyncEnd::Redis(AsyncRedisEnd {
        operation: "EVALSHA".into(),
        occurrence: 1,
        key: "done:*".into(),
        database: None,
        endpoint: None,
    })]);
    let mut eval = redis("EVALSHA", b"script-digest");
    if let RecorderEvent::RedisExchange(event) = &mut eval {
        event.args.extend([
            capture_body(b"1", 1024),
            capture_body(b"done:42", 1024),
            capture_body(b"argv", 1024),
        ]);
    }
    assert!(script.observe(&eval).is_some());
    if let RecorderEvent::RedisExchange(event) = &mut eval {
        event.args[1] = capture_body(b"0", 1024);
    }
    assert!(
        script.observe(&eval).is_none(),
        "ARGV is never a physical key"
    );
    let echo = scope(vec![AsyncEnd::Redis(AsyncRedisEnd {
        operation: "ECHO".into(),
        occurrence: 1,
        key: "done:*".into(),
        database: None,
        endpoint: None,
    })]);
    assert!(echo.observe(&redis("ECHO", b"done:42")).is_none());
}
