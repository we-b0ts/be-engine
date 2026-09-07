//! Real-driver contract tests. Fixtures belong to the engine; SQLx only sees
//! the MySQL socket and runs its normal handshake, initialization and protocol.
use super::*;
use serde_json::json;
use sqlx::{
    Connection, Row,
    mysql::{MySqlConnectOptions, MySqlConnection},
};
use std::time::Duration;
use tempfile::tempdir;

mod autocommit_tests;
mod distinct_tests;
mod or_tests;
mod predicate_tests;
mod projection_tests;
mod rollback_tests;
mod tuple_tests;

fn exchange(sql: &str, response: Value) -> Value {
    json!({"event_type":"mysql_exchange", "target_host":"127.0.0.1", "target_port":3306,
        "target_addr":"127.0.0.1:3306", "database":"appdb", "username":"root",
        "command":"COM_QUERY", "sql":sql, "response":response})
}

fn result(columns: Value, rows: Value) -> Value {
    json!({"status":"resultset", "columns":columns, "rows":rows})
}

async fn fixture(
    records: &[Value],
    policy: bool,
) -> (
    tempfile::TempDir,
    SocketAddr,
    Arc<ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    let temp = tempdir().unwrap();
    let case = temp.path().join("case-id");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(
        case.join("dependencies.jsonl"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let policy_path = if policy {
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"GET","uri":"/users"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let path = temp.path().join("policy.yaml");
        std::fs::write(
            &path,
            "version: 1\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        Some(path)
    } else {
        None
    };
    let (addr, runtime, task) = super::tests::spawn_replay_with_policy(&case, policy_path).await;
    (temp, addr, runtime, task)
}

async fn connect(addr: SocketAddr, ca: &std::path::Path) -> MySqlConnection {
    let options = MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(addr.port())
        .username("root")
        .database("appdb")
        .ssl_ca(ca)
        .ssl_mode(sqlx::mysql::MySqlSslMode::VerifyCa);
    MySqlConnection::connect_with(&options).await.unwrap()
}

#[tokio::test]
async fn sqlx_defaults_tls_prepared_queries_and_policy_use_text_evidence() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let response = result(json!([
            {"name":"id","family":"integer","sql_type":"BIGINT","unsigned":true},
            {"name":"name","family":"string","sql_type":"VARCHAR"},
            {"name":"missing","family":"string","sql_type":"VARCHAR"},
            {"name":"payload","family":"binary","sql_type":"VARBINARY"},
            {"name":"created","family":"datetime","sql_type":"DATETIME","scale":6},
            {"name":"amount","family":"decimal","sql_type":"DECIMAL","scale":4}
        ]), json!([[{"kind":"integer","value":18446744073709551615_u64},
            {"kind":"string","value":"AbC  中文"}, {"kind":"null"},
            {"kind":"bytes","raw":{"encoding":"base64","data":"AP8="}},
            {"kind":"datetime","value":"2026-09-05 12:34:56.1"},
            {"kind":"decimal","value":"12.3400"}]]));
        let sql = "SELECT id,name,missing,payload,created,amount FROM users WHERE name='AbC  中文' AND missing <=> NULL AND payload=X'00ff' LIMIT 1";
        let records = [exchange(sql, response)];
        let (temp, addr, runtime, task) = fixture(&records, true).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let row = sqlx::query("SELECT id,name,missing,payload,created,amount FROM users WHERE name=? AND missing <=> ? AND payload=? LIMIT 1")
            .bind("AbC  中文").bind(Option::<String>::None).bind(vec![0_u8, 255])
            .fetch_one(&mut client).await.unwrap();
        assert_eq!(row.get::<u64,_>("id"), u64::MAX);
        assert_eq!(row.get::<String,_>("name"), "AbC  中文");
        assert_eq!(row.get::<Option<String>,_>("missing"), None);
        assert_eq!(row.get::<Vec<u8>,_>("payload"), vec![0,255]);
        assert_eq!(row.get::<chrono::NaiveDateTime,_>("created").and_utc().timestamp_subsec_micros(), 100_000);
        assert_eq!(row.get::<sqlx::types::BigDecimal,_>("amount").to_string(), "12.3400");
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        assert!(state.mysql.events.builtin_queries.iter().any(|q| q.sql.as_deref().is_some_and(|sql| sql.contains("PIPES_AS_CONCAT"))));
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert!(state.mysql.events.metadata_warnings.is_empty(), "{:?}", state.mysql.events.metadata_warnings);
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        task.abort();
    }).await.expect("SQLx replay test timed out");
}

#[tokio::test]
async fn sqlx_cached_statement_rebinds_params_and_replays_writes_transactions_and_errors() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let ok = |count, id| json!({"status":"ok","affected_rows":count,"last_insert_id":id});
        let records = [
            exchange(
                "SELECT id FROM tasks_0509 WHERE uid=509 AND note='?'",
                result(
                    json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                    json!([[{"kind":"integer","value":1}]]),
                ),
            ),
            exchange(
                "SELECT id FROM tasks_0509 WHERE uid=1533 AND note='?'",
                result(
                    json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                    json!([]),
                ),
            ),
            exchange("INSERT INTO tasks_0509(uid) VALUES(509)", ok(1, 42)),
            exchange("UPDATE tasks_0509 SET uid=1533 WHERE id=42", ok(1, 0)),
            exchange(
                "DELETE FROM tasks_0509 WHERE id=42",
                json!({"status":"error","error_code":1062,"error_message":"duplicate entry"}),
            ),
        ];
        let (temp, addr, runtime, task) = fixture(&records, false).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let sql = "SELECT id FROM tasks_0509 WHERE uid=? AND note='?' /* ? */";
        let first = sqlx::query(sql)
            .bind(509_u64)
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(first.get::<i32, _>(0), 1);
        assert!(
            sqlx::query(sql)
                .bind(1533_u64)
                .fetch_optional(&mut client)
                .await
                .unwrap()
                .is_none()
        );
        let mut tx = client.begin().await.unwrap();
        let inserted = sqlx::query("INSERT INTO tasks_0509(uid) VALUES(?)")
            .bind(509_u64)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            (inserted.rows_affected(), inserted.last_insert_id()),
            (1, 42)
        );
        let updated = sqlx::query("UPDATE tasks_0509 SET uid=? WHERE id=?")
            .bind(1533_u64)
            .bind(42_u64)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(updated.rows_affected(), 1);
        tx.commit().await.unwrap();
        let mut tx = client.begin().await.unwrap();
        let error = sqlx::query("DELETE FROM tasks_0509 WHERE id=?")
            .bind(42_u64)
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .unwrap()
                .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .number(),
            1062
        );
        tx.rollback().await.unwrap();
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, records.len());
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        task.abort();
    })
    .await
    .expect("SQLx transaction replay test timed out");
}
