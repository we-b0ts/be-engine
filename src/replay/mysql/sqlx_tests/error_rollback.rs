//! A real Target rollback must end its failed write span, not old auth cleanup.
use super::*;

pub(in crate::replay::mysql) fn records() -> Vec<Value> {
    let auth = uuid::Uuid::from_u128(1);
    let business = uuid::Uuid::from_u128(2);
    let control = |connection, sequence, sql: &str, before: Option<u16>, after| {
        json!({
            "event_type":"mysql_exchange", "connection_id":connection,"query_sequence":sequence,
            "target_host":"127.0.0.1","target_port":3306,"database":"appdb","username":"root",
            "command":"COM_QUERY","sql":sql,"server_status_before":before,
            "response":{"status":"ok","server_status":after,"affected_rows":0,"last_insert_id":0},
        })
    };
    let read = |connection, sequence, sql: &str, before, value| {
        let mut record = control(connection, sequence, sql, Some(before), 1);
        record["response"] = json!({"status":"resultset","server_status":1,
            "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
            "rows":[[{"kind":"integer","value":value}]]});
        record
    };
    let mut insert = control(
        business,
        448,
        "INSERT INTO devices (id) VALUES (1)",
        Some(1),
        1,
    );
    insert["response"] =
        json!({"status":"error","error_code":1062,"error_message":"recorded duplicate"});
    vec![
        read(auth, 414, "SELECT id FROM users WHERE id=2", 0, 2),
        control(auth, 415, "ROLLBACK", Some(1), 0),
        read(
            business,
            445,
            "SELECT id FROM users WHERE id=1 FOR UPDATE",
            0,
            1,
        ),
        read(
            business,
            446,
            "SELECT id FROM devices WHERE name='d' ORDER BY id",
            1,
            1,
        ),
        read(
            business,
            447,
            "SELECT id FROM devices WHERE active=true",
            1,
            1,
        ),
        insert,
        control(business, 449, "ROLLBACK", None, 0),
        control(business, 450, "ROLLBACK", Some(0), 0),
    ]
}

#[tokio::test]
async fn native_failed_insert_rollback_precedes_unrelated_optional_auth_reset() {
    for policy in [false, true] {
        let values = records();
        let (temp, addr, runtime, task) = fixture(&values, policy).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut client = connect(addr, &ca).await;
        let auth = sqlx::query("SELECT id FROM users WHERE id=2")
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(auth.get::<i32, _>(0), 2);
        let mut transaction = client.begin().await.unwrap();
        for sql in [
            "SELECT id FROM users WHERE id=1 FOR UPDATE",
            "SELECT id FROM devices WHERE name='d' ORDER BY id",
            "SELECT id FROM devices WHERE active=true",
        ] {
            let row = sqlx::query(sql).fetch_one(&mut *transaction).await.unwrap();
            assert_eq!(row.get::<i32, _>(0), 1);
        }
        let error = sqlx::query("INSERT INTO devices (id) VALUES (1)")
            .execute(&mut *transaction)
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
        transaction.rollback().await.unwrap();
        let state = runtime.state.lock().await;
        let end = state
            .protocols
            .mysql
            .exchanges
            .iter()
            .find(|exchange| exchange.record.query_sequence == Some(449))
            .unwrap();
        assert!(
            end.status.is_consumed(),
            "the real same-connection ROLLBACK was assigned to old auth cleanup instead"
        );
        let auth_reset = state
            .protocols
            .mysql
            .exchanges
            .iter()
            .find(|exchange| exchange.record.query_sequence == Some(415))
            .unwrap();
        assert!(auth_reset.status.is_available());
        assert!(auth_reset.optional_session.is_some());
        assert!(
            state.unused_exchanges(ReplaySource::Case).is_empty(),
            "{:?}",
            state.unused_exchanges(ReplaySource::Case)
        );
        assert!(state.protocols.mysql.events.unmatched_queries.is_empty());
        task.abort();
    }
}
