//! Independent real-driver operations share one physical-field identity domain.
use super::*;
use sqlx::Executor;

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const TARGET: &str = "99999999-9999-4999-8999-999999999999";
const HISTORICAL: &str = "22222222-2222-4222-8222-222222222222";
const WRONG: &str = "44444444-4444-4444-8444-444444444444";

const POLICY: &str = r#"format: traffic-policy/v2
resources:
  db:
    protocol: mysql
    endpoint: 127.0.0.1:3306
    database: appdb
    username: root
    proof: {source: 'models.rs:10-30', fact: 'Generated entity ids are copied across the row and JSON payload'}
    tables:
      widgets:
        tables: [widgets]
        fields:
          id: {kind: identity, binding: widget, format: uuid}
          payload:
            codec: json
            fields:
              /id: {kind: identity, binding: widget, format: uuid}
responses:
  widget:
    api: GET /users
    proof: {source: 'handler.rs:20-30', fact: 'The response returns the same generated entity id'}
    body:
      codec: json
      fields:
        /id: {kind: identity, binding: widget, format: uuid}
rules: []
"#;

fn body(id: &str) -> String {
    json!({"id":id,"stable":true}).to_string()
}

fn row(id: &str) -> Value {
    result(
        json!([
            {"name":"id","family":"string","sql_type":"VARCHAR","database":"appdb","table":"widgets","column":"id"},
            {"name":"payload","family":"string","sql_type":"VARCHAR","database":"appdb","table":"widgets","column":"payload"}
        ]),
        json!([[{"kind":"string","value":id},{"kind":"string","value":body(id)}]]),
    )
}

#[tokio::test]
async fn mysql_field_ids_survive_reads_and_response_control_without_sql_templates() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let insert = format!(
            "INSERT INTO widgets(id,payload,title) VALUES('{SOURCE}','{}','stable')",
            body(SOURCE)
        );
        let read = format!("SELECT id,payload FROM widgets WHERE id='{SOURCE}'");
        let history = "SELECT id,payload FROM widgets WHERE title='historical'";
        let update = format!(
            "UPDATE widgets SET payload='{}',title='done' WHERE id='{SOURCE}'",
            body(SOURCE)
        );
        let copy = format!(
            "UPDATE widgets SET payload='{}' WHERE id='{HISTORICAL}'",
            body(HISTORICAL)
        );
        let records = [
            exchange(&insert, json!({"status":"ok","affected_rows":1})),
            exchange(&read, row(SOURCE)),
            exchange(history, row(HISTORICAL)),
            exchange(&update, json!({"status":"ok","affected_rows":1})),
            exchange(&copy, json!({"status":"ok","affected_rows":1})),
        ];
        let (temp, addr, runtime, task) = fixture_with_policy(&records, Some(POLICY)).await;
        let capture = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
        let original = std::fs::read(&capture).unwrap();
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        // A structurally eligible failed candidate must not reserve its proposed id.
        assert!(
            client
                .execute(
                    insert
                        .replace(SOURCE, WRONG)
                        .replace("'stable'", "'wrong'")
                        .as_str()
                )
                .await
                .is_err()
        );
        assert_eq!(
            client
                .execute(insert.replace(SOURCE, TARGET).as_str())
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        let delivered = sqlx::query(&read.replace(SOURCE, TARGET))
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(delivered.get::<String, _>("id"), TARGET);
        assert_eq!(
            serde_json::from_str::<Value>(&delivered.get::<String, _>("payload")).unwrap()["id"],
            TARGET
        );
        let historical = sqlx::query(history).fetch_one(&mut client).await.unwrap();
        assert_eq!(historical.get::<String, _>("id"), HISTORICAL);
        assert!(
            client
                .execute(update.replace(SOURCE, WRONG).as_str())
                .await
                .is_err()
        );
        assert!(
            client
                .execute(copy.replace(HISTORICAL, TARGET).as_str())
                .await
                .is_err()
        );
        assert!(
            client
                .execute(update.replace(SOURCE, TARGET).as_str())
                .await
                .is_ok()
        );
        assert!(client.execute(copy.as_str()).await.is_ok());

        // The independently asserted API response joins the live dependency map
        // through the actual private Unix control transport before case cleanup.
        let socket = crate::replay::allocate_control_socket();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let session = temp.path().join("identity-session.json");
        std::fs::write(&session, json!({"control_socket":socket}).to_string()).unwrap();
        let server_state = runtime.state.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                crate::replay::control::handle_control_stream(
                    stream,
                    server_state.clone(),
                    None,
                    None,
                )
                .await
                .unwrap();
            }
        });
        let policy = crate::policy::parse_and_compile_policy(POLICY).unwrap();
        let rules = policy
            .rules
            .iter()
            .filter(|rule| rule.rule.surface == crate::policy::Surface::ApiResponse)
            .collect::<Vec<_>>();
        let compare = |id: &str| {
            crate::value_contract::encoded::compare(
                json!({"id":SOURCE}).to_string().as_bytes(),
                json!({"id":id}).to_string().as_bytes(),
                &rules,
                Default::default(),
            )
            .unwrap()
            .identity_pairs()
        };
        assert!(
            crate::replay::check_response_identities(&session, "case-id", &compare(TARGET))
                .await
                .is_ok()
        );
        assert!(
            crate::replay::check_response_identities(&session, "case-id", &compare(WRONG))
                .await
                .is_err()
        );
        server.await.unwrap();
        let _ = std::fs::remove_file(socket);
        client.close().await.unwrap();
        assert_eq!(std::fs::read(capture).unwrap(), original);
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 5);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 3);
        task.abort();
    })
    .await
    .unwrap();
}
