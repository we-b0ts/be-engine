use super::*;
use bytes::Bytes;
use serde_json::json;
use traffic_protocol::message::ProtocolMessage;

fn event() -> Value {
    json!({"event_type":"mysql_exchange", "connection_id":uuid::Uuid::nil(), "query_sequence":1,
        "target_host":"db.test", "target_port":3306, "database":"app", "username":"user",
        "command":"COM_QUERY", "sql":"SELECT id FROM items WHERE id=7",
        "response":{"status":"resultset","columns":[{"name":"id","column":"id","table":"items","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":7}]]}})
}

#[test]
fn projection_retains_sql_order_and_exposes_values_without_policy_implementations() {
    let project = |sql: &str| {
        RequestMessage {
            command: "COM_QUERY".into(),
            sql: Some(sql.into()),
            params: None,
            database: None,
            username: None,
        }
        .project()
        .unwrap()
    };
    let source = project("SELECT * FROM t WHERE a=1 AND b IN (2,3)");
    assert_eq!(
        source.structure,
        project("select * from t where a=1 and b in (2,3)").structure
    );
    assert_ne!(
        source.structure,
        project("select * from t where b in (2,3) and a=1").structure
    );
    let reordered = project("select * from t where a=1 and b in (3,2)");
    assert_eq!(source.structure, reordered.structure);
    assert_ne!(
        source.values["/literals/1"].bytes,
        reordered.values["/literals/1"].bytes
    );
    assert_ne!(
        source.values["/literals/2"].bytes,
        reordered.values["/literals/2"].bytes
    );
}

#[test]
fn native_result_cells_can_be_selected_and_encoded_through_the_shared_value_port() {
    let exchange = Native.recorded_exchange(&event()).unwrap().unwrap();
    let mut values: std::collections::BTreeMap<String, Bytes> = exchange
        .response
        .project()
        .unwrap()
        .values
        .into_iter()
        .map(|(path, value)| (path, value.bytes))
        .collect();
    assert_eq!(
        exchange
            .response
            .locate(&json!({"kind":"field","table":"items","column":"id"}))
            .unwrap(),
        ["/rows/0/0"]
    );
    values.insert("/rows/0/0".into(), Bytes::from_static(b"99"));
    let bytes = exchange.response.encode(&values).unwrap();
    let response: response::ResponseMessage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response.response.rows[0][0].value, Some(json!(99)));
    assert_eq!(response.response.columns[0].sql_type, "INT");
}

#[test]
fn incomplete_capture_and_unimplemented_prepared_commands_fail_at_projection() {
    let mut record = event();
    record["response"]["rows_truncated"] = json!(true);
    assert!(Native.recorded_exchange(&record).is_err());
    record = event();
    record["command"] = json!("COM_STMT_EXECUTE");
    assert!(Native.recorded_exchange(&record).is_err());
}
