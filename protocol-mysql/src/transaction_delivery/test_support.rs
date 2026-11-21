//! Source fixtures shared with native connection conformance tests.
use serde_json::{Value, json};
use uuid::Uuid;

pub fn records() -> Vec<Value> {
    let control = |seq, sql, before, after| {
        json!({
            "event_type":"mysql_exchange", "connection_id":Uuid::nil(), "query_sequence":seq,
            "target_host":"127.0.0.1", "target_port":3306, "database":"appdb", "username":"root",
            "command":"COM_QUERY", "sql":sql, "server_status_before":before,
            "response":{"status":"ok", "server_status":after, "affected_rows":0, "last_insert_id":0}
        })
    };
    let read = |seq| {
        let mut r = control(seq, "SELECT id FROM users WHERE id=1", 0, 1);
        r["response"] = json!({"status":"resultset", "server_status":1,
            "columns":[{"name":"id", "family":"integer", "sql_type":"INT"}],
            "rows":[[{"kind":"integer", "value":1}]]});
        r
    };
    vec![
        control(3, "SET AUTOCOMMIT = 0", 2, 0),
        read(5),
        control(6, "UPDATE users SET active=1 WHERE id=1", 1, 1),
        control(7, "COMMIT", 1, 0),
        control(8, "ROLLBACK", 0, 0),
        read(9),
        control(10, "UPDATE users SET active=2 WHERE id=1", 1, 1),
        control(11, "COMMIT", 1, 0),
    ]
}
