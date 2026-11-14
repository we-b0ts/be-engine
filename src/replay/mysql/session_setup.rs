//! Native driver initialization facts used by the shared replay lifecycle.
pub(in crate::replay) use traffic_protocol_mysql::session_control::is_nonsemantic_session_setup;
pub(super) use traffic_protocol_mysql::session_setup::is_mysql_session_setup_sql;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_setup_observations_require_native_success_and_no_transaction_effect() {
        let mut capture = crate::dependency::observation::fixture_capture("case");
        capture.semantic_required = false;
        let value = serde_json::json!({
            "capture":capture, "command":"COM_QUERY", "sql":"SET NAMES utf8mb4",
            "query_sequence":1, "server_status_before":null,
            "response":{"status":"ok", "server_status":2, "affected_rows":0,
                        "last_insert_id":0}
        });
        let parse =
            |value| serde_json::from_value::<super::super::RecordedMysqlExchange>(value).unwrap();
        assert!(is_nonsemantic_session_setup(&parse(value.clone())));
        for (pointer, replacement) in [
            ("/capture/semantic_required", serde_json::json!(true)),
            ("/capture", serde_json::Value::Null),
            ("/sql", serde_json::json!("SET AUTOCOMMIT = 0")),
            ("/sql", serde_json::json!("SET @business = 1")),
            ("/response/status", serde_json::json!("error")),
            ("/response/affected_rows", serde_json::json!(1)),
            ("/server_status_before", serde_json::json!(1)),
            ("/query_sequence", serde_json::json!(2)),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(!is_nonsemantic_session_setup(&parse(changed)), "{pointer}");
        }
    }
}
