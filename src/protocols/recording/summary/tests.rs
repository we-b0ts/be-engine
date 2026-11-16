use super::*;
use traffic_protocol_mysql::capture::is_successful_mysql_session_setup;
#[test]
fn dependency_summary_omits_successful_stmt_prepare_lines() {
    let raw = r#"{"event_type":"mysql_exchange","command":"COM_STMT_PREPARE","response":{"status":"stmt_prepare"}}
{"event_type":"mysql_exchange","command":"COM_STMT_EXECUTE","sql":"SELECT * FROM `user`","response":{"status":"resultset","row_count":0,"columns":[]}}"#;
    let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

    assert_eq!(summary["total_events"], 1);
    assert_eq!(summary["event_types"]["mysql_exchange"], 1);
    assert_eq!(summary["mysql"]["semantic_exchanges"], 1);
    assert_eq!(summary["mysql"]["executed"]["crud"]["select"], 1);
}

#[test]
fn dependency_summary_omits_successful_mysql_session_setup_lines() {
    let raw = r#"{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SET NAMES utf8","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}
{"event_type":"mysql_exchange","query_sequence":4,"command":"COM_QUERY","sql":"SHOW COLLATION","response":{"status":"resultset","row_count":1,"columns":[]}}
{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SET @tenant_id = 1","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}
{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SELECT * FROM `user`","response":{"status":"resultset","row_count":0,"columns":[]}}"#;
    let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

    assert_eq!(summary["total_events"], 2);
    assert_eq!(summary["event_types"]["mysql_exchange"], 2);
    assert_eq!(summary["mysql"]["semantic_exchanges"], 2);
    assert_eq!(summary["mysql"]["executed"]["crud"]["select"], 1);
    assert_eq!(summary["mysql"]["executed"]["crud"]["other"], 1);
}

#[test]
fn rollback_is_preserved_in_semantic_dependencies() {
    let raw = r#"{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"ROLLBACK","response":{"status":"ok","affected_rows":0,"last_insert_id":0}}
{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"ROLLBACK","response":{"status":"error","error_code":1205}}"#;
    let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();
    assert_eq!(summary["mysql"]["semantic_exchanges"], 2);
    assert!(!is_successful_mysql_session_setup(
        "COM_QUERY",
        Some("ROLLBACK"),
        "ok",
        1
    ));
}

#[test]
fn dependency_summary_includes_mysql_connection_and_tls_rejection() {
    let raw = r#"{"event_type":"mysql_connection","route_name":"pluto","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","username":"root","database":"pluto","upstream_addr":"127.0.0.1:3306","error":null}
{"event_type":"mysql_tls_rejected","route_name":"pluto","target_host":"mysql.internal","target_port":3306,"target_addr":"mysql.internal:3306","upstream_addr":"127.0.0.1:3306","reason":"CLIENT_SSL is unsupported"}"#;
    let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

    assert_eq!(summary["total_events"], 2);
    assert_eq!(summary["event_types"]["mysql_connection"], 1);
    assert_eq!(summary["event_types"]["mysql_tls_rejected"], 1);
    assert_eq!(summary["mysql"]["connections"], 1);
    assert_eq!(summary["mysql"]["tls_rejected"], 1);
    assert_eq!(summary["mysql"]["routes"]["pluto"], 2);
    assert_eq!(summary["mysql"]["target_hosts"]["mysql.internal"], 2);
    assert_eq!(summary["mysql"]["target_addrs"]["mysql.internal:3306"], 2);
    assert_eq!(summary["mysql"]["databases"]["pluto"], 1);
    assert_eq!(summary["mysql"]["users"]["root"], 1);
    assert_eq!(summary["mysql"]["upstreams"]["127.0.0.1:3306"], 2);
    assert_eq!(
        summary["mysql"]["tls_rejection_reasons"]["CLIENT_SSL is unsupported"],
        1
    );
}

#[test]
fn dependency_summary_includes_redis_without_payloads() {
    let raw = r#"{"event_type":"redis_connection","id":"11111111-1111-1111-1111-111111111111","target_host":"redis.internal","target_port":6379,"resp_version":3}
{"event_type":"redis_exchange","connection_id":"11111111-1111-1111-1111-111111111111","target_host":"redis.internal","target_port":6379,"resp_version":3,"command":"GET","args":[{"original_len":6}],"response_kind":"bulk_string","response":{"original_len":9},"replay_safe":true}
{"event_type":"memcached_connection","id":"22222222-2222-2222-2222-222222222222","target_host":"cache.internal","target_port":11211,"wire_protocol":"text"}
{"event_type":"memcached_exchange","connection_id":"22222222-2222-2222-2222-222222222222","target_host":"cache.internal","target_port":11211,"wire_protocol":"text","command":"get","response_status":"VALUE secret 0 5","response_frames":[{"original_len":31}],"replay_safe":true}"#;
    let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

    assert_eq!(summary["redis"]["connections"], 1);
    assert_eq!(summary["redis"]["commands"]["GET"], 1);
    assert_eq!(summary["redis"]["request_bytes"], 6);
    let serialized = serde_json::to_string(&summary).unwrap();
    assert!(!serialized.contains("secret"));
}

#[test]
fn dependency_summary_tracks_publishable_client_terminations() {
    let raw = r#"{"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SELECT * FROM `user`","outcome":"client_terminated","response":{"status":"client_terminated"}}
{"event_type":"redis_exchange","command":"GET","outcome":"client_terminated","response_kind":"other","replay_safe":true}
{"event_type":"memcached_exchange","command":"get","outcome":"client_terminated","response_status":"incomplete","replay_safe":true}
{"event_type":"http_exchange","method":"POST","outcome":"client_terminated","response_status":null}"#;
    let summary = serde_json::to_value(build_dependency_summary(raw)).unwrap();

    assert_eq!(summary["mysql"]["failed"]["total"], 1);
    assert_eq!(summary["redis"]["client_terminated"], 1);
    assert_eq!(summary["redis"]["outcomes"]["client_terminated"], 1);
    assert_eq!(summary["http"]["client_terminated"], 1);
}
