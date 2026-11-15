use super::*;

#[test]
fn flat_capture_retains_host_metadata_and_initializes_runtime_state_independently() {
    let record: RecordedHttpExchange = serde_json::from_value(serde_json::json!({
        "scheme": "http",
        "method": "GET",
        "uri": "/legacy?key=value",
        "authority": "dependency.test",
        "duration_ms": "untrusted optional timing",
        "request_body": {"encoding":"utf8", "truncated":false, "data":"request"},
        "response_status": 200,
        "response_body": {"encoding":"utf8", "truncated":false, "data":"response"},
        "discovered_tcp_targets": [{
            "protocol": "http",
            "alias": "discovered.trp.test",
            "advertised_ip": "198.19.0.20",
            "upstream_ip": "127.0.0.1",
            "port": 9000
        }],
        "cleanup_authorized": true,
        "materialized_proxy_failure": true,
        "stream_delivery": true,
        "lifecycle_stop": true,
        "response_evidence": true,
        "protected_request_headers": ["authorization"]
    }))
    .unwrap();
    assert_eq!(record.native.method, "GET");
    assert_eq!(record.native.uri, "/legacy?key=value");
    assert!(record.native.request_headers.is_empty());
    assert!(record.native.request_body.stored_len.is_none());
    assert_eq!(
        decode_body(&record.native.request_body).unwrap(),
        b"request"
    );
    assert_eq!(
        record.native.duration_ms,
        Some(Value::from("untrusted optional timing"))
    );
    assert_eq!(record.discovered_tcp_targets.len(), 1);
    assert_eq!(record.discovered_tcp_targets[0].port, 9000);
    assert!(!record.cleanup_authorized);
    assert!(!record.materialized_proxy_failure);
    assert!(record.stream_delivery.is_none());
    assert!(record.lifecycle_stop.is_none());
    assert!(record.response_evidence.is_none());
    assert!(record.protected_request_headers.is_empty());
}
