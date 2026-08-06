use super::*;

#[test]
fn failure_references_report_without_embedding_it() {
    let response = serde_json::json!({
        "ok": false,
        "complete": true,
        "dirty": true,
        "error": "replay evidence is dirty",
        "report": {"large_payload": "x".repeat(1_000_000)},
    });
    let session = serde_json::json!({"report_path": "/tmp/replay-report.json"});

    let message = control_failure_message(&response, &session);

    assert!(message.contains("complete=true; dirty=true"));
    assert!(message.contains("/tmp/replay-report.json"));
    assert!(!message.contains("large_payload"));
    assert!(message.len() < 256);
}

#[cfg(unix)]
#[test]
fn allocated_control_socket_stays_below_unix_path_limit() {
    use std::os::unix::ffi::OsStrExt;

    let socket = crate::replay::allocate_control_socket();

    assert!(socket.starts_with("/tmp"));
    assert!(socket.as_os_str().as_bytes().len() < 100);
}
