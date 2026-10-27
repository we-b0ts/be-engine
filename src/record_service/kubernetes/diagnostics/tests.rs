use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn classification_retains_operations_and_causes_without_subprocess_text() {
    let cases = [
        (
            "Unable to listen on port 123: bind: address already in use private-token",
            "listen",
            "address_in_use",
        ),
        (
            "dial tcp: lookup private-host: no such host private-token",
            "unknown",
            "dns",
        ),
        (
            "lost connection to pod",
            "connection_lost",
            "connection_lost",
        ),
        (
            "error creating forwarding stream for port 123 -> 456: Timeout occurred",
            "create_forwarding_stream",
            "timeout",
        ),
        (
            "error creating error stream: connection refused",
            "create_error_stream",
            "connection_refused",
        ),
        (
            "error reading from error stream: unexpected EOF",
            "read_error_stream",
            "eof",
        ),
        (
            "error copying from remote stream: read: connection reset by peer",
            "copy_from_remote",
            "connection_reset",
        ),
        (
            "error copying from local connection: write: broken pipe",
            "copy_from_local",
            "broken_pipe",
        ),
        (
            "error upgrading connection: x509: certificate signed by unknown authority",
            "upgrade_connection",
            "tls",
        ),
        (
            "an error occurred forwarding 123 -> 456: dial: no route to host",
            "forward_connection",
            "network_unreachable",
        ),
        (
            "You must be logged in to the server (Unauthorized)",
            "unknown",
            "authentication",
        ),
        (
            "pods is forbidden: permission denied",
            "unknown",
            "permission_denied",
        ),
        (
            "authentication plugin printed arbitrary text",
            "unknown",
            "authentication",
        ),
        ("private-token=do-not-log-this", "unknown", "unknown"),
    ];
    for (line, operation, cause) in cases {
        assert_eq!(classify(line), StderrDiagnostic { operation, cause });
    }
}

#[test]
fn stderr_tail_is_bounded_and_unknown_lines_are_counted_without_storing_them() {
    let mut diagnostic = ForwardDiagnostics::new(Some(12));
    diagnostic.ready("127.0.0.1:12345".parse().unwrap());
    diagnostic.stdout("Handling connection for 12345 private-stdout-token");
    for index in 0..100 {
        diagnostic.stderr(&format!("private-token={index}"));
    }
    assert_eq!(diagnostic.stderr_lines, 100);
    assert_eq!(diagnostic.unknown_stderr_lines, 100);
    assert_eq!(diagnostic.tail.len(), 1);
    for _ in 0..20 {
        diagnostic.stderr("error creating forwarding stream: connection refused private-token");
        diagnostic.stderr("lost connection to pod private-token");
    }
    assert_eq!(diagnostic.tail.len(), TAIL_LIMIT);
    diagnostic.stderr_drained(true);
    let summary = diagnostic.summary();
    assert!(summary.contains("pid=Some(12)"));
    assert!(summary.contains("listener=Some(127.0.0.1:12345)"));
    assert!(summary.contains("handling_connections=1"));
    assert!(summary.contains("stderr_lines=140"));
    assert!(summary.contains("unknown_stderr_lines=100"));
    assert!(summary.contains("stderr_drained=true"));
    assert!(!summary.contains("private-token"));
    assert!(!summary.contains("private-stdout-token"));
}

#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn exit_events_keep_exit_zero_failure_visible_and_never_emit_private_stderr() {
    use std::os::unix::process::ExitStatusExt;

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = CapturedLog(buffer.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut diagnostic = ForwardDiagnostics::new(Some(31));
        diagnostic.stderr("error creating forwarding stream: Timeout occurred; Authorization: Bearer private-token https://private-host/path?token=private-query");
        diagnostic.stderr("plugin-response-secret");
        diagnostic.stderr_drained(true);
        diagnostic.emit_exit("team/api:8100", &ExitStatus::from_raw(0), false);
        diagnostic.emit_exit("team/api:8100", &ExitStatus::from_raw(libc::SIGTERM), true);
    });
    let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(output.contains("WARN"));
    assert!(output.contains("exit_code=0"));
    assert!(output.contains("shutdown_requested=false"));
    assert!(output.contains("signal=15"));
    assert!(output.contains("shutdown_requested=true"));
    assert!(output.contains("create_forwarding_stream"));
    assert!(output.contains("timeout"));
    for private in [
        "private-token",
        "private-host",
        "private-query",
        "plugin-response-secret",
        "Authorization",
    ] {
        assert!(
            !output.contains(private),
            "private subprocess text escaped into logs"
        );
    }
}
