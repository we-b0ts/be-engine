//! Real child exit and buffered pipes exercise the public diagnostic boundary.

use super::*;
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[tokio::test]
async fn exit_zero_keeps_final_stderr_diagnosis_without_private_output() {
    let logs = Logs::default();
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    );
    let fixture = Fixture::new(&[8100]);
    fixture.settings(serde_json::json!({
        "ports": [8100], "exit_code": 0,
        "runtime_stdout": ["Handling connection for 12345"],
        "runtime_stderr": [
            "plugin output: private-token https://user:password@cluster/?token=secret",
            "error forwarding port 8100 to pod private-token: connection refused",
            "error: lost connection to pod: private-token"
        ]
    }));
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    std::fs::write(fixture.temp.path().join("exit"), "").unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), forwards.failure())
        .await
        .unwrap();
    let error = format!("{error:#}");
    assert!(error.contains("exit status: 0"), "{error}");
    for output in [error, logs.text()] {
        for expected in [
            "connection_refused",
            "connection_lost",
            "stderr_lines=3",
            "stderr_drained=true",
            "handling_connections=1",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        for secret in [
            "private-token",
            "password",
            "token=secret",
            "plugin output",
            "https://",
        ] {
            assert!(!output.contains(secret), "diagnostics exposed {secret}");
        }
    }
    forwards.shutdown().await.unwrap();
}

#[tokio::test]
async fn surviving_plugin_pipe_cannot_block_exit_diagnostics() {
    let fixture = Fixture::new(&[8100]);
    fixture.settings(serde_json::json!({
        "ports": [8100], "helper": true, "exit_code": 0,
        "runtime_stderr": ["lost connection to pod: private-token"]
    }));
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    std::fs::write(fixture.temp.path().join("exit"), "").unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), forwards.failure())
        .await
        .unwrap();
    let error = format!("{error:#}");
    assert!(error.contains("connection_lost"), "{error}");
    assert!(error.contains("stderr_drained=false"), "{error}");
    assert!(!error.contains("private-token"));
    forwards.shutdown().await.unwrap();
}

#[tokio::test]
async fn requested_shutdown_is_logged_separately_from_forward_failure() {
    let logs = Logs::default();
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    );
    let fixture = Fixture::new(&[8100]);
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    forwards.shutdown().await.unwrap();
    let output = logs.text();
    assert!(output.contains("shutdown_requested=true"), "{output}");
    assert!(output.contains("stderr_drained=true"), "{output}");
    assert!(!output.contains("private-token"));
}
