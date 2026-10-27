//! Bounded kubectl diagnostics; subprocess output never becomes public text.

use std::{
    collections::VecDeque, net::SocketAddr, os::unix::process::ExitStatusExt, process::ExitStatus,
};

use tokio::time::Instant;

const TAIL_LIMIT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StderrDiagnostic {
    operation: &'static str,
    cause: &'static str,
}

pub(super) struct ForwardDiagnostics {
    pid: Option<u32>,
    started: Instant,
    listener: Option<SocketAddr>,
    handling_connections: u64,
    stderr_lines: u64,
    unknown_stderr_lines: u64,
    stderr_drained: bool,
    tail: VecDeque<StderrDiagnostic>,
}

impl ForwardDiagnostics {
    pub(super) fn new(pid: Option<u32>) -> Self {
        Self {
            pid,
            started: Instant::now(),
            listener: None,
            handling_connections: 0,
            stderr_lines: 0,
            unknown_stderr_lines: 0,
            stderr_drained: false,
            tail: VecDeque::with_capacity(TAIL_LIMIT),
        }
    }

    pub(super) fn ready(&mut self, listener: SocketAddr) {
        self.listener = Some(listener);
    }

    pub(super) fn stdout(&mut self, line: &str) {
        if line.trim().starts_with("Handling connection for ") {
            self.handling_connections = self.handling_connections.saturating_add(1);
        }
    }

    pub(super) fn stderr(&mut self, line: &str) {
        self.stderr_lines = self.stderr_lines.saturating_add(1);
        let diagnostic = classify(line);
        if diagnostic.operation == "unknown" && diagnostic.cause == "unknown" {
            self.unknown_stderr_lines = self.unknown_stderr_lines.saturating_add(1);
        }
        if self.tail.back() == Some(&diagnostic) {
            return;
        }
        if self.tail.len() == TAIL_LIMIT {
            self.tail.pop_front();
        }
        self.tail.push_back(diagnostic);
    }

    pub(super) fn stderr_drained(&mut self, drained: bool) {
        self.stderr_drained = drained;
    }

    pub(super) fn summary(&self) -> String {
        format!(
            "pid={:?} listener={:?} uptime_ms={} handling_connections={} stderr_lines={} unknown_stderr_lines={} stderr_drained={} stderr_tail={:?}",
            self.pid,
            self.listener,
            self.started.elapsed().as_millis(),
            self.handling_connections,
            self.stderr_lines,
            self.unknown_stderr_lines,
            self.stderr_drained,
            self.tail,
        )
    }

    pub(super) fn emit_exit(&self, identity: &str, status: &ExitStatus, shutdown_requested: bool) {
        let summary = self.summary();
        if shutdown_requested {
            tracing::info!(
                service = identity,
                exit_code = status.code(),
                signal = status.signal(),
                shutdown_requested,
                diagnostic = summary,
                "Kubernetes recording port-forward stopped"
            );
        } else {
            tracing::warn!(
                service = identity,
                exit_code = status.code(),
                signal = status.signal(),
                shutdown_requested,
                diagnostic = summary,
                "Kubernetes recording port-forward exited"
            );
        }
    }
}

fn classify(line: &str) -> StderrDiagnostic {
    // Only static labels survive this function. Authentication plugins and
    // Kubernetes errors can put credentials, URLs or arbitrary response bodies
    // anywhere in a line, so substring redaction is insufficient.
    let lower = line.to_ascii_lowercase();
    let operation = if lower.contains("lost connection to pod") {
        "connection_lost"
    } else if lower.contains("error creating forwarding stream") {
        "create_forwarding_stream"
    } else if lower.contains("error creating error stream") {
        "create_error_stream"
    } else if lower.contains("error reading from error stream") {
        "read_error_stream"
    } else if lower.contains("error copying from remote stream") {
        "copy_from_remote"
    } else if lower.contains("error copying from local connection") {
        "copy_from_local"
    } else if lower.contains("error upgrading connection") {
        "upgrade_connection"
    } else if lower.contains("error occurred forwarding") || lower.contains("error forwarding port")
    {
        "forward_connection"
    } else if lower.contains("error accepting connection") {
        "accept_connection"
    } else if lower.contains("unable to listen") {
        "listen"
    } else {
        "unknown"
    };
    let cause = if lower.contains("lost connection to pod") {
        "connection_lost"
    } else if lower.contains("address already in use") {
        "address_in_use"
    } else if lower.contains("no such host")
        || lower.contains("temporary failure in name resolution")
    {
        "dns"
    } else if lower.contains("connection refused") {
        "connection_refused"
    } else if lower.contains("connection reset") {
        "connection_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("no route to host") || lower.contains("network is unreachable") {
        "network_unreachable"
    } else if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("deadline exceeded")
    {
        "timeout"
    } else if lower.contains("unexpected eof")
        || lower.split_ascii_whitespace().any(|word| word == "eof")
    {
        "eof"
    } else if lower.contains("unauthorized")
        || lower.contains("authentication")
        || lower.contains("must be logged in")
    {
        "authentication"
    } else if lower.contains("forbidden") || lower.contains("permission denied") {
        "permission_denied"
    } else if lower.contains("tls") || lower.contains("x509") || lower.contains("certificate") {
        "tls"
    } else {
        "unknown"
    };
    StderrDiagnostic { operation, cause }
}

#[cfg(test)]
mod tests;
