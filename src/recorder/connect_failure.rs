//! Preserve failed upstream connects as finite physical dependency observations.
use std::io;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::dependency::termination::ConnectionControl;
use crate::recorder::{CaseInvalidation, DependencyConnectFailureEvent, RecorderEvent};

pub(crate) fn record_connect_failure(
    state: &AppState,
    client: &TcpStream,
    targets: DependencyTargets,
    protocol: &str,
    (host, port): (&str, u16),
    started: Instant,
    error: &io::Error,
) -> io::Result<()> {
    record_failure(
        state,
        client,
        targets,
        protocol,
        (host, port),
        started,
        failure_kind(error.kind()),
    )
}

/// A pending OS connect is cancelled by a real case lifecycle boundary. It is
/// not evidence that the upstream refused or timed out on that connection.
fn record_cancelled_connect(
    state: &AppState,
    client: &TcpStream,
    targets: DependencyTargets,
    protocol: &str,
    target: (&str, u16),
    started: Instant,
) -> io::Result<()> {
    if targets.cases.is_empty() {
        // Process shutdown can also cancel unowned/global connection attempts.
        // Those are not a new finite Case input or an upstream failure.
        return ConnectionControl::new(client).and_then(|control| control.reset());
    }
    if !targets.cases.iter().all(|(case, _)| {
        state
            .inner
            .active_cases
            .async_source_stop_requested(case.id)
    }) {
        for (case, _) in &targets.cases {
            state.invalidate_active_case(case.id, CaseInvalidation::new(
                "dependency_connect_cancelled_without_lifecycle",
                "connection attempt ended during engine cleanup without a complete async lifecycle boundary",
            ));
        }
        return ConnectionControl::new(client).and_then(|control| control.reset());
    }
    record_failure(
        state,
        client,
        targets,
        protocol,
        target,
        started,
        "engine_cancelled",
    )
}

pub(crate) async fn connect_upstream<A: tokio::net::ToSocketAddrs>(
    state: &AppState,
    client: &TcpStream,
    protocol: &str,
    target: (&str, u16),
    upstream: A,
) -> io::Result<Option<TcpStream>> {
    let targets = state.capture_dependency_targets();
    let started = Instant::now();
    tokio::select! {
        result = TcpStream::connect(upstream) => match result {
            Ok(stream) => Ok(Some(stream)),
            Err(error) => {
                record_connect_failure(state, client, targets, protocol, target, started, &error)?;
                Err(error)
            }
        },
        _ = state.inner.active_cases.wait_for_quiescing() => {
            record_cancelled_connect(state, client, targets, protocol, target, started)?;
            Ok(None)
        }
    }
}

fn record_failure(
    state: &AppState,
    client: &TcpStream,
    targets: DependencyTargets,
    protocol: &str,
    (host, port): (&str, u16),
    started: Instant,
    failure_kind: &str,
) -> io::Result<()> {
    let client_addr = client.peer_addr().ok().map(|address| address.to_string());
    // A normal drop can produce FIN or RST depending on unread client bytes.
    // Send one explicit reset so the Source observation is reproducible before
    // recording it. A failed control operation is capture corruption instead.
    if let Err(error) = ConnectionControl::new(client).and_then(|control| control.reset()) {
        for (case, _) in &targets.cases {
            state.invalidate_active_case(
                case.id,
                CaseInvalidation::new(
                    "dependency_connect_failure_capture_error",
                    "failed to deliver the observed dependency connection failure to Source",
                ),
            );
        }
        return Err(error);
    }
    state.record_event_for_targets(
        RecorderEvent::DependencyConnectFailure(DependencyConnectFailureEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            client_addr,
            protocol: protocol.into(),
            target_host: host.into(),
            target_port: port,
            duration_ms: started.elapsed().as_millis(),
            failure_kind: failure_kind.into(),
            client_outcome: "reset".into(),
        }),
        targets,
    );
    Ok(())
}

fn failure_kind(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::AddrNotAvailable => "address_unavailable",
        _ => "other",
    }
}

#[cfg(test)]
mod tests;
