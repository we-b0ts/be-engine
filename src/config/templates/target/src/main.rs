use std::net::SocketAddr;

use anyhow::{Context as _, Result};
use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use tokio::net::TcpListener;

// Initialization-only verification. Delete this module declaration and the
// startup_probe::run() call as soon as real target implementation begins.
mod startup_probe;

const DEFAULT_PORT: u16 = 8080;
const READINESS_PATH: &str = "/healthz";
const READINESS_STATUS: u16 = 200;

#[tokio::main]
async fn main() -> Result<()> {
    let logs = brz_logs::init_default().context("failed to initialize application logging")?;
    startup_probe::run().await?;
    let address = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind target listener on {address}"))?;
    tracing::info!(%address, "target template started");

    let serve_result = axum::serve(listener, Router::new().fallback(handle_request))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("target server failed");
    tracing::info!("target template stopped");
    logs.flush().context("failed to flush application logs")?;
    serve_result
}

async fn handle_request(request: Request) -> StatusCode {
    if request.uri().path() == READINESS_PATH {
        StatusCode::from_u16(READINESS_STATUS).expect("validated readiness status")
    } else {
        StatusCode::NOT_FOUND
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.expect("install SIGINT handler"),
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install shutdown signal handler");
}
