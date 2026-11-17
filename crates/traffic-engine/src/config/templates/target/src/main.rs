use std::net::SocketAddr;

use anyhow::{Context as _, Result};
use http_server::{Server, StatusCode};

// Initialization-only verification. Delete this module declaration and the
// startup_probe::run() call as soon as real target implementation begins.
mod startup_probe;

const DEFAULT_PORT: u16 = 8080;

http_server::registry!(group = readiness_apis);

// Export business APIs the same way, in their owning modules. Combine them
// by merging the routers returned by http_server::handlers! for each group.
#[http_server::get("/healthz", group = readiness_apis)]
async fn readiness() -> StatusCode {
    StatusCode::OK
}

#[tokio::main]
async fn main() -> Result<()> {
    let logs = brz_logs::init_default().context("failed to initialize application logging")?;
    startup_probe::run().await?;
    let address = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT));
    let routes = http_server::handlers!(; group = readiness_apis)
        .context("failed to build target routes")?;
    let server = Server::bind(address, routes)
        .await
        .with_context(|| format!("failed to bind target listener on {address}"))?;
    tracing::info!(%address, "target template started");

    let serve_result = server
        .serve_until(shutdown_signal())
        .await
        .context("target server failed");
    tracing::info!("target template stopped");
    logs.flush().context("failed to flush application logs")?;
    serve_result
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
