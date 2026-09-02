use std::net::SocketAddr;

use anyhow::{Context as _, Result, ensure};
use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use tokio::net::TcpListener;

const DEFAULT_PORT: u16 = 8080;
const TARGET_PORT_ENV: Option<&str> = None;
const READINESS_PATH: &str = "/healthz";
const READINESS_STATUS: u16 = 404;

#[tokio::main]
async fn main() -> Result<()> {
    let logs = brz_logs::init_default().context("failed to initialize application logging")?;
    let port = target_port()?;
    let address = SocketAddr::from(([0, 0, 0, 0], port));
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

fn target_port() -> Result<u16> {
    let Some(name) = TARGET_PORT_ENV else {
        return Ok(DEFAULT_PORT);
    };
    let Some(value) = std::env::var_os(name) else {
        return Ok(DEFAULT_PORT);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{name} must contain valid UTF-8 digits"))?;
    let port = value
        .parse::<u16>()
        .with_context(|| format!("{name} must be an integer from 1 through 65535"))?;
    ensure!(port > 0, "{name} must be an integer from 1 through 65535");
    Ok(port)
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
