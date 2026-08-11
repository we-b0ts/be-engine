use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Uri};
use tracing::{debug, info};

use crate::AppState;
use crate::config::{HttpGatewayConfig, HttpGatewayReadyConfig};
use crate::recorder::readiness::PostReadyWaitOutcome;

use super::transport::{build_upstream_request, build_upstream_uri, send_upstream};

pub(super) async fn run(state: AppState, config: HttpGatewayConfig) -> Result<()> {
    let interval = Duration::from_millis(config.ready.interval_ms.max(1));
    let post_ready_quiet = state.config().recording.post_ready_quiet_period();
    let post_ready_max_wait = state.config().recording.post_ready_max_wait();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!(
        upstream = %config.matched_upstream,
        path = %config.ready.path,
        success_status = config.ready.success_status,
        interval_ms = config.ready.interval_ms.max(1),
        "HTTP gateway ready probe started"
    );

    while state.is_bootstrap_open() {
        ticker.tick().await;
        match probe_once(&state, &config.matched_upstream, &config.ready).await {
            Ok(status) if status == config.ready.success_status => {
                let ready_at = tokio::time::Instant::now();
                if state.has_background_initial_loads() || !post_ready_quiet.is_zero() {
                    state.mark_recording_source_settling();
                    info!(
                        upstream = %config.matched_upstream,
                        path = %config.ready.path,
                        status,
                        post_ready_quiet_ms = post_ready_quiet.as_millis(),
                        post_ready_max_wait_ms = post_ready_max_wait.as_millis(),
                        waits_for_background_initial_load = state.has_background_initial_loads(),
                        "HTTP gateway ready probe succeeded; waiting for case admission prerequisites"
                    );
                }
                let wait_outcome = state
                    .wait_for_post_ready_admission(ready_at)
                    .await
                    .context(
                        "post-ready process-owned dependency observation failed with the source",
                    )?;
                if wait_outcome == PostReadyWaitOutcome::MaximumWaitElapsed {
                    tracing::warn!(
                        post_ready_max_wait_ms = post_ready_max_wait.as_millis(),
                        "post-ready process-owned dependency observation reached its hard limit; continuing recording"
                    );
                }
                if !state.is_bootstrap_open() {
                    info!("HTTP gateway readiness stopped because bootstrap is already closed");
                    return Ok(());
                }
                match state.close_bootstrap("http_gateway.ready").await {
                    Ok(true) => {}
                    Ok(false) => {
                        info!("HTTP gateway ready probe stopped before case admission was enabled");
                        return Ok(());
                    }
                    Err(error) => {
                        return Err(error).context(
                            "HTTP gateway ready probe could not seal bootstrap dependencies",
                        );
                    }
                }
                info!(
                    upstream = %config.matched_upstream,
                    path = %config.ready.path,
                    status,
                    post_ready_quiet_ms = post_ready_quiet.as_millis(),
                    post_ready_max_wait_ms = post_ready_max_wait.as_millis(),
                    "HTTP gateway ready probe succeeded and case admission is enabled"
                );
                return Ok(());
            }
            Ok(status) => {
                debug!(
                    upstream = %config.matched_upstream,
                    path = %config.ready.path,
                    status,
                    expected = config.ready.success_status,
                    "HTTP gateway ready probe did not match"
                );
            }
            Err(err) => {
                debug!(
                    upstream = %config.matched_upstream,
                    path = %config.ready.path,
                    error = %err,
                    "HTTP gateway ready probe failed"
                );
            }
        }
    }

    info!("HTTP gateway ready probe stopped because bootstrap is already closed");
    Ok(())
}

async fn probe_once(
    state: &AppState,
    upstream_base: &str,
    ready: &HttpGatewayReadyConfig,
) -> Result<u16> {
    let ready_uri = path_uri(&ready.path)?;
    let outbound_uri = build_upstream_uri(upstream_base, &ready_uri)?;
    let outbound = build_upstream_request(
        &Method::GET,
        outbound_uri,
        Bytes::new(),
        &HeaderMap::new(),
        false,
    )?;
    let response = send_upstream(state.client(), outbound)
        .await
        .context("HTTP gateway ready probe request failed")?;
    let status = response.status().as_u16();
    let _ = response.into_body().collect().await;
    Ok(status)
}

fn path_uri(path: &str) -> Result<Uri> {
    let trimmed = path.trim();
    let normalized = if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    };
    normalized
        .parse::<Uri>()
        .with_context(|| format!("invalid HTTP gateway ready path {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppConfig, HttpGatewayReadyConfig};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn builds_probe_path_uri() {
        assert_eq!(path_uri("").unwrap().to_string(), "/");
        assert_eq!(path_uri("healthz").unwrap().to_string(), "/healthz");
        assert_eq!(
            path_uri(" /ready?probe=1 ").unwrap().to_string(),
            "/ready?probe=1"
        );
    }

    #[tokio::test]
    async fn closes_bootstrap_on_success_status() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.http_gateway.matched_upstream = format!("http://{upstream_addr}");
        config.http_gateway.ready = HttpGatewayReadyConfig {
            enabled: true,
            path: "/ready".to_string(),
            success_status: 200,
            interval_ms: 1,
        };
        config.recording.post_ready_settle_ms = 0;
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");

        let state = AppState::new(config).await.unwrap();
        assert!(state.is_bootstrap_open());

        let ready_config = state.config().http_gateway.clone();
        tokio::time::timeout(Duration::from_secs(1), run(state.clone(), ready_config))
            .await
            .unwrap()
            .unwrap();

        assert!(!state.is_bootstrap_open());
    }

    #[tokio::test(start_paused = true)]
    async fn delays_case_admission_after_source_readiness() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.http_gateway.matched_upstream = format!("http://{upstream_addr}");
        config.http_gateway.ready = HttpGatewayReadyConfig {
            enabled: true,
            path: "/ready".to_string(),
            success_status: 200,
            interval_ms: 1,
        };
        config.recording.post_ready_settle_ms = 15_000;
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");

        let state = AppState::new(config).await.unwrap();
        let ready_config = state.config().http_gateway.clone();
        let started = tokio::time::Instant::now();
        let ready_task = tokio::spawn(run(state.clone(), ready_config));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let readiness = state.inner.recording_lifecycle.snapshot();
                if readiness.phase == "settling" {
                    assert!(!readiness.source_ready);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(state.is_bootstrap_open());
        ready_task.await.unwrap().unwrap();
        assert!(started.elapsed() >= Duration::from_secs(15));
        assert!(!state.is_bootstrap_open());
    }
}
