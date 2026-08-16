use std::time::Duration;

use anyhow::{Context, Result, ensure};
use motan_protocol::{DecodeStatus, FrameBuilder, Limits, ResponseStatus, decode_frame};
use tracing::{debug, info};

use crate::AppState;
use crate::config::MotanGatewayConfig;
use crate::recording_control::RecordingListener;

use super::transport;

const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const PROBE_REQUEST_ID: u64 = 0;

pub(super) async fn run(state: AppState, config: MotanGatewayConfig) -> Result<()> {
    let limits = super::protocol_limits(&config);
    let mut ticker = tokio::time::interval(PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!(
        upstream = %config.matched_upstream,
        interval_ms = PROBE_INTERVAL.as_millis(),
        "Motan gateway ready probe started"
    );

    while state.is_bootstrap_open() {
        ticker.tick().await;
        match probe_once(
            &config.matched_upstream,
            Duration::from_millis(config.connect_timeout_ms),
            Duration::from_millis(config.request_timeout_ms),
            limits,
        )
        .await
        {
            Ok(()) => {
                let admission_enabled = state
                    .mark_recording_upstream_ready(
                        RecordingListener::MotanGateway,
                        "all enabled upstreams ready",
                    )
                    .await
                    .context("Motan gateway readiness could not update source readiness")?;
                info!(
                    upstream = %config.matched_upstream,
                    admission_enabled,
                    "Motan gateway ready probe succeeded"
                );
                return Ok(());
            }
            Err(error) => {
                debug!(
                    upstream = %config.matched_upstream,
                    %error,
                    "Motan gateway ready probe failed"
                );
            }
        }
    }

    info!("Motan gateway ready probe stopped because bootstrap is already closed");
    Ok(())
}

pub(crate) async fn probe_once(
    upstream: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    limits: Limits,
) -> Result<()> {
    let encoded = FrameBuilder::request(PROBE_REQUEST_ID)
        .heartbeat(true)
        .encode()
        .context("failed to encode Motan heartbeat readiness request")?;
    let DecodeStatus::Complete(request) = decode_frame(&encoded, limits)? else {
        anyhow::bail!("encoded Motan heartbeat readiness request is incomplete");
    };
    let response =
        transport::forward_request(&request, upstream, connect_timeout, request_timeout, limits)
            .await?
            .context("Motan heartbeat readiness probe returned no response")?;
    ensure!(
        response.flags.heartbeat(),
        "Motan heartbeat readiness response omitted the heartbeat flag"
    );
    ensure!(
        response.status == ResponseStatus::Normal,
        "Motan heartbeat readiness response was not normal"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use motan_protocol::FrameDecoder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn accepts_a_normal_motan2_heartbeat_response() {
        let upstream = spawn_upstream_response(true).await;

        probe_once(
            &upstream.to_string(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Limits::default(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejects_a_response_without_the_heartbeat_flag() {
        let upstream = spawn_upstream_response(false).await;

        let error = probe_once(
            &upstream.to_string(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Limits::default(),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("omitted the heartbeat flag"));
    }

    async fn spawn_upstream_response(heartbeat: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut decoder = FrameDecoder::new(Limits::default()).unwrap();
            let request = loop {
                if let Some(request) = decoder.decode().unwrap() {
                    break request;
                }
                assert!(stream.read_buf(decoder.buffer_mut()).await.unwrap() > 0);
            };
            assert!(request.flags.heartbeat());
            let response = FrameBuilder::response(request.request_id)
                .heartbeat(heartbeat)
                .status(ResponseStatus::Normal)
                .encode()
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });
        address
    }
}
