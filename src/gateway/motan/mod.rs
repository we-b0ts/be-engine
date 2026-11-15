use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use motan_codec::inspect_request;
use motan_protocol::{FrameDecoder, Limits, MessageKind};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::config::MotanGatewayConfig;
use crate::protocols::recording::events::{ProxyErrorEvent, RecorderEvent};
use crate::recorder::CaseContext;
use crate::recording_control::RecordingListener;

mod case;
pub(crate) mod ready;
pub(crate) mod rules;
pub(crate) mod transport;

pub(crate) async fn run(state: AppState) -> Result<()> {
    let listen = state.config().motan_gateway.listen;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind Motan gateway {listen}"))?;
    run_with_listener(state, listener).await
}

async fn run_with_listener(state: AppState, listener: TcpListener) -> Result<()> {
    let config = state.config().motan_gateway.clone();
    state.mark_recording_listener_ready(RecordingListener::MotanGateway);
    info!(
        listen = %config.listen,
        matched_upstream = %config.matched_upstream,
        "Motan gateway listening"
    );
    let connections = Arc::new(Semaphore::new(config.max_connections));
    let mut ready_task = Some(tokio::spawn(ready::run(state.clone(), config.clone())));
    loop {
        let accepted = tokio::select! {
            ready_result = async {
                ready_task.as_mut().expect("ready task branch is guarded").await
            }, if ready_task.is_some() => {
                ready_task = None;
                ready_result
                    .context("Motan gateway ready task failed")?
                    .context("Motan gateway readiness failed")?;
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = accepted.context("failed to accept Motan gateway client")?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            warn!(%peer, "Motan gateway connection limit reached; rejecting client");
            drop(stream);
            continue;
        };
        let state = state.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let peer = peer.to_string();
            if let Err(error) = handle_connection(stream, peer.clone(), state.clone(), config).await
            {
                warn!(%peer, %error, "Motan gateway connection ended with error");
                if let Err(record_error) =
                    record_gateway_error(&state, Some(peer), error.to_string()).await
                {
                    warn!(%record_error, "failed to persist Motan gateway connection error");
                }
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: String,
    state: AppState,
    config: MotanGatewayConfig,
) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("failed to configure Motan downstream TCP_NODELAY")?;
    let limits = protocol_limits(&config);
    let mut decoder = FrameDecoder::new(limits)?;
    while let Some(request) = transport::read_frame(&mut stream, &mut decoder, limits).await? {
        if request.kind != MessageKind::Request {
            anyhow::bail!("Motan gateway client sent a response frame");
        }
        let envelope = match inspect_request(&request) {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!(%peer, %error, "Motan request identity is malformed; returning fixed response");
                record_gateway_error(
                    &state,
                    Some(peer.clone()),
                    format!("Motan request identity is malformed: {error}"),
                )
                .await?;
                transport::write_fixed_response(&mut stream, &request, limits).await?;
                continue;
            }
        };
        if envelope.heartbeat {
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        }
        let Some(matched) = rules::evaluate_request(&config.rules, &envelope) else {
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        };
        let api_pattern = format!("/rpc/{}", rules::api_directory(&matched.descriptor));
        if !state.should_record_motan_api(&api_pattern) {
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        }
        let case_context = CaseContext {
            id: Uuid::new_v4(),
            rule_name: matched.rule_name.clone(),
            uri_group: Some(matched.directory.clone()),
        };
        let Some(case_guard) = case::try_admit_case(
            &state,
            &case_context,
            &matched.descriptor,
            config.max_cases_per_api,
            &config.matched_upstream,
        )
        .await
        else {
            transport::write_fixed_response(&mut stream, &request, limits).await?;
            continue;
        };
        let started = Instant::now();
        let request_record = case::request_record(
            &state,
            &request,
            Some(peer.clone()),
            &matched.descriptor,
            &matched.rule_name,
            &config.matched_upstream,
        );
        let forwarded = transport::forward_request(
            &request,
            &config.matched_upstream,
            Duration::from_millis(config.connect_timeout_ms),
            Duration::from_millis(config.request_timeout_ms),
            limits,
        )
        .await;
        let (response, error) = match forwarded {
            Ok(response) => (response, None),
            Err(error) => {
                warn!(
                    %error,
                    case_id = %case_context.id,
                    api_key = %matched.descriptor.api_key,
                    "Motan matched upstream request failed; returning fixed response"
                );
                (None, Some(error.to_string()))
            }
        };
        let response_record = case::response_record(
            &state,
            &request,
            response.as_ref(),
            started.elapsed().as_millis(),
            error,
        );
        let drain_invalidation = state.drain_active_case_dependencies(case_context.id).await;
        if let Err(error) = case::finalize_case(
            state.recorder(),
            &case_context,
            request_record,
            response_record,
            state
                .active_case_invalidation(case_context.id)
                .or(drain_invalidation),
        )
        .await
        {
            warn!(%error, case_id = %case_context.id, "failed to finalize Motan gateway case");
            record_gateway_error(
                &state,
                Some(peer.clone()),
                format!(
                    "failed to finalize Motan gateway case {}: {error}",
                    case_context.id
                ),
            )
            .await?;
        }
        drop(case_guard);

        if let Some(response) = response.as_ref() {
            transport::write_frame(&mut stream, response).await?;
        } else {
            transport::write_fixed_response(&mut stream, &request, limits).await?;
        }
    }
    Ok(())
}

async fn record_gateway_error(
    state: &AppState,
    client_addr: Option<String>,
    error: String,
) -> Result<()> {
    state
        .recorder()
        .record(RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            connection_id: None,
            timestamp: chrono::Utc::now(),
            protocol: "motan_gateway".to_string(),
            client_addr,
            target: Some(state.config().motan_gateway.matched_upstream.clone()),
            error,
        }))
        .await
}

fn protocol_limits(config: &MotanGatewayConfig) -> Limits {
    Limits {
        max_frame_bytes: config.max_frame_bytes,
        max_metadata_bytes: config.max_frame_bytes,
        max_body_bytes: config.max_frame_bytes,
    }
}

#[cfg(test)]
mod tests;
