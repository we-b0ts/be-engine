mod broker;
mod matcher;
pub(super) mod report;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::dependency::DependencyExchangeOutcome;
use crate::kafka::{decode_request, read_frame, replay_supports, write_frame};

pub(crate) use matcher::KafkaReplayState;
pub(super) use matcher::{
    FiniteExchange, RecordedKafkaConnection, RecordedKafkaDelivery, RecordedKafkaFetch,
    RecordedKafkaProduce,
};
pub(super) use report::KafkaProtocolReport;

use super::{ReplayState, ReplayTarget, TargetKey};

pub(crate) async fn handle_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.protocols.kafka.events.connections += 1;
    let control = crate::dependency::termination::ConnectionControl::new(&stream)?;

    while let Some(payload) = read_frame(&mut stream, 64 * 1024 * 1024).await? {
        let request_started = tokio::time::Instant::now();
        let decoded = decode_request(&payload)?;
        let active_case_id = state.lock().await.active_case_id.clone();
        if !replay_supports(decoded.api_key, decoded.header.request_api_version) {
            let reason = format!(
                "Kafka {:?} version {} is outside the replay V1 profile",
                decoded.api_key, decoded.header.request_api_version
            );
            state.lock().await.protocols.kafka.record_unsupported(
                active_case_id.as_deref(),
                &target_key,
                format!("{:?}", decoded.api_key),
                reason.clone(),
            );
            anyhow::bail!(reason);
        }
        let plan = broker::response_for(&decoded, &target_key, state.clone())
            .await
            .with_context(|| {
                format!(
                    "failed to handle Kafka {:?} version {}",
                    decoded.api_key, decoded.header.request_api_version
                )
            })?;
        if let Some(timing) = plan.timing() {
            match timing.outcome() {
                DependencyExchangeOutcome::ClientTerminated => {
                    match timing
                        .await_client_termination_at(&mut stream, request_started)
                        .await
                    {
                        Ok(_) => {
                            plan.commit(&state).await;
                            return Ok(());
                        }
                        Err(error) => {
                            let reason = error.to_string();
                            plan.fail(&state, &target_key, reason).await;
                            super::exchange::retain_connection(&mut stream).await;
                            return Err(error);
                        }
                    }
                }
                DependencyExchangeOutcome::Terminated(termination)
                    if termination.side == crate::dependency::TerminationSide::Client =>
                {
                    match timing
                        .await_client_termination_at(&mut stream, request_started)
                        .await
                    {
                        Ok(_) => {
                            plan.commit(&state).await;
                            return Ok(());
                        }
                        Err(error) => {
                            plan.fail(&state, &target_key, error.to_string()).await;
                            super::exchange::retain_connection(&mut stream).await;
                            return Err(error);
                        }
                    }
                }
                DependencyExchangeOutcome::Terminated(termination)
                    if termination.side == crate::dependency::TerminationSide::Server =>
                {
                    let pending = timing
                        .await_server_deadline(&mut stream, request_started, 64 * 1024 * 1024)
                        .await;
                    let pending = match pending {
                        Ok(pending) if pending.is_empty() => pending,
                        Ok(_) => {
                            let error = anyhow::anyhow!(
                                "Target pipelined another Kafka request before recorded server termination; native termination batch replay is unsupported"
                            );
                            plan.fail(&state, &target_key, error.to_string()).await;
                            super::exchange::retain_connection(&mut stream).await;
                            return Err(error);
                        }
                        Err(error) => {
                            plan.fail(&state, &target_key, error.to_string()).await;
                            super::exchange::retain_connection(&mut stream).await;
                            return Err(error);
                        }
                    };
                    debug_assert!(pending.is_empty());
                    match timing
                        .terminate_server_at(&mut stream, &control, request_started)
                        .await
                    {
                        Ok(()) => {
                            plan.commit(&state).await;
                            if termination.kind == crate::dependency::TerminationKind::Eof {
                                let mut probe = [0_u8; 1];
                                if matches!(tokio::io::AsyncReadExt::read(&mut stream, &mut probe).await, Ok(count) if count > 0)
                                {
                                    state.lock().await.protocols.kafka.record_unsupported(active_case_id.as_deref(), &target_key, "after_server_eof".into(), "client sent another Kafka request after recorded server EOF".into());
                                    super::exchange::retain_connection(&mut stream).await;
                                }
                            }
                            return Ok(());
                        }
                        Err(error) => {
                            plan.fail(&state, &target_key, error.to_string()).await;
                            super::exchange::retain_connection(&mut stream).await;
                            return Err(error);
                        }
                    }
                }
                DependencyExchangeOutcome::Terminated(_) => {
                    anyhow::bail!("engine cleanup is not replayable Kafka peer termination")
                }
                DependencyExchangeOutcome::NoResponse => {
                    plan.commit(&state).await;
                    continue;
                }
                DependencyExchangeOutcome::Response => timing.delay_response().await,
            }
        }
        let response = plan
            .response_value()
            .context("Kafka replay response plan did not include a response")?;
        let payload = crate::kafka::encode_response(
            decoded.header.correlation_id,
            decoded.api_key,
            decoded.header.request_api_version,
            response,
        )?;
        if let Err(error) = write_frame(&mut stream, &payload).await {
            let reason = format!("failed to deliver Kafka replay response: {error}");
            plan.fail(&state, &target_key, reason).await;
            return Err(error);
        }
        plan.commit(&state).await;
    }
    Ok(())
}
