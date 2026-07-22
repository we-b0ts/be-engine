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

pub(super) use matcher::{
    KafkaReplayState, RecordedKafkaConnection, RecordedKafkaDelivery, RecordedKafkaFetch,
    RecordedKafkaProduce,
};
pub(super) use report::KafkaProtocolReport;

use super::{ReplayReportWriter, ReplayState, ReplayTarget, TargetKey};

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_writer: ReplayReportWriter,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.kafka.events.connections += 1;
    report_writer.request();

    while let Some(payload) = read_frame(&mut stream, 64 * 1024 * 1024).await? {
        let decoded = decode_request(&payload)?;
        let active_case_id = state.lock().await.active_case_id.clone();
        if !replay_supports(decoded.api_key, decoded.header.request_api_version) {
            let reason = format!(
                "Kafka {:?} version {} is outside the replay V1 profile",
                decoded.api_key, decoded.header.request_api_version
            );
            state.lock().await.kafka.record_unsupported(
                active_case_id.as_deref(),
                &target_key,
                format!("{:?}", decoded.api_key),
                reason.clone(),
            );
            report_writer.request();
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
                    match timing.await_client_termination(&mut stream).await {
                        Ok(_) => {
                            plan.commit(&state).await;
                            report_writer.request();
                            return Ok(());
                        }
                        Err(error) => {
                            let reason = error.to_string();
                            plan.fail(&state, &target_key, reason).await;
                            report_writer.request();
                            return Err(error);
                        }
                    }
                }
                DependencyExchangeOutcome::NoResponse => {
                    plan.commit(&state).await;
                    report_writer.request();
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
            report_writer.request();
            return Err(error);
        }
        plan.commit(&state).await;
        report_writer.request();
    }
    Ok(())
}
