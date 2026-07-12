mod broker;
mod matcher;
pub(super) mod report;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::kafka::{decode_request, read_frame, replay_supports, write_frame};

pub(super) use matcher::{
    KafkaReplayState, RecordedKafkaConnection, RecordedKafkaDelivery, RecordedKafkaProduce,
};
pub(super) use report::KafkaProtocolReport;

use super::{ReplayState, ReplayTarget, TargetKey, write_report_snapshot};

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
) -> Result<()> {
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    state.lock().await.kafka.events.connections += 1;
    write_report_snapshot(state.clone(), report_path.clone()).await?;

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
            write_report_snapshot(state.clone(), report_path.clone()).await?;
            anyhow::bail!(reason);
        }
        let response = broker::response_for(&decoded, &target_key, state.clone())
            .await
            .with_context(|| {
                format!(
                    "failed to handle Kafka {:?} version {}",
                    decoded.api_key, decoded.header.request_api_version
                )
            })?;
        let payload = crate::kafka::encode_response(
            decoded.header.correlation_id,
            decoded.api_key,
            decoded.header.request_api_version,
            &response,
        )?;
        write_frame(&mut stream, &payload).await?;
        write_report_snapshot(state.clone(), report_path.clone()).await?;
    }
    Ok(())
}
