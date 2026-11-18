//! Native RESP recording through shared capture permits and output receipts.
use super::*;
use anyhow::Context;
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use traffic_model::{capture::capture_body, trace::OutputKind};
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{CaptureHost, ConnectionIo, NativeFuture},
};
use uuid::Uuid;

pub(super) struct Capture(pub ConnectionInfo);

impl CaptureSession for Capture {
    fn run(
        self: Box<Self>,
        client: Box<dyn ConnectionIo>,
        upstream: Box<dyn ConnectionIo>,
        host: Arc<dyn CaptureHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let connection_id = Uuid::new_v4();
            let mut client = crate::BufferedReader::new(client, self.0.max_frame_bytes);
            let mut upstream = crate::BufferedReader::new(upstream, self.0.max_frame_bytes);
            let mut session = crate::capture::CaptureSessionState {
                resp_version: 2,
                database: 0,
                username: None,
                subscriptions: Default::default(),
            };
            let mut sequence = 0;
            while let Some(frame) = crate::read_frame(&mut client).await? {
                let command = crate::redis_command(&frame.raw)?;
                sequence += 1;
                let reference = ProtocolRef::connection("redis", connection_id, sequence);
                let Some(permit) = host
                    .begin(reference, crate::access::classify_command(&command))
                    .await?
                else {
                    client
                        .inner
                        .write_all(b"-ERR recording access denied\r\n")
                        .await?;
                    client.inner.flush().await?;
                    continue;
                };
                let request_started_at = Utc::now();
                let started = std::time::Instant::now();
                let (arguments, session_setup, safe, warnings) =
                    crate::capture::sanitize_and_classify(&command);
                upstream.inner.write_all(&frame.raw).await?;
                upstream.inner.flush().await?;
                let response = crate::read_frame(&mut upstream)
                    .await?
                    .context("Redis upstream ended before a complete response")?;
                let receipt = permit.prepare_output(OutputKind::End)?;
                client.inner.write_all(&response.raw).await?;
                client.inner.flush().await?;
                receipt.commit();
                let supported = session.resp_version == 2
                    && !crate::is_pubsub_command(&command.name)
                    && !crate::builtins::redis_is_unsupported(&command);
                let event = crate::events::RedisExchangeEvent {
                    id: Uuid::new_v4(),
                    connection_id,
                    sequence,
                    timestamp: Utc::now(),
                    request_started_at,
                    client_addr: self.0.client_addr.clone(),
                    target_host: self.0.endpoint.host.clone(),
                    target_port: self.0.endpoint.port,
                    target_addr: traffic_protocol::observation::format_endpoint(
                        &self.0.endpoint.host,
                        self.0.endpoint.port,
                    ),
                    upstream_addr: self.0.upstream_addr.clone().unwrap_or_default(),
                    resp_version: session.resp_version,
                    database: session.database,
                    username: session.username.clone(),
                    command: command.name.clone(),
                    args: arguments
                        .iter()
                        .map(|value| capture_body(value, self.0.max_frame_bytes))
                        .collect(),
                    response_kind: response.kind.as_str().into(),
                    response: capture_body(&response.raw, self.0.max_frame_bytes),
                    rpc_callback_capture: None,
                    cache_snapshot_rule: None,
                    cache_snapshot_hit: false,
                    session_setup,
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: started.elapsed().as_millis(),
                    replay_safe: safe && supported,
                    parse_warnings: warnings,
                };
                permit.complete(CaptureSnapshot::capture(&event)?).await?;
                if response.kind != crate::RedisFrameKind::Error {
                    session.apply_successful_setup(&command, &response.raw, sequence);
                }
                if !supported {
                    upstream.inner.write_all(&client.buffer.split()).await?;
                    client.inner.write_all(&upstream.buffer.split()).await?;
                    tokio::io::copy_bidirectional(&mut client.inner, &mut upstream.inner).await?;
                    return Ok(());
                }
                if command.name == "QUIT" {
                    return Ok(());
                }
            }
            Ok(())
        })
    }
}
