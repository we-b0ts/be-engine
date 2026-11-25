//! RESP recording correlates replies and captures confirmed pushes separately.
use std::time::Instant;

use anyhow::Context;
use chrono::{DateTime, Utc};
use tokio::io::AsyncWriteExt;
use traffic_model::{capture::capture_body, trace::OutputKind};
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{BuiltinMaintenance, CaptureExchange, CaptureHost, ConnectionIo, NativeFuture},
};
use uuid::Uuid;

use super::{notification::CapturedPush, subscription::Subscriptions, *};
use crate::{
    RedisCommand, RedisFrame, RedisFrameKind, capture::CaptureSessionState, pubsub::frame,
};

pub(super) struct Capture(pub ConnectionInfo);

struct Pending {
    sequence: u64,
    command: RedisCommand,
    capture: PendingCapture,
    started: Instant,
    wall: DateTime<Utc>,
}

enum PendingCapture {
    Exchange(Box<dyn CaptureExchange>),
    Maintenance(MaintenanceCommand, BuiltinMaintenance),
}

#[derive(Clone, Copy)]
enum MaintenanceCommand {
    Ping,
    SetInfo,
    Authenticate,
    Select,
}

impl MaintenanceCommand {
    fn classify(command: &RedisCommand) -> Option<Self> {
        match command.name.as_str() {
            "PING" if command.args.is_empty() => Some(Self::Ping),
            "CLIENT" if crate::is_client_library_info(&command.name, &command.args) => {
                Some(Self::SetInfo)
            }
            "AUTH" => Some(Self::Authenticate),
            "SELECT" => Some(Self::Select),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Ping => "PING",
            Self::SetInfo => "CLIENT SETINFO",
            Self::Authenticate => "AUTH",
            Self::Select => "SELECT",
        }
    }

    fn canonical_reply(self, command: &RedisCommand, frame: &RedisFrame) -> bool {
        let raw = frame.raw.as_ref();
        match self {
            Self::Ping => raw == b"+PONG\r\n",
            Self::SetInfo => {
                // Redis clients can ignore rejected advisory library metadata.
                raw == b"+OK\r\n" || frame.kind == RedisFrameKind::Error
            }
            Self::Authenticate => {
                raw == b"+OK\r\n"
                    && matches!(command.args.as_slice(), [_] | [_, _])
                    && (command.args.len() == 1
                        || std::str::from_utf8(&command.args[0])
                            .is_ok_and(|username| !username.is_empty()))
            }
            Self::Select => {
                raw == b"+OK\r\n"
                    && matches!(command.args.as_slice(), [database]
                        if std::str::from_utf8(database)
                            .is_ok_and(|database| database.parse::<i64>().is_ok_and(|db| db >= 0)))
            }
        }
    }
}

impl CaptureSession for Capture {
    fn run(
        self: Box<Self>,
        client: Box<dyn ConnectionIo>,
        upstream: Box<dyn ConnectionIo>,
        host: Arc<dyn CaptureHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let connection_id = host.connection_id();
            let mut client = crate::BufferedReader::new(client, usize::MAX);
            let mut upstream = crate::BufferedReader::new(upstream, usize::MAX);
            let mut session = CaptureSessionState {
                resp_version: 2,
                database: 0,
                username: None,
                subscriptions: Default::default(),
            };
            let mut subscriptions = Subscriptions::<(u64, Option<u64>, Instant)>::default();
            let mut sequence = 0_u64;
            let mut pending = None;
            loop {
                tokio::select! {
                    frame = crate::read_frame(&mut client), if pending.is_none() => {
                        let Some(frame) = frame? else { break };
                        let command = crate::redis_command(&frame.raw)?;
                        sequence = sequence.checked_add(1).context("Redis capture sequence overflow")?;
                        let reference = ProtocolRef::connection("redis", connection_id, sequence);
                        let operation = crate::access::classify_command(&command);
                        let maintenance = (session.resp_version == 2 && !subscriptions.active())
                            .then(|| MaintenanceCommand::classify(&command))
                            .flatten()
                            .and_then(|kind| BuiltinMaintenance::begin(&host, operation, kind.name()).map(|guard| (kind, guard)));
                        let capture = if let Some((kind, guard)) = maintenance {
                            PendingCapture::Maintenance(kind, guard)
                        } else {
                            let Some(permit) = host.begin(reference, operation).await? else {
                                client.inner.write_all(b"-ERR recording access denied\r\n").await?;
                                client.inner.flush().await?;
                                continue;
                            };
                            PendingCapture::Exchange(permit)
                        };
                        pending = Some(Pending {sequence, command, capture, started: Instant::now(), wall: Utc::now()});
                        upstream.inner.write_all(&frame.raw).await?;
                        upstream.inner.flush().await?;
                    }
                    frame = crate::read_frame(&mut upstream), if pending.is_some() || subscriptions.active() => {
                        let Some(frame) = frame? else {
                            ensure!(pending.is_none(), "Redis upstream ended before a complete response");
                            break;
                        };
                        if subscriptions.active() && let Some(push) = frame::decode(&frame.raw)? {
                            let anchor = subscriptions.get(push.kind, &push.subject)
                                .context("Redis notification has no confirmed subscription")?.anchor;
                            self.capture_push(&*host, &mut *client.inner, (&frame, push.kind), &session, connection_id, anchor).await?;
                            continue;
                        }

                        let request = pending.take().context("Redis response has no admitted command")?;
                        let permit = match request.capture {
                            PendingCapture::Exchange(permit) => permit,
                            PendingCapture::Maintenance(kind, guard) => {
                                client.inner.write_all(&frame.raw).await?;
                                client.inner.flush().await?;
                                let canonical = kind.canonical_reply(&request.command, &frame);
                                if canonical {
                                    session.apply_successful_setup(&request.command, &frame.raw, request.sequence);
                                }
                                guard.finish(canonical);
                                continue;
                            }
                        };
                        let supported = session.resp_version == 2 && !crate::builtins::redis_is_unsupported(&request.command);
                        let (arguments, session_setup, safe, mut warnings) =
                            crate::capture::sanitize_and_classify(&request.command);
                        let confirmation = if supported {
                            match subscriptions.confirmation(&request.command, &frame.raw, false) {
                                Ok(confirmation) => confirmation,
                                Err(error) => {
                                    warnings.push(error.to_string());
                                    None
                                }
                            }
                        } else {
                            None
                        };
                        let replay_safe = safe && supported && warnings.is_empty();
                        let receipt = permit.prepare_output(OutputKind::End)?;
                        client.inner.write_all(&frame.raw).await?;
                        client.inner.flush().await?;
                        let delivered = Instant::now();
                        let timestamp = Utc::now();
                        receipt.commit();
                        let event = crate::events::RedisExchangeEvent {
                            id: Uuid::new_v4(),
                            connection_id,
                            sequence: request.sequence,
                            timestamp,
                            request_started_at: request.wall,
                            client_addr: self.0.client_addr.clone(),
                            target_host: self.0.endpoint.host.clone(),
                            target_port: self.0.endpoint.port,
                            target_addr: traffic_protocol::observation::format_endpoint(&self.0.endpoint.host, self.0.endpoint.port),
                            upstream_addr: self.0.upstream_addr.clone().unwrap_or_default(),
                            resp_version: session.resp_version,
                            database: session.database,
                            username: session.username.clone(),
                            command: request.command.name.clone(),
                            args: arguments.iter().map(|value| capture_body(value, value.len())).collect(),
                            response_kind: frame.kind.as_str().into(),
                            response: capture_body(&frame.raw, frame.raw.len()),
                            rpc_callback_capture: None,
                            cache_snapshot_rule: None,
                            cache_snapshot_hit: false,
                            session_setup,
                            outcome: DependencyExchangeOutcome::Response,
                            duration_ms: delivered.duration_since(request.started).as_millis(),
                            replay_safe,
                            parse_warnings: warnings,
                        };
                        let dependency_id = permit.dependency_id();
                        permit.complete(CaptureSnapshot::capture(&event)?).await?;
                        if !supported || (crate::is_pubsub_command(&request.command.name) && !replay_safe) {
                            upstream.inner.write_all(&client.buffer.split()).await?;
                            client.inner.write_all(&upstream.buffer.split()).await?;
                            tokio::io::copy_bidirectional(&mut client.inner, &mut upstream.inner).await?;
                            break;
                        }
                        if let Some(confirmation) = confirmation {
                            subscriptions.apply(confirmation, Some((request.sequence, dependency_id, delivered)))?;
                        } else if frame.kind != RedisFrameKind::Error {
                            if request.command.name == "RESET" {
                                subscriptions.clear();
                                session.resp_version = 2;
                                session.database = 0;
                                session.username = None;
                            } else {
                                session.apply_successful_setup(&request.command, &frame.raw, request.sequence);
                            }
                        }
                        if request.command.name == "QUIT" {
                            break;
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

impl Capture {
    async fn capture_push(
        &self,
        host: &dyn CaptureHost,
        client: &mut dyn ConnectionIo,
        (frame, kind): (&RedisFrame, crate::RedisSubscriptionKind),
        session: &CaptureSessionState,
        connection_id: Uuid,
        (subscription_sequence, after_id, confirmed): (u64, Option<u64>, Instant),
    ) -> Result<()> {
        let mut push = CapturedPush {
            id: Uuid::new_v4(),
            notification_kind: super::notification::kind_name(kind),
            event: crate::events::RedisPubSubPushEvent {
                timestamp: Utc::now(),
                target_host: self.0.endpoint.host.clone(),
                target_port: self.0.endpoint.port,
                database: session.database,
                username: session.username.clone(),
                connection_id,
                subscription_sequence,
                rpc_request: None,
                response: capture_body(&frame.raw, frame.raw.len()),
                duration_ms: u64::try_from(confirmed.elapsed().as_millis())?,
                replay_safe: session.resp_version == 2,
            },
        };
        let event = CaptureSnapshot::capture(&push)?.with_source_predecessor(after_id);
        let permit = host
            .begin_message(&event)
            .await?
            .context("Redis notification capture admission is closed")?;
        let (receipt, late_capture) = if permit.supports_staged_output() {
            (permit.stage_output(event, OutputKind::End).await?, None)
        } else {
            (permit.prepare_output(OutputKind::End)?, Some(permit))
        };
        client.write_all(&frame.raw).await?;
        client.flush().await?;
        receipt.commit();
        if let Some(permit) = late_capture {
            push.event.timestamp = Utc::now();
            push.event.duration_ms = u64::try_from(confirmed.elapsed().as_millis())?;
            permit
                .complete(CaptureSnapshot::capture(&push)?.with_source_predecessor(after_id))
                .await?;
        }
        Ok(())
    }
}
