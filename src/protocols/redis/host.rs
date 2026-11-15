//! Application recording policy, immutable ownership and storage for native Redis capture.
use crate::protocols::recording::events::{ProxyErrorEvent, RecorderEvent};
use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use traffic_model::{TerminationSide, recording::ProtocolRef, trace::OutputKind};
use traffic_protocol::connection::{CaptureOutput, NativeFuture};
use traffic_protocol_redis::capture::connection::{
    CaptureDecision, CaptureHost, CaptureRequest, CapturedPush, CapturedRequest, PushRequest,
};
use traffic_protocol_redis::events::{RedisConnectionEvent, RedisExchangeEvent};
use uuid::Uuid;

use super::{ConnectionContext, pubsub, rpc};
use crate::{
    AppState,
    access_policy::AccessDecision,
    active_case::DependencyTargets,
    recorder::{
        cache_snapshot::CacheSnapshotReservation,
        capture_health::{ConnectionCaptureHealth, RawTrafficDirection},
    },
};

pub(super) struct Host {
    state: AppState,
    context: ConnectionContext,
    connection_id: Uuid,
    health: ConnectionCaptureHealth,
}

impl Host {
    pub(super) fn new(state: AppState, context: ConnectionContext, connection_id: Uuid) -> Self {
        let health = ConnectionCaptureHealth::new(
            connection_id,
            "redis",
            context.client_addr.clone(),
            context.target_addr.clone(),
        );
        Self {
            state,
            context,
            connection_id,
            health,
        }
    }
}

struct RequestCapture {
    state: AppState,
    targets: DependencyTargets,
    rpc_callback_capture: Option<String>,
    snapshot_rule: Option<String>,
    snapshot_key: Option<Vec<u8>>,
    snapshot_hit: bool,
}

impl CapturedRequest for RequestCapture {
    fn cached_response(&mut self) -> NativeFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let Some(key) = self.snapshot_key.take() else {
                return Ok(None);
            };
            let response = match self.state.reserve_cache_snapshot(key.clone()).await? {
                CacheSnapshotReservation::Leader => {
                    self.snapshot_key = Some(key);
                    return Ok(None);
                }
                CacheSnapshotReservation::Hit(response) => response,
                CacheSnapshotReservation::Wait(waiter) => waiter.response().await?,
            };
            self.snapshot_hit = true;
            Ok(Some(response))
        })
    }

    fn observe_response(&mut self, response: Bytes, reusable: bool) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            if let Some(key) = self.snapshot_key.take() {
                self.state
                    .complete_cache_snapshot(&key, response, reusable)
                    .await?;
            }
            Ok(())
        })
    }

    fn abort_response(&mut self) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            if let Some(key) = self.snapshot_key.take() {
                self.state
                    .abort_cache_snapshot(&key, "Redis snapshot fill ended before a response")
                    .await;
            }
            Ok(())
        })
    }

    fn prepare_output(&self, output: OutputKind) -> Option<Box<dyn CaptureOutput>> {
        self.targets.prepare_output(output).map(|receipt| {
            Box::new(crate::recorder::native::Output(receipt)) as Box<dyn CaptureOutput>
        })
    }

    fn complete(
        self: Box<Self>,
        mut event: RedisExchangeEvent,
        confirmed_subscription: bool,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            self.targets.record_output(event.outcome);
            event.rpc_callback_capture = self.rpc_callback_capture;
            event.cache_snapshot_rule = self.snapshot_rule;
            event.cache_snapshot_hit = self.snapshot_hit;
            let event = RecorderEvent::RedisExchange(event);
            if confirmed_subscription {
                pubsub::record_subscription(&self.state, event, self.targets).await?;
            } else {
                self.state.record_event_for_targets(event, self.targets);
            }
            Ok(())
        })
    }
}

impl CaptureHost for Host {
    fn begin_request<'a>(
        &'a self,
        request: CaptureRequest<'a>,
    ) -> NativeFuture<'a, CaptureDecision> {
        Box::pin(async move {
            let command = request.command;
            let operation = traffic_protocol_redis::access::classify_command(command);
            if self.state.access_decision(operation) == AccessDecision::Reject {
                self.state
                    .record_readonly_rejection(
                        "redis",
                        operation,
                        command.name.clone(),
                        self.context.client_addr.clone(),
                        Some(self.context.target_addr.clone()),
                        "Redis command is classified as a write operation",
                    )
                    .await;
                return Ok(CaptureDecision::Rejected);
            }
            let snapshot_rule = self
                .state
                .matching_redis_snapshot_rule(
                    self.context.target_port,
                    &command.name,
                    &command.args,
                )
                .map(ToOwned::to_owned);
            if snapshot_rule.is_some() {
                self.state.record_redis_cache_request();
            }
            let snapshot_key = snapshot_rule.as_ref().map(|rule| {
                request
                    .session
                    .snapshot_key(rule, &command.name, &command.args)
            });
            let targets = self.state.capture_dependency_request(
                crate::protocols::recording::request::DependencyRequest::Redis {
                    target_port: self.context.target_port,
                    command: &command.name,
                    args: &command.args,
                },
            );
            targets.bind_protocol(ProtocolRef::connection(
                "redis",
                request.connection_id,
                request.sequence,
            ));
            if let Err(error) = rpc::observe(
                &self.state,
                &self.context,
                &targets,
                command,
                request.connection_id,
                request.sequence,
            ) {
                self.record_error(error.to_string());
            }
            Ok(CaptureDecision::Admitted(Box::new(RequestCapture {
                state: self.state.clone(),
                targets,
                rpc_callback_capture: crate::redis::socketio_rpc::request(
                    &command.name,
                    &command.args,
                )
                .ok()
                .flatten()
                .map(|_| "bounded_window".to_owned()),
                snapshot_rule,
                snapshot_key,
                snapshot_hit: false,
            })))
        })
    }

    fn capture_push(&self, request: PushRequest<'_>) -> Result<Box<dyn CapturedPush>> {
        Ok(Box::new(pubsub::capture(
            &self.state,
            &self.context,
            request.session,
            request.connection_id,
            request.push,
            request.bytes,
            request.subscription_sequence,
            request.elapsed_ms,
        )?))
    }

    fn observe_connection(&self, event: RedisConnectionEvent) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            self.state
                .record_event(RecorderEvent::RedisConnection(event));
            Ok(())
        })
    }

    fn record_error(&self, error: String) {
        self.state
            .record_event(RecorderEvent::ProxyError(ProxyErrorEvent {
                id: Uuid::new_v4(),
                connection_id: Some(self.connection_id),
                timestamp: Utc::now(),
                protocol: "redis".into(),
                client_addr: self.context.client_addr.clone(),
                target: Some(self.context.target_addr.clone()),
                error,
            }));
    }

    fn degrade(&self, reason: String) {
        self.health.activate(&self.state, reason);
    }
    fn is_degraded(&self) -> bool {
        self.health.is_degraded()
    }
    fn degradation_reason(&self) -> Option<String> {
        self.health.reason()
    }
    fn raw_activity(&self, side: TerminationSide) {
        let direction = if side == TerminationSide::Client {
            RawTrafficDirection::ClientToServer
        } else {
            RawTrafficDirection::ServerToClient
        };
        self.health.note_activity(&self.state, direction);
    }
}
