//! Native capture facts and application-owned recording capabilities.
use super::super::CaptureSessionState;
use crate::{
    RedisCommand, RedisPubSubPush, events::RedisConnectionEvent, events::RedisExchangeEvent,
};
use anyhow::Result;
use bytes::Bytes;
use traffic_model::{TerminationSide, trace::OutputKind};
use traffic_protocol::connection::{CaptureOutput, NativeFuture};
use uuid::Uuid;

pub struct CaptureRequest<'a> {
    pub connection_id: Uuid,
    pub sequence: u64,
    pub command: &'a RedisCommand,
    pub session: &'a CaptureSessionState,
}

pub enum CaptureDecision {
    Admitted(Box<dyn CapturedRequest>),
    Rejected,
}

/// An admitted request retains its original recording ownership. The host
/// supplies shared snapshot coordination, persistence and actual output receipts.
pub trait CapturedRequest: Send {
    fn cached_response(&mut self) -> NativeFuture<'_, Option<Bytes>>;
    fn observe_response(&mut self, response: Bytes, reusable: bool) -> NativeFuture<'_, ()>;
    fn abort_response(&mut self) -> NativeFuture<'_, ()>;
    fn prepare_output(&self, output: OutputKind) -> Option<Box<dyn CaptureOutput>>;
    fn complete(
        self: Box<Self>,
        event: RedisExchangeEvent,
        confirmed_subscription: bool,
    ) -> NativeFuture<'static, ()>;
}

pub struct PushRequest<'a> {
    pub session: &'a CaptureSessionState,
    pub connection_id: Uuid,
    pub push: &'a RedisPubSubPush,
    pub bytes: Bytes,
    pub subscription_sequence: u64,
    pub elapsed_ms: u64,
}

/// Push ownership is captured before the ordered writer can delay delivery.
pub trait CapturedPush: Send {
    fn record(self: Box<Self>) -> NativeFuture<'static, ()>;
}

pub trait CaptureHost: Send + Sync {
    fn begin_request<'a>(
        &'a self,
        request: CaptureRequest<'a>,
    ) -> NativeFuture<'a, CaptureDecision>;
    fn capture_push(&self, request: PushRequest<'_>) -> Result<Box<dyn CapturedPush>>;
    fn observe_connection(&self, event: RedisConnectionEvent) -> NativeFuture<'_, ()>;
    fn record_error(&self, error: String);
    fn degrade(&self, reason: String);
    fn is_degraded(&self) -> bool;
    fn degradation_reason(&self) -> Option<String>;
    fn raw_activity(&self, side: TerminationSide);
}
