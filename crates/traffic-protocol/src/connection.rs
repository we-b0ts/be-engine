//! Native connection semantics exposed to the recording and Replay hosts.
use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::Result;
use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use traffic_model::recording::ProtocolRef;

use crate::{
    capture::CaptureSnapshot,
    message::{MessageEncoder, ProtocolMessage},
};

pub type NativeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait ConnectionIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ConnectionIo for T {}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

pub fn endpoint_from_addr(value: &str) -> Option<Endpoint> {
    use crate::observation::normalize_host;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<std::net::SocketAddr>() {
        return Some(Endpoint {
            host: normalize_host(&addr.ip().to_string()),
            port: addr.port(),
        });
    }
    let (host, port) = value.rsplit_once(':')?;
    Some(Endpoint {
        host: normalize_host(host.trim_start_matches('[').trim_end_matches(']')),
        port: port.parse().ok()?,
    })
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub endpoint: Endpoint,
    pub client_addr: Option<String>,
    pub upstream_addr: Option<String>,
    pub max_frame_bytes: usize,
}

/// Immutable protocol facts. Source ownership, clocks, policy bindings and
/// finite consumption are assigned by the host separately.
pub struct RecordedExchange {
    pub reference: ProtocolRef,
    pub endpoint: Endpoint,
    pub lane: Option<String>,
    pub response_delay: std::time::Duration,
    pub request: Arc<dyn ProtocolMessage>,
    pub response: Arc<dyn MessageEncoder>,
}

/// Native framing, handshakes, TLS upgrades and session-local controls own their
/// transport. Business requests enter the host's shared execution flow.
pub trait ServerSession: Send {
    fn run(
        self: Box<Self>,
        io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()>;
}

pub trait RequestHost: Send + Sync {
    fn begin_input(&self) -> NativeFuture<'_, Box<dyn RequestInput>> {
        Box::pin(async { Ok(Box::new(()) as Box<dyn RequestInput>) })
    }
    fn accept_tls(
        &self,
        _io: Box<dyn ConnectionIo>,
        _alpn: Vec<Vec<u8>>,
    ) -> NativeFuture<'_, Box<dyn ConnectionIo>> {
        Box::pin(async { anyhow::bail!("server TLS is unavailable") })
    }
    fn execute(
        &self,
        request: Arc<dyn ProtocolMessage>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>>;
}

/// A live request retains its original I/O ownership until its parser or delivery ends.
pub trait RequestInput: Send {}
impl RequestInput for () {}

pub trait ResponseFramer: Send {
    fn frame(&mut self, response: Bytes) -> Result<Bytes> {
        Ok(response)
    }
}

/// The host retains response bytes, claims and delivery receipts. Native framing
/// may adjust session metadata before the host performs the actual write/flush.
pub trait ResponseDelivery: Send {
    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn ConnectionIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Read,
    Write,
    Session,
    Unknown,
}

impl Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Session => "session",
            Self::Unknown => "unknown",
        }
    }
}

/// An admitted capture retains its original ownership until completion. Dropping
/// an unfinished exchange leaves an incomplete obligation with the host.
pub trait CaptureExchange: Send {
    fn prepare_output(
        &self,
        output: traffic_model::trace::OutputKind,
    ) -> Result<Box<dyn CaptureOutput>>;
    fn complete(self: Box<Self>, event: CaptureSnapshot) -> NativeFuture<'static, ()>;
}

pub trait CaptureOutput: Send {
    fn commit(self: Box<Self>);
}

pub trait CaptureHost: Send + Sync {
    fn accept_tls(
        &self,
        _io: Box<dyn ConnectionIo>,
        _alpn: Vec<Vec<u8>>,
    ) -> NativeFuture<'_, Box<dyn ConnectionIo>> {
        Box::pin(async { anyhow::bail!("recording TLS is unavailable") })
    }
    fn begin(
        &self,
        reference: ProtocolRef,
        operation: Operation,
    ) -> NativeFuture<'_, Option<Box<dyn CaptureExchange>>>;

    fn observe(&self, event: CaptureSnapshot) -> NativeFuture<'_, ()>;
}

pub trait TlsServer: std::fmt::Debug + Send + Sync {
    fn accept(
        &self,
        io: Box<dyn ConnectionIo>,
        host: String,
        alpn: Vec<Vec<u8>>,
    ) -> NativeFuture<'_, Box<dyn ConnectionIo>>;
}

/// Protocol-owned framing, correlation and session state. The host owns access
/// admission, capture lifetime, attribution, persistence and cancellation.
pub trait CaptureSession: Send {
    fn run(
        self: Box<Self>,
        client: Box<dyn ConnectionIo>,
        upstream: Box<dyn ConnectionIo>,
        host: Arc<dyn CaptureHost>,
    ) -> NativeFuture<'static, ()>;
}

/// Installed with the native codec at application startup. A new protocol
/// supplies this capability without extending host enums or state layouts.
pub trait NativeProtocol: Send + Sync {
    fn report_semantics(&self) -> &'static str {
        "native-reference/v1"
    }
    fn report_summary(&self, exchange: &RecordedExchange) -> Result<Value> {
        Ok(
            serde_json::json!({"protocol_ref":exchange.reference,"target":exchange.endpoint,"lane":exchange.lane}),
        )
    }

    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>>;
    fn recorded_exchange_with_secrets(
        &self,
        event: &Value,
        _secrets: &dyn crate::evidence::EvidenceSecrets,
    ) -> Result<Option<RecordedExchange>> {
        self.recorded_exchange(event)
    }
    fn recorded_protocol(&self, _event: &Value) -> Result<Option<crate::ProtocolId>> {
        Ok(None)
    }
    fn recorded_endpoint(&self, event: &Value) -> Result<Option<Endpoint>> {
        Ok(self
            .recorded_exchange(event)?
            .map(|exchange| exchange.endpoint))
    }
    fn server_session(&self, info: ConnectionInfo) -> Result<Box<dyn ServerSession>>;
    fn capture_session(&self, info: ConnectionInfo) -> Result<Box<dyn CaptureSession>>;
}
