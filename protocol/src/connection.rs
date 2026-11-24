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

pub trait OutputIo: AsyncWrite + Unpin + Send {}
impl<T: AsyncWrite + Unpin + Send + ?Sized> OutputIo for T {}

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
    pub input: RecordedInput,
    pub response: Arc<dyn MessageEncoder>,
}

/// Native input semantics. An emission is enabled only after the referenced
/// real Target interaction was successfully delivered on the same connection.
/// The emission offset is relative to that successful delivery receipt.
pub enum RecordedInput {
    Request(Arc<dyn ProtocolMessage>),
    Emission {
        after: ProtocolRef,
        offset: std::time::Duration,
    },
}
impl RecordedExchange {
    pub fn request(&self) -> Option<&dyn ProtocolMessage> {
        match &self.input {
            RecordedInput::Request(request) => Some(request.as_ref()),
            _ => None,
        }
    }
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
    fn release_session(&self) {}

    /// Report a native command rejected before request admission. The host may
    /// identify the current Source command without claiming its exchange.
    fn reject_command<'a>(
        &'a self,
        command: RejectedCommand<'a>,
        _session: RequestSession,
    ) -> NativeFuture<'a, String> {
        Box::pin(async move { Ok(command.reason(None)) })
    }

    /// Execute within a provider-owned lifetime using a receipt from this connection.
    fn execute_in_session(
        &self,
        request: Arc<dyn ProtocolMessage>,
        session: RequestSession,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            anyhow::ensure!(
                session.after.is_none(),
                "native request session is unavailable"
            );
            self.execute(request).await
        })
    }
    /// Try an expected Source control before a protocol emits a safe local reply.
    fn try_execute_session_control(
        &self,
        _request: Arc<dyn ProtocolMessage>,
        _session: RequestSession,
    ) -> NativeFuture<'_, Option<Box<dyn ResponseDelivery>>> {
        Box::pin(async { Ok(None) })
    }
    /// Authorize a provisional native start without consuming a Source event.
    fn can_defer_transaction_start<'a>(
        &'a self,
        _request: &'a dyn ProtocolMessage,
    ) -> NativeFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    /// Inspect matching Source response metadata without claiming an execution.
    fn statement_metadata<'a>(
        &'a self,
        _template: &'a dyn ProtocolMessage,
        _session: &'a RequestSession,
    ) -> NativeFuture<'a, Option<Arc<dyn MessageEncoder>>> {
        Box::pin(async { Ok(None) })
    }
    fn event_session(&self) -> bool {
        false
    }
    /// Prefer a scheduled matching request over a provider's exact local observation.
    fn try_execute_driver_observation(
        &self,
        _request: Arc<dyn ProtocolMessage>,
        _session: RequestSession,
    ) -> NativeFuture<'_, Option<Box<dyn ResponseDelivery>>> {
        Box::pin(async { anyhow::bail!("native driver observations are unavailable") })
    }
    /// Bind a stateful native session to one Source lane. A continuation must
    /// name a successful delivery retained on this physical connection.
    fn execute_bound(
        &self,
        _request: Arc<dyn ProtocolMessage>,
        _after: Option<ProtocolRef>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async { anyhow::bail!("native session binding is unavailable") })
    }
    fn forget_anchor(&self, _reference: &ProtocolRef) {}
    /// Wait for an eligible finite Source message. Native session state selects
    /// anchors; the host authenticates them against this connection's receipts.
    fn next_message(
        &self,
        _anchors: Vec<ProtocolRef>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async { anyhow::bail!("server messages are unavailable") })
    }

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

pub struct RejectedCommand<'a> {
    pub protocol_name: &'static str,
    pub received: &'a str,
    pub observation: Vec<u8>,
}

impl RejectedCommand<'_> {
    pub fn reason(&self, expected: Option<&str>) -> String {
        let Self {
            protocol_name,
            received,
            ..
        } = self;
        match expected {
            Some(expected) if expected != *received => {
                format!(
                    "{protocol_name} command mismatch: expected {expected}, received {received}"
                )
            }
            Some(expected) => {
                format!(
                    "{protocol_name} command unavailable in Replay: expected {expected}, received {received}"
                )
            }
            None => {
                format!("{protocol_name} received {received} with no matching recorded command")
            }
        }
    }
}

/// A live request retains its original I/O ownership until its parser or delivery ends.
pub trait RequestInput: Send {}
impl RequestInput for () {}

pub trait ResponseFramer: Send {
    /// Prepare session-local encoding and logical boundaries before shared delivery.
    fn prepare_output(
        &mut self,
        output: Box<dyn crate::output::OutputStream>,
    ) -> Result<Box<dyn crate::output::OutputStream>> {
        Ok(output)
    }

    fn frame(&mut self, response: Bytes) -> Result<Bytes> {
        Ok(response)
    }
}

/// The host retains response bytes, claims and delivery receipts. Native framing
/// may adjust session metadata before the host performs the actual write/flush.
pub trait ResponseDelivery: Send {
    /// Wait for Source output admission without borrowing the physical writer.
    fn ready(&mut self) -> NativeFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    /// Protocol session state can retain this receipt as an emission anchor.
    fn retain_as_anchor(&mut self) {}
    fn reference(&self) -> Option<ProtocolRef> {
        None
    }
    /// Whether the selected Source exchange continues or closes a native lifetime.
    fn session_step(&self) -> Option<&ReplaySessionStep> {
        None
    }

    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn OutputIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()>;
}

/// Source slot roles supplied by a protocol after inspecting a complete scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaySessionStep {
    Optional,
    Unverified,
    InTransaction,
    Start,
    ImplicitStart,
    Continue { after: ProtocolRef, end: bool },
    ReadOnlyEnd { after: ProtocolRef },
}

/// A protocol provider's proof for a complete, non-business Source operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverPrelude {
    MysqlSqlalchemyPymysql,
    MysqlIdleMetadataRollback,
    MysqlPostTransactionIdleRollback,
}

#[derive(Default)]
pub struct EventSessionPreparation {
    pub steps: std::collections::BTreeMap<usize, ReplaySessionStep>,
    pub driver_prelude: std::collections::BTreeMap<usize, DriverPrelude>,
}

/// A Target request's admissible start and actual preceding delivery.
#[derive(Default)]
pub struct RequestSession {
    pub can_start: bool,
    pub after: Option<ProtocolRef>,
    pub implicit_start_pending: bool,
    pub read_only_end_alternative: Option<Arc<dyn ProtocolMessage>>,
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
    fn dependency_id(&self) -> Option<u64> {
        None
    }
    fn prepare_output(
        &self,
        output: traffic_model::trace::OutputKind,
    ) -> Result<Box<dyn CaptureOutput>>;
    fn complete(self: Box<Self>, event: CaptureSnapshot) -> NativeFuture<'static, ()>;
}

pub trait CaptureOutput: Send {
    fn commit(self: Box<Self>);
}

#[derive(Clone, Default)]
pub struct CaptureTransport {
    pub termination: crate::transport::ConnectionTermination,
    pub client: Option<crate::transport::ConnectionControl>,
    pub upstream: Option<crate::transport::ConnectionControl>,
}

pub trait CaptureHost: Send + Sync {
    fn connection_id(&self) -> uuid::Uuid {
        uuid::Uuid::new_v4()
    }

    fn begin_message(
        &self,
        _event: &CaptureSnapshot,
    ) -> NativeFuture<'_, Option<Box<dyn CaptureExchange>>> {
        Box::pin(async { anyhow::bail!("server message capture is unavailable") })
    }

    fn transport(&self) -> CaptureTransport {
        CaptureTransport::default()
    }
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

    fn omit_builtin_maintenance(&self, _operation: Operation) -> bool {
        false
    }

    fn builtin_maintenance_failed(&self, _name: &'static str) {}

    fn observe(&self, event: CaptureSnapshot) -> NativeFuture<'_, ()>;
}

/// A recognized control skips recorded admission only while its protocol facts
/// can prove the locally reproducible reply. An interrupted or different
/// reply invalidates capture because its original sequence was not retained.
pub struct BuiltinMaintenance {
    host: Option<Arc<dyn CaptureHost>>,
    name: &'static str,
}

impl BuiltinMaintenance {
    pub fn begin(
        host: &Arc<dyn CaptureHost>,
        operation: Operation,
        name: &'static str,
    ) -> Option<Self> {
        host.omit_builtin_maintenance(operation).then(|| Self {
            host: Some(host.clone()),
            name,
        })
    }

    pub fn finish(mut self, canonical_reply: bool) {
        if canonical_reply {
            self.host = None;
        }
    }
}

impl Drop for BuiltinMaintenance {
    fn drop(&mut self) {
        if let Some(host) = &self.host {
            host.builtin_maintenance_failed(self.name);
        }
    }
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
    /// Only providers with cross-exchange semantics opt in. Ordinary messages
    /// continue to load independently, including large streams of server emissions.
    fn prepare_replay_scope(
        &self,
        _scope: traffic_model::attribution::DependencyScope,
        _records: &[(usize, &Value)],
    ) -> Result<std::collections::BTreeMap<usize, ReplaySessionStep>> {
        Ok(Default::default())
    }
    /// Prepare native continuity for a complete strict Source session.
    fn prepare_event_session(
        &self,
        records: &[(usize, &Value)],
    ) -> Result<EventSessionPreparation> {
        Ok(EventSessionPreparation {
            steps: self.prepare_replay_scope(
                traffic_model::attribution::DependencyScope::Startup,
                records,
            )?,
            ..Default::default()
        })
    }
    fn has_replay_scope(&self) -> bool {
        false
    }
    fn decode_evidence(
        &self,
        _event: &Value,
        _payload: &[u8],
        _side: crate::evidence::MessageSide,
    ) -> Result<crate::evidence::MessageEvidence> {
        anyhow::bail!("native evidence decoding is unavailable")
    }
    fn report_semantics(&self) -> &'static str {
        "native-reference/v1"
    }
    fn report_summary(&self, exchange: &RecordedExchange) -> Result<Value> {
        Ok(
            serde_json::json!({"protocol_ref":exchange.reference,"target":exchange.endpoint,"lane":exchange.lane}),
        )
    }

    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>>;

    /// Prepare only the routing and timing of a server emission. Metadata has
    /// no request or response body. Providers may use the ordinary eager path.
    fn recorded_emission(
        &self,
        _metadata: &Value,
        _response: Arc<dyn MessageEncoder>,
    ) -> Result<Option<RecordedExchange>> {
        Ok(None)
    }
    fn recorded_emission_structure(&self, _metadata: &Value) -> Option<Value> {
        None
    }
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
