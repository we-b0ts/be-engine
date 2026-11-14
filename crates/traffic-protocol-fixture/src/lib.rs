//! Independent native protocol used to verify the host extension contract.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use bytes::{Bytes, BytesMut};
use serde_json::{Value, json};
use traffic_protocol::{
    DependencyProvider, FrameDecoder, Peer, Probe, Recognition, Session,
    connection::{
        CaptureSession, ConnectionInfo, Endpoint, NativeProtocol, RecordedExchange, ServerSession,
    },
    evidence::EvidenceAdapter,
    message::{MessageEncoder, ProjectedMessage, ProjectedValue, ProtocolMessage},
    observation::TrafficInteraction,
};

mod capture;
mod server;

pub const NAME: &str = "fixture-rpc";
pub const EVENT: &str = "fixture_message";
const MAGIC: &[u8] = b"\xe7TRP";

pub struct Provider;
impl DependencyProvider for Provider {
    fn name(&self) -> &'static str {
        NAME
    }
    fn recognize(&self, probe: Probe<'_>) -> Recognition {
        if probe.peer != Peer::Client {
            return Recognition::Reject;
        }
        if MAGIC.starts_with(probe.bytes) {
            return Recognition::NeedMore;
        }
        if probe.bytes.starts_with(MAGIC) {
            Recognition::Match
        } else {
            Recognition::Reject
        }
    }
    fn create_session(&self) -> Result<Session> {
        Ok(Session::new(Decoder))
    }
    fn evidence(&self) -> Option<Arc<dyn EvidenceAdapter>> {
        Some(Arc::new(Evidence))
    }
    fn native_protocol(&self) -> Option<Arc<dyn NativeProtocol>> {
        Some(Arc::new(Native))
    }
}

pub struct Decoder;
impl FrameDecoder for Decoder {
    type Frame = Bytes;
    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<Bytes>> {
        if input.len() < 8 {
            return Ok(None);
        }
        ensure!(
            input.starts_with(MAGIC),
            "fixture native frame signature changed"
        );
        let length = u32::from_be_bytes(input[4..8].try_into()?) as usize;
        let end = length
            .checked_add(8)
            .context("fixture frame size overflow")?;
        if input.len() < end {
            return Ok(None);
        }
        Ok(Some(input.split_to(end).freeze().slice(8..)))
    }
    fn encode(&self, frame: &Bytes, output: &mut BytesMut) -> Result<()> {
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&u32::try_from(frame.len())?.to_be_bytes());
        output.extend_from_slice(frame);
        Ok(())
    }
    fn read_size(&self, input: &[u8]) -> Result<usize> {
        if input.len() < 8 {
            return Ok(8 - input.len());
        }
        let length = u32::from_be_bytes(input[4..8].try_into()?) as usize;
        length
            .checked_add(8)
            .and_then(|end| end.checked_sub(input.len()))
            .filter(|remaining| *remaining > 0)
            .context("fixture decoder made no progress")
    }
}

pub fn encode(value: &Value) -> Result<Bytes> {
    encode_payload(Bytes::from(serde_json::to_vec(value)?))
}

fn encode_payload(payload: Bytes) -> Result<Bytes> {
    let mut bytes = BytesMut::new();
    Decoder.encode(&payload, &mut bytes)?;
    Ok(bytes.freeze())
}

pub async fn read<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Value> {
    let bytes = traffic_protocol::io::read_one(reader, &mut Decoder, 1024 * 1024)
        .await?
        .context("fixture connection ended before a native frame")?;
    Ok(serde_json::from_slice(&bytes)?)
}

struct Message(Bytes);
impl ProtocolMessage for Message {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"native_frame":"fixture_document"}),
            values: BTreeMap::from([("document".into(), ProjectedValue::bytes(self.0.clone()))]),
        })
    }
    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        ensure!(
            *selector == json!({"kind":"document"}),
            "fixture value selector is invalid"
        );
        Ok(vec!["document".into()])
    }
    fn evidence(&self, query: &Value) -> Result<Value> {
        let document: Value = serde_json::from_slice(&self.0)?;
        if let Some(pointer) = query["pointer"].as_str() {
            return Ok(match document.pointer(pointer) {
                Some(value) => json!({"wire_format":"fixture","presence":"present","value":value}),
                None => json!({"wire_format":"fixture","presence":"missing"}),
            });
        }
        Ok(json!({"wire_format":"fixture","document":document}))
    }
}
impl MessageEncoder for Message {
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        encode_payload(
            values
                .get("document")
                .context("fixture response document is absent")?
                .clone(),
        )
    }
}

struct Native;
impl NativeProtocol for Native {
    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>> {
        if event["event_type"] != EVENT {
            return Ok(None);
        }
        let call: capture::Call = serde_json::from_value(event.clone())?;
        ensure!(call.wire_complete, "fixture native capture is incomplete");
        Ok(Some(RecordedExchange {
            reference: call.reference(),
            endpoint: Endpoint {
                host: call.peer.address,
                port: call.peer.port,
            },
            lane: Some(call.channel.to_string()),
            response_delay: std::time::Duration::from_micros(call.latency_micros),
            request: Arc::new(Message(Bytes::from(call.input))),
            response: Arc::new(Message(Bytes::from(call.reply))),
        }))
    }
    fn recorded_endpoint(&self, event: &Value) -> Result<Option<Endpoint>> {
        if event["event_type"] != EVENT {
            return Ok(None);
        }
        let peer: capture::PeerAddress = serde_json::from_value(event["peer"].clone())?;
        Ok(Some(Endpoint {
            host: peer.address,
            port: peer.port,
        }))
    }
    fn server_session(&self, info: ConnectionInfo) -> Result<Box<dyn ServerSession>> {
        Ok(Box::new(server::Server::new(info.max_frame_bytes)))
    }
    fn capture_session(&self, info: ConnectionInfo) -> Result<Box<dyn CaptureSession>> {
        Ok(Box::new(capture::Capture(info)))
    }
}

struct Evidence;
impl EvidenceAdapter for Evidence {
    fn schema(&self) -> &'static str {
        "fixture-rpc/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &[EVENT]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        serde_json::from_value::<capture::Call>(event.clone()).is_ok_and(|call| call.wire_complete)
    }
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let peer: capture::PeerAddress = serde_json::from_value(event["peer"].clone()).ok()?;
        Some(TrafficInteraction {
            protocol: NAME.into(),
            endpoint: Some(traffic_protocol::observation::format_endpoint(
                &peer.address,
                peer.port,
            )),
            operation: "fixture-call".into(),
        })
    }
}
