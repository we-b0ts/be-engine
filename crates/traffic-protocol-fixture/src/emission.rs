//! Independent server messages validate the shared contract without Redis.
use super::*;
use serde::{Deserialize, Serialize};
use traffic_model::recording::ProtocolRef;
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts};
use uuid::Uuid;

pub const EVENT: &str = "fixture_emission";

#[derive(Serialize, Deserialize)]
pub(super) struct Emission {
    pub channel: Uuid,
    pub ordinal: u64,
    pub anchor: u64,
    pub peer: capture::PeerAddress,
    pub body: Vec<u8>,
    pub offset_micros: u64,
}

impl Emission {
    pub fn reference(&self) -> ProtocolRef {
        ProtocolRef::new(NAME, json!({"channel":self.channel,"message":self.ordinal})).unwrap()
    }
    pub fn project(self) -> Result<RecordedExchange> {
        Ok(RecordedExchange {
            reference: self.reference(),
            endpoint: Endpoint {
                host: self.peer.address,
                port: self.peer.port,
            },
            lane: None,
            response_delay: Default::default(),
            input: traffic_protocol::connection::RecordedInput::Emission {
                after: ProtocolRef::new(
                    NAME,
                    json!({"channel":self.channel,"ordinal":self.anchor}),
                )?,
                offset: std::time::Duration::from_micros(self.offset_micros),
            },
            response: Arc::new(Message(self.body.into())),
        })
    }
}
impl CaptureEvidence for Emission {
    fn event_type(&self) -> &'static str {
        EVENT
    }
    fn capture_facts(&self) -> CaptureFacts {
        CaptureFacts::dependency(self.reference(), "response", true)
    }
}
