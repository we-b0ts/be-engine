//! Native frame correlation publishes capture facts through host-owned permits.
use super::*;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use traffic_model::{recording::ProtocolRef, trace::OutputKind};
use traffic_protocol::{
    capture::{CaptureEvidence, CaptureFacts, CaptureSnapshot},
    connection::{CaptureHost, ConnectionIo, NativeFuture, Operation},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub(super) struct PeerAddress {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Call {
    pub channel: Uuid,
    pub ordinal: u64,
    pub peer: PeerAddress,
    pub input: Vec<u8>,
    pub reply: Vec<u8>,
    pub latency_micros: u64,
    pub wire_complete: bool,
}

impl Call {
    pub(super) fn reference(&self) -> ProtocolRef {
        ProtocolRef::new(NAME, json!({"channel":self.channel,"ordinal":self.ordinal}))
            .expect("fixture reference is an object")
    }
}

impl CaptureEvidence for Call {
    fn event_type(&self) -> &'static str {
        EVENT
    }
    fn capture_facts(&self) -> CaptureFacts {
        CaptureFacts::dependency(self.reference(), "response", self.wire_complete)
    }
}

pub(super) struct Capture(pub ConnectionInfo);
impl CaptureSession for Capture {
    fn run(
        self: Box<Self>,
        client: Box<dyn ConnectionIo>,
        upstream: Box<dyn ConnectionIo>,
        host: Arc<dyn CaptureHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let channel = Uuid::new_v4();
            let mut ordinal = 0;
            let mut client =
                traffic_protocol::io::BufferedReader::new(client, self.0.max_frame_bytes);
            let mut upstream =
                traffic_protocol::io::BufferedReader::new(upstream, self.0.max_frame_bytes);
            while let Some(input) =
                traffic_protocol::io::read_frame(&mut client, &mut Decoder).await?
            {
                ordinal += 1;
                let reference =
                    ProtocolRef::new(NAME, json!({"channel":channel,"ordinal":ordinal}))?;
                let Some(permit) = host.begin(reference, Operation::Read).await? else {
                    client
                        .inner
                        .write_all(&encode(&json!({"error":"access_denied"}))?)
                        .await?;
                    client.inner.flush().await?;
                    continue;
                };
                let started = std::time::Instant::now();
                upstream
                    .inner
                    .write_all(&encode_payload(input.clone())?)
                    .await?;
                upstream.inner.flush().await?;
                let reply = traffic_protocol::io::read_frame(&mut upstream, &mut Decoder)
                    .await?
                    .context("fixture upstream ended before its response")?;
                let receipt = permit.prepare_output(OutputKind::End)?;
                client
                    .inner
                    .write_all(&encode_payload(reply.clone())?)
                    .await?;
                client.inner.flush().await?;
                receipt.commit();
                let event = Call {
                    channel,
                    ordinal,
                    peer: PeerAddress {
                        address: self.0.endpoint.host.clone(),
                        port: self.0.endpoint.port,
                    },
                    input: input.to_vec(),
                    reply: reply.to_vec(),
                    latency_micros: u64::try_from(started.elapsed().as_micros())?,
                    wire_complete: true,
                };
                permit.complete(CaptureSnapshot::capture(&event)?).await?;
            }
            Ok(())
        })
    }
}
