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
            let (client_read, mut client_write) = tokio::io::split(client);
            let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
            let mut client =
                traffic_protocol::io::BufferedReader::new(client_read, self.0.max_frame_bytes);
            let mut upstream =
                traffic_protocol::io::BufferedReader::new(upstream_read, self.0.max_frame_bytes);
            let mut pending = std::collections::VecDeque::new();
            let mut anchor = None;
            let mut messages = 0;
            let mut client_decoder = Decoder;
            let mut upstream_decoder = Decoder;
            loop {
                tokio::select! {
                    input = traffic_protocol::io::read_frame(&mut client, &mut client_decoder) => {
                        let Some(input) = input? else { break; };
                        ordinal += 1;
                        let reference = ProtocolRef::new(NAME, json!({"channel":channel,"ordinal":ordinal}))?;
                        let Some(permit) = host.begin(reference, Operation::Read).await? else { anyhow::bail!("fixture capture denied") };
                        ensure!(pending.len() < 32, "fixture pending capture budget exceeded");
                        let started = std::time::Instant::now();
                        upstream_write.write_all(&encode_payload(input.clone())?).await?;
                        upstream_write.flush().await?;
                        pending.push_back((ordinal, input, started, permit));
                    }
                    body = traffic_protocol::io::read_frame(&mut upstream, &mut upstream_decoder) => {
                        let Some(body) = body? else { ensure!(pending.is_empty(), "fixture upstream omitted a response"); break; };
                        let value: Value = serde_json::from_slice(&body)?;
                        if value["notification"] == true {
                            let (subscription, started): (u64, std::time::Instant) = anchor.context("fixture message has no confirmed listener")?;
                            messages += 1;
                            let event = emission::Emission { channel, ordinal: messages, anchor: subscription,
                                peer: PeerAddress { address: self.0.endpoint.host.clone(), port: self.0.endpoint.port },
                                body: body.to_vec(), offset_micros: u64::try_from(started.elapsed().as_micros())? };
                            let event = CaptureSnapshot::capture(&event)?;
                            let permit = host.begin_message(&event).await?.context("fixture message capture denied")?;
                            let receipt = permit.prepare_output(OutputKind::End)?;
                            client_write.write_all(&encode_payload(body)?).await?;
                            client_write.flush().await?;
                            receipt.commit();
                            permit.complete(event).await?;
                        } else {
                            let (ordinal, input, started, permit) = pending.pop_front().context("fixture response has no request")?;
                            let listen = serde_json::from_slice::<Value>(&input)?["operation"] == "listen";
                            let receipt = permit.prepare_output(OutputKind::End)?;
                            client_write.write_all(&encode_payload(body.clone())?).await?;
                            client_write.flush().await?;
                            receipt.commit();
                            if listen { anchor = Some((ordinal, std::time::Instant::now())); }
                            let event = Call { channel, ordinal, peer: PeerAddress { address: self.0.endpoint.host.clone(), port: self.0.endpoint.port },
                                input: input.to_vec(), reply: body.to_vec(), latency_micros: u64::try_from(started.elapsed().as_micros())?, wire_complete: true };
                            permit.complete(CaptureSnapshot::capture(&event)?).await?;
                        }
                    }
                }
            }
            Ok(())
        })
    }
}
