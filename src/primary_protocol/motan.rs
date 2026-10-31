//! Motan executes the original native frame against the real Target endpoint.
use super::{
    ApiIdentity, CaseClock, CaseExecutionContext, Metadata, NativePrimaryAdapter,
    PrimaryObservation, PrimaryOutput,
};
use crate::protocol_contract::NativeProtocolVersion;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use motan_protocol::{DecodeStatus, Frame, FrameDecoder, MessageKind, ProtocolVersion};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(crate) struct MotanPrimary {
    api: ApiIdentity,
    source_started_at: Option<chrono::DateTime<chrono::Utc>>,
    frame: Frame,
}

#[derive(Deserialize)]
struct Recorded {
    frame: RecordedFrame,
}

#[derive(Deserialize)]
struct RecordedFrame {
    encoding: String,
    data: String,
    truncated: bool,
}

impl MotanPrimary {
    pub(super) fn from_recorded(bytes: &[u8], metadata: Metadata) -> Result<Self> {
        let Recorded { frame } = serde_json::from_slice(bytes)?;
        ensure!(!frame.truncated, "Motan request frame is truncated");
        let raw = match frame.encoding.as_str() {
            "utf8" => frame.data.into_bytes(),
            "base64" => STANDARD.decode(frame.data)?,
            _ => bail!("unsupported Motan request encoding"),
        };
        let DecodeStatus::Complete(frame) =
            motan_protocol::decode_frame(&raw, motan_protocol::Limits::default())?
        else {
            bail!("Motan request frame is incomplete");
        };
        ensure!(
            frame.kind == MessageKind::Request,
            "Motan primary input is not a request frame"
        );
        let expected = match frame.version {
            ProtocolVersion::Motan1 => "motan1",
            ProtocolVersion::Motan2 => "motan2",
        };
        ensure!(
            metadata.protocol_version.as_deref() == Some(expected),
            "Motan input version differs from its native frame"
        );
        let envelope = motan_codec::inspect_request(&frame)
            .context("Motan primary API identity is malformed")?;
        Ok(Self {
            api: ApiIdentity::Motan {
                group: envelope.group,
                interface: envelope.interface_name,
                method: envelope.method_name,
                parameter_desc: envelope.parameter_desc,
                method_sign: envelope.method_sign,
            },
            source_started_at: metadata.timestamp,
            frame,
        })
    }
}

impl NativePrimaryAdapter for MotanPrimary {
    fn api(&self) -> &ApiIdentity {
        &self.api
    }

    fn native_version(&self) -> NativeProtocolVersion {
        match self.frame.version {
            ProtocolVersion::Motan1 => NativeProtocolVersion::Motan1,
            ProtocolVersion::Motan2 => NativeProtocolVersion::Motan2,
        }
    }

    async fn execute(&self, context: &CaseExecutionContext<'_>) -> Result<PrimaryOutput> {
        let upstream = context
            .settings
            .motan_upstream
            .context("Motan case requires a configured target Motan endpoint")?;
        let started_at = chrono::Utc::now();
        let operation = async {
            let mut stream = TcpStream::connect(upstream).await?;
            stream.set_nodelay(true)?;
            stream.write_all(self.frame.raw()).await?;
            if self.frame.flags.oneway() {
                return Ok((204, Vec::new()));
            }
            let mut decoder = FrameDecoder::new(context.settings.motan_limits)?;
            let response = loop {
                if let Some(frame) = decoder.decode()? {
                    break frame;
                }
                if stream.read_buf(decoder.buffer_mut()).await? == 0 {
                    bail!("target closed before returning a Motan response");
                }
            };
            ensure!(
                response.kind == MessageKind::Response
                    && response.request_id == self.frame.request_id
                    && response.version == self.frame.version,
                "target returned a mismatched Motan response frame"
            );
            Ok::<_, anyhow::Error>((
                crate::motan::response_kind_status_code(response.response_kind()),
                response.raw().to_vec(),
            ))
        };
        let mut failure = context.dependency_failure.clone();
        let (status, response_frame) = tokio::select! {
            biased;
            _ = crate::dependency::execution::rejected(&mut failure) => return Err(crate::dependency::execution::UnmatchedDependency {observed_status:None}.into()),
            response = tokio::time::timeout_at(context.deadline, operation) => response.map_err(|_| anyhow::anyhow!("target Motan request timed out"))??,
        };
        Ok(PrimaryOutput {
            api: self.api.clone(),
            clocks: CaseClock {
                source_request_started_at: self.source_started_at,
                target_request_started_at: started_at,
            },
            observation: PrimaryObservation::Motan {
                status,
                response_frame,
            },
        })
    }
}
