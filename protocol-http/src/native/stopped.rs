//! Source exit with a complete HTTP request and no downstream response.

use std::collections::BTreeMap;

use anyhow::Result;
use bytes::Bytes;
use serde_json::Value;
use traffic_protocol::{
    message::{MessageEncoder, ProjectedMessage, ProtocolMessage},
    output::{BufferedOutput, OutputBoundary, OutputChunk, OutputStream},
};

pub(super) struct StoppedResponse;

impl ProtocolMessage for StoppedResponse {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: Value::Null,
            values: BTreeMap::new(),
        })
    }

    fn locate(&self, _: &Value) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn evidence(&self, _: &Value) -> Result<Value> {
        anyhow::bail!("HTTP request stopped before a response was sent")
    }
}

impl MessageEncoder for StoppedResponse {
    fn encode(&self, _: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        anyhow::bail!("HTTP request without a response requires sequenced delivery")
    }

    fn output(&self, _: &BTreeMap<String, Bytes>) -> Result<Box<dyn OutputStream>> {
        Ok(Box::new(BufferedOutput::new(
            0,
            [OutputChunk {
                bytes: Bytes::new(),
                boundary: OutputBoundary::TargetStop,
                complete: true,
            }],
        )))
    }
}
