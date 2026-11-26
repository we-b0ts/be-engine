//! HTTP/1 chunked output using the captured logical response boundaries.

use std::{io::Write, sync::Arc};

use super::*;
use crate::stream::{ResponseChunk, ResponseStream};

pub(crate) const CHUNKED_HEADER: &[u8] = b"transfer-encoding: chunked";

pub(crate) struct StreamResponse {
    response: ResponseMessage,
    chunks: Arc<[ResponseChunk]>,
    end: OutputBoundary,
}

impl StreamResponse {
    pub(crate) fn new(
        response: ResponseMessage,
        stream: ResponseStream,
        client_terminated: bool,
    ) -> Result<Self> {
        if stream.stopped_at_source_exit {
            ensure!(
                stream.version == 2 && !stream.complete && !client_terminated,
                "HTTP Source-stop response requires version-2 incomplete stream evidence"
            );
            stream.validate_prefix(response.body.len())?;
        } else {
            stream.validate(response.body.len())?;
        }
        ensure!(
            stream.trailers.is_none(),
            "HTTP trailers require a native streaming capability"
        );
        ensure!(
            response.allows_body(hyper::StatusCode::from_u16(response.status)?),
            "bodyless HTTP response cannot replay as a stream"
        );
        Ok(Self {
            response,
            chunks: stream.chunks.into(),
            end: if stream.stopped_at_source_exit {
                OutputBoundary::TargetStop
            } else if client_terminated {
                OutputBoundary::ClientTermination
            } else {
                OutputBoundary::End
            },
        })
    }
}

impl ProtocolMessage for StreamResponse {
    fn project(&self) -> Result<ProjectedMessage> {
        self.response.project()
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.response.locate(selector)
    }

    fn evidence(&self, query: &Value) -> Result<Value> {
        self.response.evidence(query)
    }
}

impl MessageEncoder for StreamResponse {
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        ensure!(
            self.end == OutputBoundary::End,
            "HTTP terminated response prefix requires sequenced streaming output"
        );
        let mut output = self.output(values)?;
        let mut wire = Vec::new();
        while let Some(chunk) = output.next()? {
            wire.extend_from_slice(&chunk.bytes);
        }
        Ok(wire.into())
    }

    fn output(&self, values: &BTreeMap<String, Bytes>) -> Result<Box<dyn OutputStream>> {
        let status = hyper::StatusCode::from_u16(self.response.status)?;
        let mut headers = self.response.encode_headers(status, values)?;
        ensure!(
            values["/body"] == self.response.body,
            "HTTP streamed response body rewrites require a recorded boundary mapping"
        );
        headers.extend_from_slice(CHUNKED_HEADER);
        headers.extend_from_slice(b"\r\nconnection: close\r\n\r\n");
        Ok(Box::new(ChunkedOutput {
            headers: Some(headers.into()),
            body: self.response.body.clone(),
            chunks: self.chunks.clone(),
            next_part: 0,
            end: Some(self.end),
        }))
    }
}

struct ChunkedOutput {
    headers: Option<Bytes>,
    body: Bytes,
    chunks: Arc<[ResponseChunk]>,
    next_part: usize,
    end: Option<OutputBoundary>,
}

impl OutputStream for ChunkedOutput {
    fn part_count(&self) -> usize {
        self.chunks.len()
    }

    fn next(&mut self) -> Result<Option<OutputChunk>> {
        let (bytes, boundary) = if let Some(headers) = self.headers.take() {
            (headers, OutputBoundary::Headers)
        } else if let Some(part) = self.chunks.get(self.next_part) {
            self.next_part += 1;
            let body = &self.body[part.start..part.end];
            let mut wire = Vec::with_capacity(body.len() + 2 * std::mem::size_of::<usize>() + 4);
            write!(wire, "{:x}\r\n", body.len())?;
            wire.extend_from_slice(body);
            wire.extend_from_slice(b"\r\n");
            (wire.into(), OutputBoundary::Part)
        } else if let Some(end) = self.end.take() {
            let bytes = if end == OutputBoundary::End {
                Bytes::from_static(b"0\r\n\r\n")
            } else {
                Bytes::new()
            };
            (bytes, end)
        } else {
            return Ok(None);
        };
        Ok(Some(OutputChunk {
            bytes,
            boundary,
            complete: true,
        }))
    }
}
