//! HTTP response values and shared HTTP/1 header rendering.
use super::*;
use traffic_protocol::message::MessageEncoder;
use traffic_protocol::output::{BufferedOutput, OutputBoundary, OutputChunk, OutputStream};

mod stream;
pub(crate) use stream::{CHUNKED_HEADER, StreamResponse};

pub struct ResponseMessage {
    pub status: u16,
    pub headers: crate::headers::HeaderSnapshot,
    pub body: Bytes,
    pub head_request: bool,
}

impl ProtocolMessage for ResponseMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let headers = crate::headers::normalized(&self.headers);
        let mut shape = BTreeMap::new();
        let mut values =
            BTreeMap::from([("/body".into(), ProjectedValue::bytes(self.body.clone()))]);
        for (name, entries) in headers {
            if is_framing_header(&name) {
                continue;
            }
            shape.insert(name.clone(), entries.len());
            for (index, value) in entries.into_iter().enumerate() {
                values.insert(header_location(&name, index), ProjectedValue::bytes(value));
            }
        }
        Ok(ProjectedMessage {
            structure: json!({"status":self.status,"headers":shape,"head_request":self.head_request}),
            values,
        })
    }
    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        match serde_json::from_value::<RequestLocation>(selector.clone())? {
            RequestLocation::Request => Ok(self.project()?.values.into_keys().collect()),
            RequestLocation::Body => Ok(vec!["/body".into()]),
            RequestLocation::Header { name, index } => {
                let projection = self.project()?;
                let name = name.to_ascii_lowercase();
                let count = crate::headers::normalized(&self.headers)
                    .get(&name)
                    .map_or(0, Vec::len);
                let locations = match index {
                    Some(index) => vec![header_location(&name, index)],
                    None => (0..count)
                        .map(|index| header_location(&name, index))
                        .collect(),
                };
                ensure!(
                    locations
                        .iter()
                        .all(|path| projection.values.contains_key(path)),
                    "HTTP response header selector is unavailable"
                );
                Ok(locations)
            }
            _ => anyhow::bail!("HTTP response selector requires body or headers"),
        }
    }
    fn evidence(&self, selector: &Value) -> Result<Value> {
        let projection = self.project()?;
        let values = self.locate(selector)?.into_iter().map(|location| {
            json!({"location":location,"capture":traffic_model::capture::capture_body(&projection.values[&location].bytes,usize::MAX)})
        }).collect::<Vec<_>>();
        Ok(json!({"status":self.status,"values":values}))
    }
}

impl MessageEncoder for ResponseMessage {
    fn output(&self, values: &BTreeMap<String, Bytes>) -> Result<Box<dyn OutputStream>> {
        let wire = self.encode(values)?;
        let header_end = wire
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .expect("encoded HTTP response includes its header terminator")
            + 4;
        Ok(Box::new(BufferedOutput::new(
            0,
            [
                OutputChunk {
                    bytes: wire.slice(..header_end),
                    boundary: OutputBoundary::Headers,
                    complete: true,
                },
                OutputChunk {
                    bytes: wire.slice(header_end..),
                    boundary: OutputBoundary::End,
                    complete: true,
                },
            ],
        )))
    }

    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        let status = hyper::StatusCode::from_u16(self.status)?;
        let mut bytes = self.encode_headers(status, values)?;
        let body = &values["/body"];
        if self.head_request {
            let source = crate::headers::normalized(&self.headers);
            if let Some(length) = source
                .get("content-length")
                .and_then(|values| values.first())
            {
                let length = length.parse::<usize>()?;
                bytes.extend_from_slice(format!("content-length: {length}\r\n").as_bytes());
            }
        } else if self.allows_body(status) {
            bytes.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
        } else {
            ensure!(body.is_empty(), "bodyless HTTP response contains payload");
        }
        bytes.extend_from_slice(b"connection: close\r\n\r\n");
        if !self.head_request {
            bytes.extend_from_slice(body);
        }
        Ok(bytes.into())
    }
}

impl ResponseMessage {
    fn allows_body(&self, status: hyper::StatusCode) -> bool {
        !self.head_request
            && !status.is_informational()
            && status != hyper::StatusCode::NO_CONTENT
            && status != hyper::StatusCode::NOT_MODIFIED
    }

    fn encode_headers(
        &self,
        status: hyper::StatusCode,
        values: &BTreeMap<String, Bytes>,
    ) -> Result<Vec<u8>> {
        ensure!(
            self.project()?.values.keys().eq(values.keys()),
            "HTTP response value inventory changed"
        );
        ensure!(
            status != hyper::StatusCode::SWITCHING_PROTOCOLS,
            "HTTP upgrades require an installed streaming capability"
        );
        let mut bytes = format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or_default()
        )
        .into_bytes();
        for (name, entries) in crate::headers::normalized(&self.headers) {
            if is_framing_header(&name) {
                continue;
            }
            hyper::header::HeaderName::from_bytes(name.as_bytes())?;
            for index in 0..entries.len() {
                let value = &values[&header_location(&name, index)];
                hyper::header::HeaderValue::from_bytes(value)?;
                bytes.extend_from_slice(name.as_bytes());
                bytes.extend_from_slice(b": ");
                bytes.extend_from_slice(value);
                bytes.extend_from_slice(b"\r\n");
            }
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_output_retains_headers_and_body_completion_without_stream_parts() {
        for head_request in [false, true] {
            let message = ResponseMessage {
                status: 200,
                headers: BTreeMap::new(),
                body: Bytes::from_static(b"value"),
                head_request,
            };
            let values = message
                .project()
                .unwrap()
                .values
                .into_iter()
                .map(|(path, value)| (path, value.bytes))
                .collect();
            let expected = message.encode(&values).unwrap();
            let mut output = message.output(&values).unwrap();
            assert_eq!(output.part_count(), 0);
            let mut bytes = Vec::new();
            let mut boundaries = Vec::new();
            while let Some(chunk) = output.next().unwrap() {
                bytes.extend_from_slice(&chunk.bytes);
                boundaries.push(chunk.boundary);
            }
            assert_eq!(bytes, expected);
            assert_eq!(boundaries, [OutputBoundary::Headers, OutputBoundary::End]);
        }
    }
}
