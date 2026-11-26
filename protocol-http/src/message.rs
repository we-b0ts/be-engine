//! HTTP message locations supplied independently of value-rule execution.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};
mod response;
pub use response::ResponseMessage;
pub(crate) use response::{CHUNKED_HEADER, StreamResponse};

pub struct RequestMessage {
    pub method: String,
    pub uri: String,
    pub headers: crate::headers::HeaderSnapshot,
    pub body: Bytes,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestLocation {
    Request,
    PathSegment { index: usize },
    QueryParameter { name: String, index: Option<usize> },
    Body,
    Header { name: String, index: Option<usize> },
}

impl RequestMessage {
    fn project_request(&self, for_evidence: bool) -> Result<ProjectedMessage> {
        let mut headers = crate::headers::normalized(&self.headers);
        headers.retain(|name, _| projected_header(name, for_evidence));
        let shape: BTreeMap<_, _> = headers
            .iter()
            .map(|(name, values)| (name.clone(), values.len()))
            .collect();
        let (uri, mut values) = uri_projection(&self.uri)?;
        values.insert("/body".into(), ProjectedValue::bytes(self.body.clone()));
        for (name, entries) in headers {
            for (index, value) in entries.into_iter().enumerate() {
                values.insert(
                    header_location(&name, index),
                    ProjectedValue::bytes(Bytes::from(value)),
                );
            }
        }
        Ok(ProjectedMessage {
            structure: json!({"method":self.method, "uri":uri, "headers":shape}),
            values,
        })
    }

    fn request_locations(&self, selector: &Value, for_evidence: bool) -> Result<Vec<String>> {
        match serde_json::from_value::<RequestLocation>(selector.clone())? {
            RequestLocation::Request => Ok(self
                .project_request(for_evidence)?
                .values
                .into_keys()
                .collect()),
            RequestLocation::PathSegment { index } => {
                let (_, values) = uri_projection(&self.uri)?;
                let location = format!("/uri/path/{index}");
                ensure!(
                    values.contains_key(&location),
                    "HTTP path segment selector is out of range"
                );
                Ok(vec![location])
            }
            RequestLocation::QueryParameter { name, index } => {
                let uri: hyper::Uri = self.uri.parse()?;
                let locations = uri
                    .query()
                    .into_iter()
                    .flat_map(|query| query.split('&'))
                    .enumerate()
                    .filter(|(_, parameter)| parameter.split('=').next() == Some(name.as_str()))
                    .map(|(index, _)| format!("/uri/query/{index}"))
                    .collect::<Vec<_>>();
                if let Some(index) = index {
                    ensure!(
                        index < locations.len(),
                        "HTTP query selector is out of range"
                    );
                    Ok(vec![locations[index].clone()])
                } else {
                    Ok(locations)
                }
            }
            RequestLocation::Body => Ok(vec!["/body".into()]),
            RequestLocation::Header { name, index } => {
                let headers = crate::headers::normalized(&self.headers);
                let name = name.to_ascii_lowercase();
                ensure!(
                    projected_header(&name, for_evidence),
                    "HTTP transport metadata has no request value location"
                );
                let count = headers.get(&name).map_or(0, Vec::len);
                if let Some(index) = index {
                    ensure!(index < count, "HTTP header selector is out of range");
                    Ok(vec![header_location(&name, index)])
                } else {
                    Ok((0..count)
                        .map(|index| header_location(&name, index))
                        .collect())
                }
            }
        }
    }
}

impl ProtocolMessage for RequestMessage {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn project(&self) -> Result<ProjectedMessage> {
        self.project_request(false)
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.request_locations(selector, false)
    }

    fn evidence(&self, query: &Value) -> Result<Value> {
        // Keep the negotiation and tracing headers available for diagnosis.
        let projection = self.project_request(true)?;
        let values = self
            .request_locations(query, true)?
            .into_iter()
            .map(|location| {
                let capture = traffic_model::capture::capture_body(
                    &projection.values[&location].bytes,
                    usize::MAX,
                );
                json!({"location":location, "capture":capture})
            })
            .collect::<Vec<_>>();
        Ok(json!({"method":self.method, "values":values}))
    }
}

fn projected_header(name: &str, for_evidence: bool) -> bool {
    !is_framing_header(name)
        && !name.starts_with("x-recorder-")
        && (for_evidence
            || !matches!(
                name,
                crate::headers::ACCEPT_ENCODING | crate::headers::TRACEPARENT
            ))
}

fn is_framing_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "transfer-encoding" | "content-length" | "trailer"
    )
}

fn header_location(name: &str, index: usize) -> String {
    format!(
        "/headers/{}/{index}",
        name.replace('~', "~0").replace('/', "~1")
    )
}

fn uri_projection(target: &str) -> Result<(Value, BTreeMap<String, ProjectedValue>)> {
    let uri: hyper::Uri = target.parse()?;
    let mut values = BTreeMap::new();
    let path = uri.path();
    let path = path.strip_prefix('/').unwrap_or(path);
    let mut segments = 0;
    for (index, segment) in path.split('/').enumerate() {
        values.insert(
            format!("/uri/path/{index}"),
            ProjectedValue::bytes(Bytes::copy_from_slice(segment.as_bytes())),
        );
        segments += 1;
    }
    let query = uri.query().map(|query| {
        query
            .split('&')
            .enumerate()
            .map(|(index, parameter)| {
                let (name, value) = parameter
                    .split_once('=')
                    .map_or((parameter, None), |(name, value)| (name, Some(value)));
                values.insert(
                    format!("/uri/query/{index}"),
                    ProjectedValue::bytes(Bytes::copy_from_slice(
                        value.unwrap_or_default().as_bytes(),
                    )),
                );
                json!({"name":name, "has_equals":value.is_some()})
            })
            .collect::<Vec<_>>()
    });
    Ok((
        json!({"scheme":uri.scheme_str(), "authority":uri.authority().map(|authority| authority.as_str()),
        "absolute_path":uri.path().starts_with('/'), "segments":segments, "query":query}),
        values,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_and_tracing_headers_are_evidence_only() {
        let mut request = RequestMessage {
            method: "POST".into(),
            uri: "/value".into(),
            headers: BTreeMap::from([("content-encoding".into(), vec!["gzip".into()])]),
            body: Bytes::new(),
        };
        let expected = request.project().unwrap();
        for (accept_encoding, traceparent) in [
            (
                "gzip, deflate, br, zstd",
                "00-123456789abcdef0123456789abcdef0-0123456789abcdef-01",
            ),
            (
                "gzip;q=0, identity",
                "00-123456789abcdef0123456789abcdef0-123456789abcdef0-01",
            ),
        ] {
            request
                .headers
                .insert("Accept-Encoding".into(), vec![accept_encoding.into()]);
            request
                .headers
                .insert("Traceparent".into(), vec![traceparent.into()]);
            let projected = request.project().unwrap();
            assert_eq!(projected.structure, expected.structure);
            assert_eq!(
                projected.values.keys().collect::<Vec<_>>(),
                expected.values.keys().collect::<Vec<_>>()
            );
        }
        for (name, location) in [
            ("Accept-Encoding", "/headers/accept-encoding/0"),
            ("Traceparent", "/headers/traceparent/0"),
        ] {
            let selector = json!({"kind":"header","name":name});
            assert!(request.locate(&selector).is_err());
            let evidence = request.evidence(&selector).unwrap();
            assert_eq!(evidence["values"][0]["location"], location);
        }
        request.headers.remove("content-encoding");
        assert_ne!(request.project().unwrap().structure, expected.structure);
    }

    #[test]
    fn recorder_transport_metadata_is_excluded_while_sdk_headers_remain_strict() {
        let mut request = RequestMessage {
            method: "GET".into(),
            uri: "/value".into(),
            headers: BTreeMap::from([
                ("host".into(), vec!["api.test".into()]),
                ("x-sdk-signature".into(), vec!["business-value".into()]),
                ("X-Recorder-Fake-Ip".into(), vec!["198.19.0.1:80".into()]),
                ("x-recorder-original-domain".into(), vec!["api.test".into()]),
                (
                    "x-recorder-upstream-addr".into(),
                    vec!["127.0.0.1:80".into()],
                ),
            ]),
            body: Bytes::new(),
        };
        let source = request.project().unwrap();
        assert!(
            request
                .locate(&json!({"kind":"header", "name":"x-recorder-fake-ip"}))
                .is_err()
        );
        request
            .headers
            .retain(|name, _| !name.to_ascii_lowercase().starts_with("x-recorder-"));
        let target = request.project().unwrap();
        assert_eq!(source.structure, target.structure);
        assert!(
            source
                .values
                .iter()
                .all(|(path, value)| value.bytes == target.values[path].bytes)
        );
        request.headers.remove("x-sdk-signature");
        assert_ne!(source.structure, request.project().unwrap().structure);
    }
}
