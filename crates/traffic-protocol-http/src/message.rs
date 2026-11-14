//! HTTP message locations supplied independently of value-rule execution.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};

pub struct RequestMessage {
    pub method: String,
    pub uri: String,
    pub headers: crate::headers::HeaderSnapshot,
    pub body: Bytes,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestLocation {
    PathSegment { index: usize },
    QueryParameter { name: String, index: Option<usize> },
    Body,
    Header { name: String, index: Option<usize> },
}

impl ProtocolMessage for RequestMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let headers = crate::headers::normalized(&self.headers);
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

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        match serde_json::from_value::<RequestLocation>(selector.clone())? {
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

    fn evidence(&self, query: &Value) -> Result<Value> {
        let projection = self.project()?;
        let values = self
            .locate(query)?
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
