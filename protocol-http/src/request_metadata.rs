//! Explicit semantic comparison for finite HTTPS request metadata.

use std::{collections::BTreeSet, net::Ipv4Addr, sync::Arc};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_protocol::{
    connection::Endpoint,
    message::{ProjectedMessage, ProjectedValue, ProtocolMessage},
};

use crate::{headers, message::RequestMessage, recorded::HttpScheme};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestMetadataRule {
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub json_ipv4: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub traceparent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_encoding: Option<ContentCoding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentCoding {
    Gzip,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl ContentCoding {
    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
        }
    }
}

pub fn validate_rules(rules: &[RequestMetadataRule]) -> Result<()> {
    ensure!(rules.len() <= 256, "too many HTTP request metadata rules");
    let mut routes = BTreeSet::new();
    for rule in rules {
        let host: hyper::http::uri::Authority = rule.host.parse()?;
        ensure!(
            host.as_str() == host.host() && rule.host == rule.host.to_ascii_lowercase(),
            "HTTP request metadata requires a literal lowercase HTTPS host"
        );
        let method: hyper::Method = rule.method.parse()?;
        ensure!(
            method.as_str() == rule.method.to_ascii_uppercase(),
            "HTTP request metadata requires an uppercase method"
        );
        crate::path_pattern::validate_literal_path(&rule.path)?;
        ensure!(
            !rule.path.contains('*') && routes.insert((&rule.host, &rule.method, &rule.path)),
            "HTTP request metadata requires a unique exact route"
        );
        ensure!(
            !rule.json_ipv4.is_empty() || rule.traceparent || rule.accept_encoding.is_some(),
            "HTTP request metadata requires a selected location"
        );
        ensure!(
            rule.json_ipv4.len() <= 16,
            "too many HTTP JSON address fields"
        );
        let mut fields = BTreeSet::new();
        for pointer in &rule.json_ipv4 {
            traffic_contract::path::validate_pointer(pointer, true)?;
            ensure!(
                !pointer.is_empty() && !pointer.contains('*') && fields.insert(pointer),
                "HTTP request metadata requires a unique exact JSON address pointer"
            );
        }
    }
    Ok(())
}

/// Apply a declared metadata view to Source only when its finite response
/// proves this representation is replayable. Target still supplies its raw
/// form first, so an ordinary Source exchange always compares strictly.
pub fn request(
    rules: &[RequestMetadataRule],
    endpoint: &Endpoint,
    raw: Arc<dyn ProtocolMessage>,
    source: Option<&Value>,
) -> Result<Arc<dyn ProtocolMessage>> {
    if endpoint.port != 443 || !rules.iter().any(|rule| rule.host == endpoint.host) {
        return Ok(raw);
    }
    let http = if source.is_some() {
        raw.as_any()
            .and_then(|raw| raw.downcast_ref::<RequestMessage>())
    } else {
        raw.as_any()
            .and_then(|raw| raw.downcast_ref::<TlsRequest>())
            .and_then(|tls| tls.raw.as_any())
            .and_then(|raw| raw.downcast_ref::<RequestMessage>())
    };
    let Some(http) = http else {
        return Ok(raw);
    };
    let uri: hyper::Uri = http.uri.parse()?;
    let Some(rule) = rules.iter().find(|rule| {
        rule.host == endpoint.host && rule.method == http.method && rule.path == uri.path()
    }) else {
        return Ok(raw);
    };
    if source.is_some_and(|source| !eligible_source(source, rule)) {
        return Ok(raw);
    }
    let Some(projection) = metadata_projection(http, rule)? else {
        return Ok(raw);
    };
    let equivalent = MetadataRequest {
        projection,
        raw: raw.clone(),
    };
    if source.is_some() {
        return Ok(Arc::new(equivalent));
    }
    Ok(Arc::new(TargetRequest { raw, equivalent }))
}

fn eligible_source(record: &Value, rule: &RequestMetadataRule) -> bool {
    let Some(scheme) = record["scheme"].as_str() else {
        return false;
    };
    if !HttpScheme::from_recorded(scheme).is_ok_and(|scheme| scheme == HttpScheme::Https)
        || !record["response_stream"].is_null()
        || !record["response_status"]
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status))
    {
        return false;
    }
    let Some(coding) = rule.accept_encoding else {
        return true;
    };
    let Ok(headers) =
        serde_json::from_value::<headers::HeaderSnapshot>(record["response_headers"].clone())
    else {
        return false;
    };
    let headers = headers::normalized(&headers);
    !headers.contains_key("vary")
        && single_header(&headers, "content-encoding")
            .is_some_and(|value| value.eq_ignore_ascii_case(coding.name()))
}

fn metadata_projection(
    request: &RequestMessage,
    rule: &RequestMetadataRule,
) -> Result<Option<ProjectedMessage>> {
    let headers = headers::normalized(&request.headers);
    if !single_header(&headers, "host").is_some_and(|host| host == rule.host) {
        return Ok(None);
    }
    let mut projection = request.project()?;
    if !rule.json_ipv4.is_empty() {
        if single_header(&headers, "content-type") != Some("application/json")
            || [
                "content-md5",
                "digest",
                "content-digest",
                "repr-digest",
                "signature",
                "signature-input",
            ]
            .iter()
            .any(|name| headers.contains_key(*name))
        {
            return Ok(None);
        }
        let Some(body) = traffic_codec_json::parse(&request.body) else {
            return Ok(None);
        };
        let mut body = serde_json::to_value(body)?;
        for pointer in &rule.json_ipv4 {
            let Some(value) = body
                .pointer_mut(pointer)
                .filter(|value| value.as_str().is_some_and(local_ipv4))
            else {
                return Ok(None);
            };
            *value = Value::String("local IPv4 address".to_owned());
        }
        projection.values.insert(
            "/body".to_owned(),
            ProjectedValue::bytes(traffic_codec_json::canonical(&body)),
        );
    }
    if rule.traceparent
        && let Some(trace) = headers.get("traceparent")
    {
        if !matches!(trace.as_slice(), [value] if valid_traceparent(value)) {
            return Ok(None);
        }
        projection.structure["headers"]
            .as_object_mut()
            .expect("HTTP projected headers")
            .remove("traceparent");
        projection.values.remove("/headers/traceparent/0");
    }
    if let Some(coding) = rule.accept_encoding {
        if !single_header(&headers, "accept-encoding")
            .is_some_and(|value| accepts_coding(value, coding))
        {
            return Ok(None);
        }
        projection.values.insert(
            "/headers/accept-encoding/0".to_owned(),
            ProjectedValue::bytes(coding.name()),
        );
    }
    projection.structure["finite_http_request_metadata"] = Value::Bool(true);
    Ok(Some(projection))
}

fn accepts_coding(value: &str, coding: ContentCoding) -> bool {
    let mut seen = BTreeSet::new();
    for offered in value.split(',') {
        let offered = offered.trim().to_ascii_lowercase();
        if !matches!(
            offered.as_str(),
            "br" | "deflate" | "gzip" | "identity" | "zstd"
        ) || !seen.insert(offered)
        {
            return false;
        }
    }
    seen.contains(coding.name())
}

fn single_header<'a>(headers: &'a headers::HeaderSnapshot, name: &str) -> Option<&'a str> {
    match headers.get(name).map(Vec::as_slice) {
        Some([value]) => Some(value),
        _ => None,
    }
}

fn local_ipv4(value: &str) -> bool {
    value
        .parse::<Ipv4Addr>()
        .is_ok_and(|addr| !addr.is_unspecified() && !addr.is_broadcast() && !addr.is_multicast())
}

fn valid_traceparent(value: &str) -> bool {
    let mut fields = value.split('-');
    let valid_hex = |value: &str, length| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let valid_id =
        |value: &str, length| valid_hex(value, length) && value.bytes().any(|byte| byte != b'0');
    fields.next() == Some("00")
        && fields.next().is_some_and(|value| valid_id(value, 32))
        && fields.next().is_some_and(|value| valid_id(value, 16))
        && fields.next().is_some_and(|value| valid_hex(value, 2))
        && fields.next().is_none()
}

struct MetadataRequest {
    projection: ProjectedMessage,
    raw: Arc<dyn ProtocolMessage>,
}

impl ProtocolMessage for MetadataRequest {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: self.projection.structure.clone(),
            values: self.projection.values.clone(),
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        let mut locations = self.raw.locate(selector)?;
        locations.retain(|location| self.projection.values.contains_key(location));
        Ok(locations)
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.raw.evidence(selector)
    }
}

struct TargetRequest {
    raw: Arc<dyn ProtocolMessage>,
    equivalent: MetadataRequest,
}

/// Keep the validated TLS transport apart from the strict application values.
/// WebSocket offers have their own native request representation.
pub(crate) fn tls_target_request(raw: Arc<dyn ProtocolMessage>) -> Arc<dyn ProtocolMessage> {
    if raw.as_any().is_some_and(|raw| raw.is::<RequestMessage>()) {
        Arc::new(TlsRequest { raw })
    } else {
        raw
    }
}

struct TlsRequest {
    raw: Arc<dyn ProtocolMessage>,
}

impl ProtocolMessage for TlsRequest {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn project(&self) -> Result<ProjectedMessage> {
        self.raw.project()
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.raw.locate(selector)
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.raw.evidence(selector)
    }
}

impl ProtocolMessage for TargetRequest {
    fn exact_request_alternative(&self) -> Option<&dyn ProtocolMessage> {
        Some(&self.equivalent)
    }

    fn project(&self) -> Result<ProjectedMessage> {
        self.raw.project()
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.raw.locate(selector)
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.raw.evidence(selector)
    }
}

#[cfg(test)]
mod tests;
