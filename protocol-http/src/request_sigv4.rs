//! Exact outbound route matching for AWS Signature Version 4 headers.
use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_contract::time::{TimestampFormat, parse_timestamp};
use traffic_protocol::{
    connection::Endpoint,
    message::{ProjectedMessage, ProjectedValue, ProtocolMessage},
    observation::{format_endpoint, normalize_endpoint},
};

use crate::{
    headers::HeaderSnapshot,
    message::{RequestLocation, RequestView, header_locations},
    request_metadata::wire_request,
};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const PROJECTION: &str = "sigv4_authorization";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigV4Authorization {
    AwsSigv4 {},
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigV4RequestRule {
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    pub authorization: SigV4Authorization,
}

pub fn validate_rules(rules: &[SigV4RequestRule]) -> Result<()> {
    ensure!(rules.len() <= 256, "too many SigV4 HTTP request rules");
    let mut routes = BTreeSet::new();
    for rule in rules {
        let authority: hyper::http::uri::Authority = rule.host.parse()?;
        ensure!(
            !rule.host.contains(['@', '/', '?', '#', '*'])
                && rule.host.len() <= 512
                && authority.port_u16().is_some_and(|port| port != 0)
                && normalize_endpoint(&rule.host).as_deref() == Some(rule.host.as_str()),
            "SigV4 HTTP request requires an exact lowercase host and port"
        );
        let method: hyper::Method = rule.method.parse()?;
        ensure!(
            method.as_str() == rule.method.to_ascii_uppercase(),
            "SigV4 HTTP request requires an uppercase method"
        );
        crate::path_pattern::validate_literal_path(&rule.path)?;
        ensure!(
            rule.path.len() <= 4096 && !rule.path.contains('*'),
            "SigV4 HTTP request requires an exact path"
        );
        if let Some(query) = &rule.query {
            ensure!(
                query.len() <= 4096 && !query.contains('#'),
                "SigV4 HTTP request query must be bounded and exclude fragments"
            );
            let uri: hyper::http::uri::PathAndQuery = format!("{}?{query}", rule.path).parse()?;
            ensure!(
                uri.query() == Some(query.as_str()),
                "SigV4 HTTP request must preserve its exact query"
            );
        }
        ensure!(
            routes.insert((&rule.host, &rule.method, &rule.path, &rule.query)),
            "duplicate SigV4 HTTP request route"
        );
    }
    Ok(())
}

pub fn request(
    rules: &[SigV4RequestRule],
    endpoint: &Endpoint,
    raw: Arc<dyn ProtocolMessage>,
    source: Option<&Value>,
) -> Result<Arc<dyn ProtocolMessage>> {
    if rules.is_empty() {
        return Ok(raw);
    }
    let Some(http) = wire_request(raw.as_ref()) else {
        return Ok(raw);
    };
    let host = format_endpoint(&endpoint.host, endpoint.port);
    if !rules.iter().any(|rule| rule.host == host) {
        return Ok(raw);
    }
    let uri: hyper::Uri = http.uri.parse()?;
    if !rules.iter().any(|rule| {
        rule.host == host
            && rule.method == http.method
            && rule.path == uri.path()
            && rule.query.as_deref() == uri.query()
    }) {
        return Ok(raw);
    }
    let Some(authorization) = Authorization::parse(&http.headers) else {
        return Ok(raw);
    };
    let mut projection =
        http.project_request_with_headers(RequestView::Match, &authorization.signed_headers)?;
    projection.structure[PROJECTION] = Value::Bool(true);
    projection.values.insert(
        "/headers/authorization/0".into(),
        ProjectedValue::bytes(authorization.comparable()),
    );
    Ok(Arc::new(SigV4Request {
        projection,
        raw,
        allow_raw_alternative: source.is_none(),
    }))
}

/// The single valid signing date, independent of the selected authorization rule.
pub fn amz_date(request: &dyn ProtocolMessage) -> Option<&str> {
    let raw = request
        .as_any()
        .and_then(|raw| raw.downcast_ref::<SigV4Request>())
        .map_or(request, |request| request.raw.as_ref());
    signing_date(&wire_request(raw)?.headers)
}

fn signing_date(headers: &HeaderSnapshot) -> Option<&str> {
    let value = single_header(headers, "x-amz-date")?;
    parse_timestamp(&Value::String(value.into()), TimestampFormat::AmzDate, None).ok()?;
    Some(value)
}

fn single_header<'a>(headers: &'a HeaderSnapshot, name: &str) -> Option<&'a str> {
    let mut values = header_values(headers, name);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn header_values<'a>(headers: &'a HeaderSnapshot, name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
        .flat_map(|(_, values)| values.iter().map(|value| value.trim_matches([' ', '\t'])))
}

struct Authorization<'a> {
    access_key_id: &'a str,
    scope: &'a str,
    signed_headers: Vec<&'a str>,
}

impl<'a> Authorization<'a> {
    fn parse(headers: &'a HeaderSnapshot) -> Option<Self> {
        let value = single_header(headers, "authorization")?;
        if value.len() > 8192 {
            return None;
        }
        let (algorithm, parameters) = value.split_once(' ')?;
        if algorithm != ALGORITHM {
            return None;
        }
        let [credential, signed, signature] = authorization_fields(parameters)?;
        if signature.len() != 64
            || !signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let (access_key_id, remainder) = credential.split_once('/')?;
        let (date, scope) = remainder.split_once('/')?;
        let mut scope_segments = scope.split('/');
        let region = scope_segments.next()?;
        let service = scope_segments.next()?;
        if !valid_scope_name(region)
            || !valid_scope_name(service)
            || scope_segments.next() != Some("aws4_request")
            || scope_segments.next().is_some()
            || access_key_id.is_empty()
            || !access_key_id.bytes().all(|byte| byte.is_ascii_graphic())
            || signing_date(headers)?.get(..8)? != date
        {
            return None;
        }
        let signed_headers = signed.split(';').collect::<Vec<_>>();
        if !signed_headers.contains(&"host")
            || !signed_headers.contains(&"x-amz-date")
            || signed_headers.windows(2).any(|pair| pair[0] >= pair[1])
            || signed_headers.iter().any(|name| {
                *name == "authorization"
                    || name.bytes().any(|byte| byte.is_ascii_uppercase())
                    || hyper::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                    || header_values(headers, name).next().is_none()
            })
        {
            return None;
        }
        Some(Self {
            access_key_id,
            scope,
            signed_headers,
        })
    }

    fn comparable(&self) -> String {
        format!(
            "{ALGORITHM} Credential={}/{}, SignedHeaders={}",
            self.access_key_id,
            self.scope,
            self.signed_headers.join(";"),
        )
    }
}

fn valid_scope_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn authorization_fields(parameters: &str) -> Option<[&str; 3]> {
    let mut fields = [None; 3];
    for parameter in parameters.split(',') {
        let (name, value) = parameter.trim_matches([' ', '\t']).split_once('=')?;
        let position = match name {
            "Credential" => 0,
            "SignedHeaders" => 1,
            "Signature" => 2,
            _ => return None,
        };
        if fields[position].replace(value).is_some() {
            return None;
        }
    }
    let [Some(credential), Some(signed), Some(signature)] = fields else {
        return None;
    };
    Some([credential, signed, signature])
}

struct SigV4Request {
    projection: ProjectedMessage,
    raw: Arc<dyn ProtocolMessage>,
    allow_raw_alternative: bool,
}

impl ProtocolMessage for SigV4Request {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn exact_request_alternative(&self) -> Option<&dyn ProtocolMessage> {
        self.allow_raw_alternative.then_some(self.raw.as_ref())
    }

    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: self.projection.structure.clone(),
            values: self.projection.values.clone(),
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        match serde_json::from_value::<RequestLocation>(selector.clone())? {
            RequestLocation::Request => Ok(self.projection.values.keys().cloned().collect()),
            RequestLocation::Header { name, index } => {
                let name = name.to_ascii_lowercase();
                match self.projection.structure["headers"][&name].as_u64() {
                    Some(count) => header_locations(&name, index, count as usize),
                    None => self.raw.locate(selector),
                }
            }
            _ => self.raw.locate(selector),
        }
    }

    fn evidence(&self, query: &Value) -> Result<Value> {
        self.raw.evidence(query)
    }
}

#[cfg(test)]
mod tests;
