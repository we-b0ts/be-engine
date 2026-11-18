//! Native endpoint and immutable lookup identities for HTTP dependencies.
use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use traffic_protocol::evidence::index::{IndexEndpoint, LookupProjection};

pub fn key(host: &str, port: u16, method: &str, path: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                host.trim_end_matches('.').to_ascii_lowercase(),
                port,
                method.to_ascii_uppercase(),
                path
            ))
            .unwrap()
        )
    )
}
pub fn endpoint(value: &Value) -> Result<IndexEndpoint> {
    let protocol = match value["scheme"]
        .as_str()
        .context("HTTP evidence lacks scheme")?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "http" | "fake_ip_http" | "http_gateway" => "http",
        "https" | "fake_ip_https" => "https",
        _ => anyhow::bail!("invalid HTTP evidence scheme"),
    };
    let authority = value["authority"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .context("HTTP evidence lacks authority")?
        .parse::<hyper::http::uri::Authority>()?;
    Ok(IndexEndpoint {
        host: authority.host().trim_end_matches('.').to_ascii_lowercase(),
        port: authority
            .port_u16()
            .unwrap_or(if protocol == "https" { 443 } else { 80 }),
        protocol: protocol.into(),
    })
}
pub fn lookup(event: &Value, endpoint: &IndexEndpoint) -> Result<LookupProjection> {
    let uri: hyper::Uri = event["uri"].as_str().context("HTTP URI missing")?.parse()?;
    Ok(LookupProjection {
        index: "http".into(),
        key: Some(key(
            &endpoint.host,
            endpoint.port,
            event["method"].as_str().context("HTTP method missing")?,
            uri.path(),
        )),
        connection: None,
        summary: Value::Null,
    })
}
