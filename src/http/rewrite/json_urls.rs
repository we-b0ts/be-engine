use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::Value;
use url::{Host, Url};

use crate::dependency::DiscoveredTcpTarget;
use crate::dns_mock::{FakeDnsEntry, FakeDnsUpstreamProtocol};

use super::{DiscoveredTarget, Plugin, PluginResult, ResponseBody, RewriteInput};

pub(super) struct JsonUrls {
    pointers: Vec<String>,
}

impl JsonUrls {
    pub(super) fn new(pointers: &[String]) -> Self {
        Self {
            pointers: pointers.to_vec(),
        }
    }
}

impl Plugin for JsonUrls {
    fn name(&self) -> &'static str {
        "json-url-targets"
    }

    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult> {
        let document: Value = serde_json::from_slice(input.body)
            .context("address-bearing HTTP response is not valid JSON")?;
        let mut fields = Vec::new();
        let mut targets = BTreeMap::new();
        for pointer in &self.pointers {
            let Some(value) = document.pointer(pointer).filter(|value| !value.is_null()) else {
                continue;
            };
            let text = value
                .as_str()
                .ok_or_else(|| anyhow!("URL field {pointer:?} must be a string"))?;
            let Some(target) = inspect_url_target(text)
                .with_context(|| format!("URL field {pointer:?} cannot be rewritten"))?
            else {
                continue;
            };
            let UrlTarget {
                alias,
                ip,
                port,
                scheme,
                upstream_authority,
                rewritten,
            } = target;
            targets
                .entry(alias.clone())
                .or_insert_with(|| DiscoveredTarget {
                    alias: alias.clone(),
                    connect_ip: ip,
                    upstream_authority: Some(upstream_authority),
                    upstream_protocol: Some(if scheme == "http" {
                        FakeDnsUpstreamProtocol::Http
                    } else {
                        FakeDnsUpstreamProtocol::Https
                    }),
                });
            fields.push(Field {
                pointer: pointer.clone(),
                rewritten,
                alias,
                ip,
                port,
                protocol: scheme,
            });
        }
        if fields.is_empty() {
            return Ok(PluginResult::Unchanged);
        }
        Ok(PluginResult::Rewritten {
            body: Box::new(ResponsePlan { document, fields }),
            targets: targets.into_values().collect(),
            kubectl_proxy: None,
        })
    }
}

/// Shared by runtime rewriting and bounded rule-candidate inspection.
pub(crate) struct UrlTarget {
    pub(crate) alias: String,
    pub(crate) ip: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) scheme: String,
    upstream_authority: String,
    rewritten: String,
}

pub(crate) fn inspect_url_target(text: &str) -> Result<Option<UrlTarget>> {
    ensure!(
        text.trim() == text && !text.chars().any(|ch| ch.is_control() || ch == '\\'),
        "URL has ambiguous whitespace or separators"
    );
    let url = Url::parse(text).context("invalid URL")?;
    let ip = match url.host() {
        Some(Host::Ipv4(ip)) => ip,
        Some(Host::Domain(_)) => return Ok(None),
        Some(Host::Ipv6(_)) => bail!("response address rewriting currently requires IPv4"),
        None => bail!("URL has no host"),
    };
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "URL requires HTTP or HTTPS"
    );
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        "URL has an unusable upstream address"
    );
    let port = url
        .port_or_known_default()
        .context("HTTP URL has no effective port")?;
    ensure!(port != 0, "URL has a zero port");
    let alias = format!(
        "{}-{}-{}.trp.test",
        url.scheme(),
        ip.to_string().replace('.', "-"),
        port
    );
    let start = text
        .find("://")
        .context("HTTP URL has no authority separator")?
        + 3;
    let end = text[start..]
        .find(['/', '?', '#'])
        .map_or(text.len(), |offset| start + offset);
    let authority_start = text[start..end]
        .rfind('@')
        .map_or(start, |offset| start + offset + 1);
    let host_end = text[authority_start..end]
        .find(':')
        .map_or(end, |offset| authority_start + offset);
    ensure!(
        text[authority_start..host_end] == ip.to_string(),
        "URL requires a canonical IPv4 host"
    );
    // Replace only the original host; serialization could normalize signed URLs.
    let rewritten = format!("{}{}{}", &text[..authority_start], alias, &text[host_end..]);
    Ok(Some(UrlTarget {
        alias,
        ip,
        port,
        scheme: url.scheme().to_string(),
        upstream_authority: text[authority_start..end].to_string(),
        rewritten,
    }))
}

struct Field {
    pointer: String,
    rewritten: String,
    alias: String,
    ip: Ipv4Addr,
    port: u16,
    protocol: String,
}

pub(super) struct ResponsePlan {
    document: Value,
    fields: Vec<Field>,
}

impl ResponseBody for ResponsePlan {
    fn materialize(
        mut self: Box<Self>,
        registered: &BTreeMap<String, FakeDnsEntry>,
    ) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)> {
        let mut discovered = BTreeMap::new();
        for field in self.fields {
            let entry = registered
                .get(&field.alias)
                .context("JSON URL has no registered route")?;
            *self
                .document
                .pointer_mut(&field.pointer)
                .context("JSON URL pointer disappeared during rewriting")? =
                Value::String(field.rewritten);
            discovered
                .entry((field.alias.clone(), field.port))
                .or_insert(DiscoveredTcpTarget {
                    protocol: field.protocol,
                    alias: field.alias,
                    advertised_ip: entry.fake_ip,
                    upstream_ip: field.ip,
                    port: field.port,
                    service: None,
                    cluster: None,
                });
        }
        Ok((
            serde_json::to_vec(&self.document)?,
            discovered.into_values().collect(),
        ))
    }
}
