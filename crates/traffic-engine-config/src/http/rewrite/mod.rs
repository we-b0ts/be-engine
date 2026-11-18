use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bytes::Bytes;
use hyper::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, TRANSFER_ENCODING,
};
use hyper::{HeaderMap, Method, StatusCode, Uri};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::config::{
    HttpResponseRewriteConfig, HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
};
use crate::dependency::DiscoveredTcpTarget;
use crate::dns_mock::{FakeDnsRegistry, FakeDnsUpstreamProtocol};
use crate::http::content_encoding;

#[cfg(test)]
mod document_tests;
#[cfg(test)]
mod json_url_tests;
mod json_urls;
mod kubectl_proxy;
mod pluto;
mod registered;

pub use json_urls::{UrlTarget, inspect_url_target};
pub use kubectl_proxy::KubectlProxyManager;
use kubectl_proxy::KubectlProxySpec;

pub struct RewriteInput<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub authority: Option<&'a str>,
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

pub struct RewrittenResponse {
    pub transformation: traffic_model::recording::Transformation,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub discovered_tcp_targets: Vec<DiscoveredTcpTarget>,
}

trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult>;
}

enum PluginResult {
    Unchanged,
    Rewritten {
        body: Box<dyn ResponseBody>,
        targets: Vec<DiscoveredTarget>,
        kubectl_proxy: Option<KubectlProxySpec>,
    },
}

trait ResponseBody: Send + Sync {
    fn materialize(
        self: Box<Self>,
        registered: &BTreeMap<String, crate::dns_mock::FakeDnsEntry>,
    ) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)>;
}

struct CompleteBody(Vec<u8>);
impl ResponseBody for CompleteBody {
    fn materialize(
        self: Box<Self>,
        _registered: &BTreeMap<String, crate::dns_mock::FakeDnsEntry>,
    ) -> Result<(Vec<u8>, Vec<DiscoveredTcpTarget>)> {
        Ok((self.0, Vec::new()))
    }
}

struct DiscoveredTarget {
    alias: String,
    connect_ip: Ipv4Addr,
    upstream_authority: Option<String>,
    upstream_protocol: Option<FakeDnsUpstreamProtocol>,
}

pub struct CompiledRewrites {
    fingerprint: String,
    config: HttpResponseRewriteConfig,
    strategies: BTreeMap<String, registered::RegisteredRewrite>,
}

impl CompiledRewrites {
    pub fn new(config: &HttpResponseRewriteConfig) -> Result<Self> {
        let strategies = config
            .rules
            .iter()
            .filter_map(|rule| match &rule.plugin {
                Some(HttpResponseRewritePluginConfig::Policy(definition)) => Some(
                    registered::RegisteredRewrite::from_definition(definition)
                        .map(|compiled| (rule.name.clone(), compiled)),
                ),
                Some(HttpResponseRewritePluginConfig::Documents { rules }) => Some(
                    serde_json::from_value(serde_json::json!({"rules":rules}))
                        .map_err(anyhow::Error::from)
                        .and_then(|configuration| {
                            registered::RegisteredRewrite::new("documents", &configuration)
                        })
                        .map(|compiled| (rule.name.clone(), compiled)),
                ),
                _ => None,
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            fingerprint: format!("{:x}", Sha256::digest(serde_json::to_vec(config)?)),
            config: config.clone(),
            strategies,
        })
    }
}

pub async fn apply(
    compiled: &CompiledRewrites,
    registry: &FakeDnsRegistry,
    kubectl_proxy_manager: &KubectlProxyManager,
    recorder_ca_pem: &str,
    max_decoded_body_bytes: usize,
    input: RewriteInput<'_>,
) -> Result<Option<RewrittenResponse>> {
    let config = &compiled.config;
    if !config.is_enabled() {
        return Ok(None);
    }
    let Some(rule) = config.rules.iter().find(|rule| matches(rule, &input)) else {
        return Ok(None);
    };
    let mut rule = rule.clone();
    if rule.plugin.is_none() {
        for matching in config
            .rules
            .iter()
            .filter(|candidate| candidate.plugin.is_none() && matches(candidate, &input))
        {
            for pointer in &matching.pointers {
                if !rule.pointers.contains(pointer) {
                    rule.pointers.push(pointer.clone());
                }
            }
        }
    }
    let decoded_body = decode_rewrite_body(input.headers, input.body, max_decoded_body_bytes)
        .with_context(|| {
            format!(
                "failed to decode HTTP response rewrite rule {:?} body",
                rule.name
            )
        })?;
    let input = RewriteInput {
        body: decoded_body.as_ref(),
        ..input
    };
    let rule_ids = if rule.plugin.is_some() {
        vec![rule.name.clone()]
    } else {
        config
            .rules
            .iter()
            .filter(|candidate| candidate.plugin.is_none() && matches(candidate, &input))
            .map(|candidate| candidate.name.clone())
            .collect()
    };

    let owned: Box<dyn Plugin>;
    let plugin: &dyn Plugin = match &rule.plugin {
        Some(HttpResponseRewritePluginConfig::PlutoEciKubeconfig {
            kubectl_binary,
            proxy_listen,
        }) => {
            owned = Box::new(pluto::EciKubeconfig::new(
                kubectl_binary,
                *proxy_listen,
                recorder_ca_pem,
            )?);
            owned.as_ref()
        }
        Some(
            HttpResponseRewritePluginConfig::Documents { .. }
            | HttpResponseRewritePluginConfig::Policy(_),
        ) => compiled
            .strategies
            .get(&rule.name)
            .ok_or_else(|| anyhow!("response rewrite rule was not compiled"))?,
        None => {
            owned = Box::new(json_urls::JsonUrls::new(&rule.pointers));
            owned.as_ref()
        }
    };

    let PluginResult::Rewritten {
        body,
        targets,
        kubectl_proxy,
    } = plugin
        .rewrite(&input)
        .with_context(|| format!("HTTP response rewrite plugin {} failed", plugin.name()))?
    else {
        return Ok(None);
    };

    if let Some(kubectl_proxy) = kubectl_proxy {
        kubectl_proxy_manager
            .ensure_running(kubectl_proxy)
            .await
            .with_context(|| {
                format!(
                    "HTTP response rewrite plugin {} proxy failed",
                    plugin.name()
                )
            })?;
    }

    let mut registered_aliases = BTreeMap::new();
    for target in targets {
        let entry = match (&target.upstream_authority, target.upstream_protocol) {
            (Some(authority), Some(protocol)) => {
                registry
                    .register_response_alias(&target.alias, target.connect_ip, authority, protocol)
                    .await
            }
            (None, None) => {
                registry
                    .register_raw_tcp_response_alias(&target.alias, target.connect_ip)
                    .await
            }
            _ => bail!(
                "HTTP response rewrite target {:?} has incomplete upstream metadata",
                target.alias
            ),
        }
        .with_context(|| format!("failed to register response alias {}", target.alias))?;
        info!(
            rule = rule.name,
            plugin = plugin.name(),
            alias = target.alias,
            fake_ip = %entry.fake_ip,
            connect_ip = %target.connect_ip,
            "registered response-discovered target"
        );
        registered_aliases.insert(target.alias, entry.clone());
    }
    let (body, discovered_tcp_targets) = body.materialize(&registered_aliases)?;

    let mut headers = input.headers.clone();
    normalize_rewritten_headers(&mut headers, body.len())?;
    info!(
        rule = rule.name,
        plugin = plugin.name(),
        discovered_tcp_targets = discovered_tcp_targets.len(),
        "rewrote HTTP response and registered discovered target"
    );
    Ok(Some(RewrittenResponse {
        transformation: traffic_model::recording::Transformation {
            surface: "http_response".into(),
            rule_ids,
            policy_sha256: compiled.fingerprint.clone(),
            original_sha256: format!("{:x}", Sha256::digest(input.body)),
            delivered_sha256: format!("{:x}", Sha256::digest(&body)),
            original_body_base64: base64::engine::general_purpose::STANDARD.encode(input.body),
        },
        headers,
        body: Bytes::from(body),
        discovered_tcp_targets,
    }))
}

pub fn matches(rule: &HttpResponseRewriteRuleConfig, input: &RewriteInput<'_>) -> bool {
    let authority = input.authority.map(normalize_authority);
    let authority_matches = authority.is_some_and(|authority| {
        rule.authorities
            .iter()
            .any(|candidate| normalize_authority(candidate) == authority)
    });
    let method_matches = rule.methods.is_empty()
        || rule
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(input.method.as_str()));
    let path_matches = rule.path_pattern.as_ref().map_or_else(
        || input.uri.path() == rule.path,
        |pattern| crate::path_pattern::matches_path_pattern(pattern, input.uri.path()),
    );
    let generic = rule.plugin.is_none();
    let status_matches = if rule.status_codes.is_empty() {
        !generic || input.status.is_success()
    } else {
        rule.status_codes.contains(&input.status.as_u16())
    };
    let content_type_matches = if rule.content_types.is_empty() {
        !generic
            || response_content_type(input.headers).is_some_and(|content_type| {
                content_type.eq_ignore_ascii_case("application/json")
                    || content_type.to_ascii_lowercase().ends_with("+json")
            })
    } else {
        response_content_type(input.headers).is_some_and(|content_type| {
            rule.content_types
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(content_type))
        })
    };

    authority_matches && method_matches && path_matches && status_matches && content_type_matches
}

pub fn decode_rewrite_body<'a>(
    headers: &HeaderMap,
    body: &'a [u8],
    max_decoded_body_bytes: usize,
) -> Result<Cow<'a, [u8]>> {
    if body.len() > max_decoded_body_bytes {
        bail!(
            "response exceeds configured rewrite limit of {} bytes",
            max_decoded_body_bytes
        );
    }
    let Some(value) = headers.get(CONTENT_ENCODING) else {
        return Ok(Cow::Borrowed(body));
    };
    let encoding = value
        .to_str()
        .context("content-encoding is not valid text")?
        .trim();
    if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
        return Ok(Cow::Borrowed(body));
    }
    let decoded =
        content_encoding::decode(body, &encoding.to_ascii_lowercase(), max_decoded_body_bytes)?;
    if decoded.truncated {
        return Err(anyhow!(
            "decoded response exceeds configured limit of {} bytes",
            max_decoded_body_bytes
        ));
    }
    Ok(Cow::Owned(decoded.body))
}

fn normalize_rewritten_headers(headers: &mut HeaderMap, body_len: usize) -> Result<()> {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
    headers.remove("content-md5");
    headers.remove(CONTENT_RANGE);
    headers.remove(ETAG);
    headers.remove(TRANSFER_ENCODING);
    headers.remove("digest");
    headers.insert(CONTENT_LENGTH, body_len.to_string().parse()?);
    Ok(())
}

fn normalize_authority(authority: &str) -> String {
    authority
        .trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase()
}

fn response_content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    #[test]
    fn matches_authority_path_status_and_content_type() {
        let rule: HttpResponseRewriteRuleConfig = toml::from_str(
            r#"
            name = "pluto"
            authorities = ["cs.aliyuncs.com"]
            methods = ["GET"]
            path = "/api/v2/k8s/c142fe56e07d04a749c1630fb5f1b680b/user_config"
            status_codes = [200]
            content_types = ["application/json"]
            plugin = { name = "pluto-eci-kubeconfig", kubectl_binary = "kubectl", proxy_listen = "127.0.0.1:8001" }
            "#,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/json;charset=utf-8".parse().unwrap(),
        );
        let method = Method::GET;
        let uri = "/api/v2/k8s/c142fe56e07d04a749c1630fb5f1b680b/user_config"
            .parse()
            .unwrap();
        let mut input = RewriteInput {
            method: &method,
            uri: &uri,
            authority: Some("cs.aliyuncs.com:80"),
            status: StatusCode::OK,
            headers: &headers,
            body: b"{}",
        };

        assert!(matches(&rule, &input));
        let other_uri = "/api/v2/k8s/c142fe56e07d04a749c1630fb5f1b680b/user_config/extra"
            .parse()
            .unwrap();
        input.uri = &other_uri;
        assert!(!matches(&rule, &input));
    }

    #[test]
    fn decodes_gzip_before_response_rewrite() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(br#"{"code":200}"#).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());

        let decoded = decode_rewrite_body(&headers, &compressed, 1024).unwrap();

        assert_eq!(decoded.as_ref(), br#"{"code":200}"#);
    }

    #[test]
    fn rejects_rewrite_body_that_exceeds_decoded_limit() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![b'a'; 2048]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());

        let error = decode_rewrite_body(&headers, &compressed, 1024).unwrap_err();

        assert!(error.to_string().contains("exceeds configured limit"));
    }
}
