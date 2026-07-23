use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use hyper::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, TRANSFER_ENCODING,
};
use hyper::{HeaderMap, Method, StatusCode, Uri};
use tracing::info;

use crate::config::{
    HttpResponseRewriteConfig, HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
};
use crate::dependency::DiscoveredTcpTarget;
use crate::dns_mock::{FakeDnsRegistry, FakeDnsUpstreamProtocol};

mod kubectl_proxy;
mod pluto;
mod vintage;

pub(crate) use kubectl_proxy::KubectlProxyManager;
use kubectl_proxy::KubectlProxySpec;

pub(crate) struct RewriteInput<'a> {
    pub(crate) method: &'a Method,
    pub(crate) uri: &'a Uri,
    pub(crate) authority: Option<&'a str>,
    pub(crate) status: StatusCode,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) body: &'a [u8],
}

pub(crate) struct RewrittenResponse {
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
    pub(crate) discovered_tcp_targets: Vec<DiscoveredTcpTarget>,
}

trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult>;
}

enum PluginResult {
    Unchanged,
    Rewritten {
        body: Box<RewrittenBody>,
        targets: Vec<DiscoveredTarget>,
        kubectl_proxy: Option<KubectlProxySpec>,
    },
}

enum RewrittenBody {
    Complete(Vec<u8>),
    Vintage(vintage::ResponsePlan),
}

struct DiscoveredTarget {
    alias: String,
    connect_ip: Ipv4Addr,
    upstream_authority: Option<String>,
    upstream_protocol: Option<FakeDnsUpstreamProtocol>,
}

pub(crate) async fn apply(
    config: &HttpResponseRewriteConfig,
    registry: &FakeDnsRegistry,
    kubectl_proxy_manager: &KubectlProxyManager,
    recorder_ca_pem: &str,
    input: RewriteInput<'_>,
) -> Result<Option<RewrittenResponse>> {
    if !config.enabled {
        return Ok(None);
    }
    let Some(rule) = config.rules.iter().find(|rule| matches(rule, &input)) else {
        return Ok(None);
    };
    ensure_identity_encoding(rule, input.headers)?;

    let plugin: Box<dyn Plugin> = match &rule.plugin {
        HttpResponseRewritePluginConfig::PlutoEciKubeconfig {
            kubectl_binary,
            proxy_listen,
        } => Box::new(pluto::EciKubeconfig::new(
            kubectl_binary,
            *proxy_listen,
            recorder_ca_pem,
        )?),
        HttpResponseRewritePluginConfig::VintageNaming {
            services,
            clusters,
            force_full_lookup,
        } => Box::new(vintage::Naming::new(services, clusters, *force_full_lookup)),
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

    let mut registered = BTreeMap::new();
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
        registered.insert(target.connect_ip, entry);
    }
    let (body, discovered_tcp_targets) = match *body {
        RewrittenBody::Complete(body) => (body, Vec::new()),
        RewrittenBody::Vintage(plan) => plan
            .render(&registered)
            .context("failed to render rewritten Vintage naming response")?,
    };

    let mut headers = input.headers.clone();
    normalize_rewritten_headers(&mut headers, body.len())?;
    info!(
        rule = rule.name,
        plugin = plugin.name(),
        discovered_tcp_targets = discovered_tcp_targets.len(),
        "rewrote HTTP response and registered discovered target"
    );
    Ok(Some(RewrittenResponse {
        headers,
        body: Bytes::from(body),
        discovered_tcp_targets,
    }))
}

fn matches(rule: &HttpResponseRewriteRuleConfig, input: &RewriteInput<'_>) -> bool {
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
    let path_matches = input.uri.path() == rule.path;
    let status_matches =
        rule.status_codes.is_empty() || rule.status_codes.contains(&input.status.as_u16());
    let content_type_matches = rule.content_types.is_empty()
        || response_content_type(input.headers).is_some_and(|content_type| {
            rule.content_types
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(content_type))
        });

    authority_matches && method_matches && path_matches && status_matches && content_type_matches
}

fn ensure_identity_encoding(
    rule: &HttpResponseRewriteRuleConfig,
    headers: &HeaderMap,
) -> Result<()> {
    let Some(encoding) = headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    if encoding.eq_ignore_ascii_case("identity") {
        return Ok(());
    }
    bail!(
        "HTTP response rewrite rule {:?} does not support content-encoding {encoding:?}",
        rule.name
    )
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
}
