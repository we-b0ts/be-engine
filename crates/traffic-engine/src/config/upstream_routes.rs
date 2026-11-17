use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::AppConfig;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesConfig {
    pub kubectl_binary: PathBuf,
    pub kubeconfig: Option<PathBuf>,
    pub context: Option<String>,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            kubectl_binary: PathBuf::from("kubectl"),
            kubeconfig: None,
            context: None,
        }
    }
}

impl KubernetesConfig {
    pub(super) fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamRouteConfig {
    pub host: String,
    pub via: UpstreamTransportConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamTransportConfig {
    KubernetesPortForward { namespace: String, service: String },
}

pub(crate) fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

pub(super) fn validate(config: &AppConfig) -> Result<()> {
    if config.upstream_routes.is_empty() {
        return Ok(());
    }
    ensure!(
        config.dns_mock.enabled && config.tcp_gateway.enabled,
        "upstream_routes requires enabled DNS and TCP gateways"
    );
    ensure!(
        !config.kubernetes.kubectl_binary.as_os_str().is_empty(),
        "kubernetes.kubectl_binary must not be empty"
    );
    if let Some(path) = &config.kubernetes.kubeconfig {
        ensure!(
            !path.as_os_str().is_empty(),
            "kubernetes.kubeconfig must not be empty"
        );
    }
    if let Some(context) = &config.kubernetes.context {
        ensure!(
            !context.is_empty() && !context.contains(['\0', '\n', '\r']),
            "kubernetes.context must be a nonempty single line"
        );
    }
    let mut hosts = BTreeSet::new();
    let bypass = crate::dns_mock::DomainMatcher::from_patterns(&config.dns_mock.bypass_domains);
    for route in &config.upstream_routes {
        let host = normalize_host(&route.host);
        ensure!(
            host.len() <= 253
                && host.contains('.')
                && host.split('.').all(dns_label)
                && host.parse::<std::net::IpAddr>().is_err(),
            "upstream_routes.host must be an exact DNS hostname: {:?}",
            route.host
        );
        ensure!(
            hosts.insert(host.clone()),
            "duplicate upstream route for {host}"
        );
        ensure!(
            !bypass.matches(&host),
            "upstream route for {host} conflicts with DNS bypass"
        );
        ensure!(
            !config
                .dns_mock
                .hosts
                .keys()
                .any(|name| normalize_host(name) == host),
            "upstream route for {host} conflicts with dns_mock.hosts"
        );
        match &route.via {
            UpstreamTransportConfig::KubernetesPortForward { namespace, service } => {
                ensure!(
                    dns_label(namespace),
                    "invalid Kubernetes namespace {namespace:?}"
                );
                ensure!(dns_label(service), "invalid Kubernetes Service {service:?}");
            }
        }
    }
    Ok(())
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

#[cfg(test)]
mod tests;
