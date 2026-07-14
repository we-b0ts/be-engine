use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpResponseRewriteConfig {
    pub enabled: bool,
    pub rules: Vec<HttpResponseRewriteRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpResponseRewriteRuleConfig {
    pub name: String,
    #[serde(default)]
    pub authorities: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    pub path: String,
    #[serde(default)]
    pub status_codes: Vec<u16>,
    #[serde(default)]
    pub content_types: Vec<String>,
    pub plugin: HttpResponseRewritePluginConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "name", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HttpResponseRewritePluginConfig {
    PlutoEciKubeconfig {
        kubectl_binary: String,
        proxy_listen: SocketAddr,
    },
}

impl HttpResponseRewriteConfig {
    pub(super) fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        for rule in &self.rules {
            let name = rule.name.trim();
            if name.is_empty() {
                bail!("HTTP response rewrite rule name must not be empty");
            }
            if !names.insert(name) {
                bail!("duplicate HTTP response rewrite rule name {name:?}");
            }
            validate_values(name, "authorities", &rule.authorities)?;
            validate_values(name, "methods", &rule.methods)?;
            validate_values(name, "content_types", &rule.content_types)?;
            if rule.authorities.is_empty() {
                bail!("HTTP response rewrite rule {name:?} must include authorities");
            }
            if rule.path.trim().is_empty() || !rule.path.starts_with('/') {
                bail!("HTTP response rewrite rule {name:?} path must be an absolute HTTP path");
            }
            if rule
                .status_codes
                .iter()
                .any(|status| !(100..=599).contains(status))
            {
                bail!("HTTP response rewrite rule {name:?} has an invalid status code");
            }
            rule.plugin.validate(name)?;
        }
        Ok(())
    }
}

impl HttpResponseRewritePluginConfig {
    fn validate(&self, rule_name: &str) -> Result<()> {
        match self {
            Self::PlutoEciKubeconfig {
                kubectl_binary,
                proxy_listen,
            } => {
                if kubectl_binary.trim().is_empty() {
                    bail!(
                        "HTTP response rewrite rule {rule_name:?} kubectl_binary must not be empty"
                    );
                }
                if !matches!(
                    proxy_listen.ip(),
                    std::net::IpAddr::V4(ip) if ip.is_loopback()
                ) || proxy_listen.port() == 0
                {
                    bail!(
                        "HTTP response rewrite rule {rule_name:?} proxy_listen must be an IPv4 loopback address with a non-zero port"
                    );
                }
                Ok(())
            }
        }
    }
}

fn validate_values(rule_name: &str, field: &str, values: &[String]) -> Result<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        bail!("HTTP response rewrite rule {rule_name:?} has an empty {field} value");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_pluto_eci_kubeconfig_rule() {
        let config: crate::AppConfig = toml::from_str(
            r#"
            [http_response_rewrite]
            enabled = true

            [dns_mock]
            enabled = true

            [tcp_gateway]
            enabled = true
            record_http = true

            [[http_response_rewrite.rules]]
            name = "pluto-kubeconfig"
            authorities = ["cs.aliyuncs.com"]
            methods = ["GET"]
            path = "/api/v2/k8s/c142fe56e07d04a749c1630fb5f1b680b/user_config"
            status_codes = [200]
            content_types = ["application/json"]
            plugin = { name = "pluto-eci-kubeconfig", kubectl_binary = "kubectl", proxy_listen = "127.0.0.1:8001" }
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.http_response_rewrite.enabled);
        assert_eq!(config.http_response_rewrite.rules.len(), 1);
    }

    #[test]
    fn rejects_non_loopback_proxy_listen() {
        let config: crate::AppConfig = toml::from_str(
            r#"
            [http_response_rewrite]
            enabled = true

            [[http_response_rewrite.rules]]
            name = "pluto-kubeconfig"
            authorities = ["cs.aliyuncs.com"]
            path = "/api/v2/k8s/c142fe56e07d04a749c1630fb5f1b680b/user_config"
            plugin = { name = "pluto-eci-kubeconfig", kubectl_binary = "kubectl", proxy_listen = "10.0.0.1:8001" }
            "#,
        )
        .unwrap();

        assert!(config.http_response_rewrite.validate().is_err());
    }
}
