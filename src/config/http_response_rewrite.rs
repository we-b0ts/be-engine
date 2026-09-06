use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct HttpResponseRewriteConfig {
    pub enabled: bool,
    pub rules: Vec<HttpResponseRewriteRuleConfig>,
}

impl Default for HttpResponseRewriteConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseRewriteRuleConfig {
    pub name: String,
    #[serde(default)]
    pub authorities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_codes: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<HttpResponseRewritePluginConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "name", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HttpResponseRewritePluginConfig {
    PlutoEciKubeconfig {
        kubectl_binary: String,
        proxy_listen: SocketAddr,
    },
    VintageNaming {
        #[serde(default)]
        services: Vec<String>,
        #[serde(default)]
        clusters: Vec<String>,
    },
    VintageCacheConfig,
}

impl HttpResponseRewriteConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.rules.is_empty()
    }

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
            match (&rule.path_pattern, rule.path.is_empty()) {
                (Some(pattern), true) => crate::path_pattern::validate_path_pattern(pattern)?,
                (None, false) if rule.path.starts_with('/') => {}
                _ => bail!(
                    "HTTP response rewrite rule {name:?} requires exactly one absolute path or path_pattern"
                ),
            }
            if rule
                .status_codes
                .iter()
                .any(|status| !(100..=599).contains(status))
            {
                bail!("HTTP response rewrite rule {name:?} has an invalid status code");
            }
            match (&rule.plugin, rule.pointers.is_empty()) {
                (Some(plugin), true) => plugin.validate(name)?,
                (None, false) => validate_pointers(name, &rule.pointers)?,
                _ => bail!(
                    "HTTP response rewrite rule {name:?} requires pointers or a legacy plugin, exclusively"
                ),
            }
        }
        Ok(())
    }
}

fn validate_pointers(name: &str, pointers: &[String]) -> Result<()> {
    let mut seen = HashSet::new();
    for pointer in pointers {
        if !seen.insert(pointer) || (!pointer.is_empty() && !pointer.starts_with('/')) {
            bail!(
                "HTTP response rewrite rule {name:?} has a duplicate or invalid JSON pointer {pointer:?}"
            );
        }
        let mut chars = pointer.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
                bail!(
                    "HTTP response rewrite rule {name:?} has an invalid JSON pointer escape {pointer:?}"
                );
            }
        }
    }
    Ok(())
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
            Self::VintageNaming {
                services, clusters, ..
            } => {
                validate_values(rule_name, "plugin.services", services)?;
                validate_values(rule_name, "plugin.clusters", clusters)
            }
            Self::VintageCacheConfig => Ok(()),
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
    use super::HttpResponseRewritePluginConfig;

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

    #[test]
    fn parses_vintage_naming_rule_without_cache_behavior_changes() {
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
            name = "vintage-motan"
            authorities = ["static.config.api.demo.test"]
            methods = ["GET"]
            path = "/naming/service"
            status_codes = [200]
            content_types = ["application/json"]
            plugin = { name = "vintage-naming", services = ["yf-rpc"], clusters = ["cn.sina.api.data.service.SinaUserService/service"] }
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        let HttpResponseRewritePluginConfig::VintageNaming { services, clusters } =
            config.http_response_rewrite.rules[0]
                .plugin
                .as_ref()
                .unwrap()
        else {
            panic!("expected Vintage naming plugin");
        };
        assert_eq!(services, &["yf-rpc"]);
        assert_eq!(
            clusters,
            &["cn.sina.api.data.service.SinaUserService/service"]
        );
    }

    #[test]
    fn parses_vintage_cache_config_rule() {
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
            name = "vintage-cache-config"
            authorities = ["config.api.demo.test"]
            methods = ["GET"]
            path = "/1/config/service"
            status_codes = [200]
            content_types = ["application/json"]
            plugin = { name = "vintage-cache-config" }
            "#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(matches!(
            config.http_response_rewrite.rules[0].plugin,
            Some(HttpResponseRewritePluginConfig::VintageCacheConfig)
        ));
    }
}
