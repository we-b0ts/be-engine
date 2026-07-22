use anyhow::{Result, bail, ensure};
use hyper::Uri;
use serde::{Deserialize, Serialize};

use super::HttpGatewayConfig;

const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CompareConfig {
    pub baseline_upstream: String,
    pub candidate_upstream: String,
    pub upstream_timeout_ms: u64,
    pub max_in_flight: usize,
    pub summary_flush_interval_ms: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub allow_side_effecting_methods: bool,
}

impl CompareConfig {
    pub(super) fn validate(&self, gateway: &HttpGatewayConfig) -> Result<()> {
        let baseline = validate_upstream("baseline_upstream", &self.baseline_upstream)?;
        let candidate = validate_upstream("candidate_upstream", &self.candidate_upstream)?;
        ensure!(
            baseline != candidate,
            "compare baseline_upstream and candidate_upstream must be different"
        );
        ensure!(
            self.upstream_timeout_ms > 0,
            "compare.upstream_timeout_ms must be greater than zero"
        );
        ensure!(
            self.max_in_flight > 0,
            "compare.max_in_flight must be greater than zero"
        );
        ensure!(
            self.summary_flush_interval_ms > 0,
            "compare.summary_flush_interval_ms must be greater than zero"
        );
        ensure!(
            self.max_request_bytes > 0,
            "compare.max_request_bytes must be greater than zero"
        );
        ensure!(
            self.max_response_bytes > 0,
            "compare.max_response_bytes must be greater than zero"
        );
        ensure!(
            !gateway.rules.is_empty(),
            "compare requires at least one explicit [[http_gateway.rules]] entry"
        );
        let mut names = std::collections::HashSet::new();
        for rule in &gateway.rules {
            let name = rule.name.as_deref().unwrap_or("").trim();
            ensure!(
                !name.is_empty(),
                "compare HTTP gateway rules must have names"
            );
            ensure!(
                names.insert(name),
                "duplicate compare HTTP gateway rule name {name:?}"
            );
            ensure!(
                !rule.methods.is_empty(),
                "compare HTTP gateway rule {name:?} must declare explicit methods"
            );
            if !self.allow_side_effecting_methods {
                for method in &rule.methods {
                    let canonical = method.trim().to_ascii_uppercase();
                    ensure!(
                        SAFE_METHODS.contains(&canonical.as_str()),
                        "compare HTTP gateway rule {name:?} method {method:?} requires compare.allow_side_effecting_methods=true"
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UpstreamOrigin {
    scheme: String,
    host: String,
    port: u16,
}

fn validate_upstream(field: &str, value: &str) -> Result<UpstreamOrigin> {
    let uri = value
        .parse::<Uri>()
        .map_err(|error| anyhow::anyhow!("invalid compare.{field}: {error}"))?;
    let Some(scheme @ ("http" | "https")) = uri.scheme_str() else {
        bail!("compare.{field} must be an absolute HTTP or HTTPS URI");
    };
    let Some(authority) = uri.authority() else {
        bail!("compare.{field} must be an absolute HTTP or HTTPS URI");
    };
    ensure!(
        uri.path() == "/" && uri.query().is_none(),
        "compare.{field} must contain only an HTTP or HTTPS origin without a path or query"
    );
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "http" { 80 } else { 443 });
    Ok(UpstreamOrigin {
        scheme: scheme.to_string(),
        host: authority.host().trim_end_matches('.').to_ascii_lowercase(),
        port,
    })
}

impl Default for CompareConfig {
    fn default() -> Self {
        Self {
            baseline_upstream: "http://127.0.0.1:8082".to_string(),
            candidate_upstream: "http://127.0.0.1:8081".to_string(),
            upstream_timeout_ms: 30_000,
            max_in_flight: 256,
            summary_flush_interval_ms: 1_000,
            max_request_bytes: 10 * 1024 * 1024,
            max_response_bytes: 10 * 1024 * 1024,
            allow_side_effecting_methods: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpGatewayRuleConfig;

    fn gateway(methods: &[&str]) -> HttpGatewayConfig {
        HttpGatewayConfig {
            rules: vec![HttpGatewayRuleConfig {
                name: Some("api".to_string()),
                methods: methods.iter().map(|value| (*value).to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn requires_explicit_safe_methods_by_default() {
        let config = CompareConfig::default();
        assert!(config.validate(&gateway(&[])).is_err());
        assert!(config.validate(&gateway(&["GET", "HEAD"])).is_ok());
        assert!(config.validate(&gateway(&["POST"])).is_err());
    }

    #[test]
    fn permits_explicit_side_effecting_methods_when_enabled() {
        let config = CompareConfig {
            allow_side_effecting_methods: true,
            ..Default::default()
        };
        assert!(config.validate(&gateway(&["POST"])).is_ok());
    }

    #[test]
    fn rejects_differently_spelled_equivalent_upstreams() {
        for (baseline, candidate) in [
            ("http://127.0.0.1:8082", "http://127.0.0.1:8082/"),
            ("http://EXAMPLE.test", "http://example.test:80/"),
        ] {
            let config = CompareConfig {
                baseline_upstream: baseline.to_string(),
                candidate_upstream: candidate.to_string(),
                ..Default::default()
            };
            assert!(config.validate(&gateway(&["GET"])).is_err());
        }
    }

    #[test]
    fn rejects_upstream_base_paths_that_would_be_ignored() {
        let config = CompareConfig {
            candidate_upstream: "http://127.0.0.1:8081/base".to_string(),
            ..Default::default()
        };
        assert!(config.validate(&gateway(&["GET"])).is_err());
    }
}
