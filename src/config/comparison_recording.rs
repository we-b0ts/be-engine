use anyhow::{Result, bail, ensure};
use hyper::Uri;
use serde::{Deserialize, Serialize};

use super::{HttpGatewayConfig, HttpGatewayFallbackMode};

const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComparisonRecordingConfig {
    pub baseline_upstream: Option<String>,
    pub candidate_upstream: String,
    pub baseline_recheck: bool,
    pub upstream_timeout_ms: u64,
    pub max_in_flight: usize,
    pub summary_flush_interval_ms: u64,
}

impl ComparisonRecordingConfig {
    pub(super) fn validate(&self, gateway: &HttpGatewayConfig) -> Result<()> {
        ensure!(
            gateway.fallback_mode == HttpGatewayFallbackMode::FixedResponse,
            "comparison recording requires http_gateway.fallback_mode = \"fixed_response\" so rejected requests reach neither upstream"
        );
        let baseline = validate_upstream(
            self.baseline_upstream
                .as_deref()
                .map(|value| ("comparison_recording.baseline_upstream", value))
                .unwrap_or(("http_gateway.matched_upstream", &gateway.matched_upstream)),
        )?;
        let candidate = validate_upstream((
            "comparison_recording.candidate_upstream",
            &self.candidate_upstream,
        ))?;
        ensure!(
            baseline != candidate,
            "comparison recording baseline and candidate upstreams must be different"
        );
        ensure!(
            self.upstream_timeout_ms > 0,
            "comparison_recording.upstream_timeout_ms must be greater than zero"
        );
        ensure!(
            self.max_in_flight > 0,
            "comparison_recording.max_in_flight must be greater than zero"
        );
        ensure!(
            self.summary_flush_interval_ms > 0,
            "comparison_recording.summary_flush_interval_ms must be greater than zero"
        );
        ensure!(
            !gateway.rules.is_empty(),
            "comparison recording requires at least one explicit [[http_gateway.rules]] entry"
        );
        let mut names = std::collections::HashSet::new();
        for rule in &gateway.rules {
            let name = rule.name.as_deref().unwrap_or("").trim();
            ensure!(
                !name.is_empty(),
                "comparison recording HTTP gateway rules must have names"
            );
            ensure!(
                names.insert(name),
                "duplicate comparison recording HTTP gateway rule name {name:?}"
            );
            ensure!(
                !rule.methods.is_empty(),
                "comparison recording HTTP gateway rule {name:?} must declare explicit methods"
            );
            for method in &rule.methods {
                let canonical = method.trim().to_ascii_uppercase();
                ensure!(
                    SAFE_METHODS.contains(&canonical.as_str()),
                    "comparison recording HTTP gateway rule {name:?} method {method:?} is not read-only; only GET, HEAD, and OPTIONS may be mirrored"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn baseline_upstream<'a>(&'a self, gateway: &'a HttpGatewayConfig) -> &'a str {
        self.baseline_upstream
            .as_deref()
            .unwrap_or(&gateway.matched_upstream)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UpstreamOrigin {
    scheme: String,
    host: String,
    port: u16,
}

fn validate_upstream((field, value): (&str, &str)) -> Result<UpstreamOrigin> {
    let uri = value
        .parse::<Uri>()
        .map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))?;
    let Some(scheme @ ("http" | "https")) = uri.scheme_str() else {
        bail!("{field} must be an absolute HTTP or HTTPS URI");
    };
    let Some(authority) = uri.authority() else {
        bail!("{field} must be an absolute HTTP or HTTPS URI");
    };
    ensure!(
        uri.path() == "/" && uri.query().is_none(),
        "{field} must contain only an HTTP or HTTPS origin without a path or query"
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

impl Default for ComparisonRecordingConfig {
    fn default() -> Self {
        Self {
            baseline_upstream: None,
            candidate_upstream: "http://127.0.0.1:8082".to_string(),
            baseline_recheck: false,
            upstream_timeout_ms: 30_000,
            max_in_flight: 256,
            summary_flush_interval_ms: 1_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, HttpGatewayFixedResponseConfig, HttpGatewayRuleConfig};

    fn gateway(methods: &[&str]) -> HttpGatewayConfig {
        HttpGatewayConfig {
            fallback_mode: HttpGatewayFallbackMode::FixedResponse,
            fixed_response: Some(HttpGatewayFixedResponseConfig {
                status: 200,
                body: "fixed".to_string(),
                ..Default::default()
            }),
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
        let config = ComparisonRecordingConfig::default();
        assert!(config.validate(&gateway(&[])).is_err());
        assert!(config.validate(&gateway(&["GET", "HEAD"])).is_ok());
        assert!(config.validate(&gateway(&["POST"])).is_err());
    }

    #[test]
    fn rejects_side_effecting_methods_even_without_baseline_recheck() {
        let config = ComparisonRecordingConfig::default();
        assert!(config.validate(&gateway(&["POST"])).is_err());
    }

    #[test]
    fn requires_fixed_response_for_non_admitted_requests() {
        let mut gateway = gateway(&["GET"]);
        gateway.fallback_mode = HttpGatewayFallbackMode::Upstream;
        gateway.fixed_response = None;

        let error = ComparisonRecordingConfig::default()
            .validate(&gateway)
            .unwrap_err();

        assert!(error.to_string().contains("fixed_response"));
    }

    #[test]
    fn rejects_removed_side_effecting_method_override() {
        let result = toml::from_str::<ComparisonRecordingConfig>(
            r#"
            allow_side_effecting_methods = true
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_removed_stage_specific_body_limits() {
        for field in ["max_request_bytes", "max_response_bytes"] {
            let result = toml::from_str::<ComparisonRecordingConfig>(&format!("{field} = 64"));
            assert!(result.is_err(), "accepted obsolete field {field}");
        }
    }

    #[test]
    fn rejects_differently_spelled_equivalent_upstreams() {
        for (baseline, candidate) in [
            ("http://127.0.0.1:8082", "http://127.0.0.1:8082/"),
            ("http://EXAMPLE.test", "http://example.test:80/"),
        ] {
            let config = ComparisonRecordingConfig {
                baseline_upstream: Some(baseline.to_string()),
                candidate_upstream: candidate.to_string(),
                ..Default::default()
            };
            assert!(config.validate(&gateway(&["GET"])).is_err());
        }
    }

    #[test]
    fn rejects_upstream_base_paths_that_would_be_ignored() {
        let config = ComparisonRecordingConfig {
            candidate_upstream: "http://127.0.0.1:8081/base".to_string(),
            ..Default::default()
        };
        assert!(config.validate(&gateway(&["GET"])).is_err());
    }

    #[test]
    fn defaults_baseline_to_http_gateway_upstream() {
        let gateway = gateway(&["GET"]);
        let config = ComparisonRecordingConfig::default();

        config.validate(&gateway).unwrap();

        assert_eq!(config.baseline_upstream(&gateway), gateway.matched_upstream);
    }

    #[test]
    fn accepts_explicit_baseline_without_artifacts_section() {
        let config: AppConfig = toml::from_str(
            r#"
            [comparison_recording]
            baseline_upstream = "http://127.0.0.1:8082"
            candidate_upstream = "http://127.0.0.1:8083"

            [http_gateway]
            matched_upstream = "http://127.0.0.1:8081"
            fallback_mode = "fixed_response"

            [http_gateway.fixed_response]
            status = 200
            body = "fixed"

            [[http_gateway.rules]]
            name = "api"
            methods = ["GET"]

            [recording]
            output_dir = "./legacy-recordings"
            "#,
        )
        .unwrap();

        config.validate_comparison_recording().unwrap();

        assert_eq!(
            config
                .comparison_recording
                .as_ref()
                .unwrap()
                .baseline_upstream(&config.http_gateway),
            "http://127.0.0.1:8082"
        );
        assert_eq!(
            config.comparison_recording_output_dir(),
            std::path::PathBuf::from("./legacy-recordings/comparison-recordings")
        );
    }

    #[test]
    fn rejects_the_removed_compare_section() {
        let config: AppConfig = toml::from_str(
            r#"
            [compare]
            candidate_upstream = "http://127.0.0.1:8083"

            [http_gateway]
            matched_upstream = "http://127.0.0.1:8081"

            [[http_gateway.rules]]
            name = "api"
            methods = ["GET"]
            "#,
        )
        .unwrap();

        assert!(config.comparison_recording.is_none());
        assert!(
            config
                .validate_comparison_recording()
                .unwrap_err()
                .to_string()
                .contains("[comparison_recording]")
        );
    }
}
