use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{StatusCode, Uri};
use serde::{Deserialize, Serialize};

use super::HttpGatewayConfig;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpGatewayFallbackMode {
    #[default]
    Upstream,
    FixedResponse,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct HttpGatewayFixedResponseConfig {
    pub status: u16,
    pub content_type: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

pub(super) fn validate_config(config: &HttpGatewayConfig) -> Result<()> {
    ensure!(
        config.request_timeout_ms > 0,
        "http_gateway.request_timeout_ms must be greater than zero"
    );
    for rule in config.rules.iter().chain(&config.exclude_rules) {
        for path in &rule.paths {
            ensure!(
                path.starts_with('/')
                    && path.parse::<Uri>().is_ok_and(|uri| {
                        uri.scheme().is_none()
                            && uri.authority().is_none()
                            && uri.query().is_none()
                            && uri.path() == path
                    }),
                "http_gateway rule paths must contain absolute paths without query strings: {path:?}"
            );
        }
    }
    match config.fallback_mode {
        HttpGatewayFallbackMode::Upstream => {
            ensure!(
                config.fixed_response.is_none(),
                "http_gateway.fixed_response requires fallback_mode = \"fixed_response\""
            );
            Ok(())
        }
        HttpGatewayFallbackMode::FixedResponse => {
            let fixed = config.fixed_response.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "http_gateway.fallback_mode = \"fixed_response\" requires [http_gateway.fixed_response]"
                )
            })?;
            validate_fixed_response(fixed)
        }
    }
}

fn validate_fixed_response(config: &HttpGatewayFixedResponseConfig) -> Result<()> {
    let status = StatusCode::from_u16(config.status)
        .map_err(|_| anyhow::anyhow!("http_gateway.fixed_response.status is invalid"))?;
    ensure!(
        !status.is_informational() && status.as_u16() <= 599,
        "http_gateway.fixed_response.status must be a standard final HTTP status"
    );
    ensure!(
        !matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        ) || config.body.is_empty(),
        "http_gateway.fixed_response.body must be empty for status {}",
        status.as_u16()
    );
    if let Some(content_type) = &config.content_type {
        HeaderValue::from_str(content_type).map_err(|_| {
            anyhow::anyhow!("http_gateway.fixed_response.content_type is not a valid header value")
        })?;
    }
    let mut names = BTreeSet::new();
    for (name, value) in &config.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            anyhow::anyhow!("http_gateway.fixed_response header name {name:?} is invalid")
        })?;
        ensure!(
            names.insert(name.as_str().to_string()),
            "http_gateway.fixed_response header {} is duplicated case-insensitively",
            name.as_str()
        );
        ensure!(
            config.content_type.is_none() || name.as_str() != "content-type",
            "http_gateway.fixed_response content-type must not be set in both content_type and headers"
        );
        ensure!(
            !is_managed_or_hop_by_hop_header(&name),
            "http_gateway.fixed_response header {} is managed or hop-by-hop",
            name.as_str()
        );
        HeaderValue::from_str(value).map_err(|_| {
            anyhow::anyhow!(
                "http_gateway.fixed_response header {} has an invalid value",
                name.as_str()
            )
        })?;
    }
    Ok(())
}

fn is_managed_or_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_fixed_response_and_rejects_ambiguous_or_invalid_shapes() {
        let mut config = HttpGatewayConfig {
            fallback_mode: HttpGatewayFallbackMode::FixedResponse,
            fixed_response: Some(HttpGatewayFixedResponseConfig {
                status: 201,
                content_type: Some("application/json".to_string()),
                headers: BTreeMap::from([("x-fallback".to_string(), "fixed".to_string())]),
                body: r#"{"code":"created"}"#.to_string(),
            }),
            ..HttpGatewayConfig::default()
        };
        validate_config(&config).unwrap();

        config.fixed_response.as_mut().unwrap().status = 101;
        assert!(validate_config(&config).is_err());
        config.fixed_response.as_mut().unwrap().status = 204;
        assert!(validate_config(&config).is_err());
        config.fixed_response.as_mut().unwrap().status = 200;
        config
            .fixed_response
            .as_mut()
            .unwrap()
            .headers
            .insert("content-length".to_string(), "1".to_string());
        assert!(validate_config(&config).is_err());

        config.fallback_mode = HttpGatewayFallbackMode::Upstream;
        assert!(validate_config(&config).is_err());

        config.fixed_response = None;
        config.request_timeout_ms = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn parses_explicit_fixed_response() {
        let config: crate::AppConfig = toml::from_str(
            r#"
            [http_gateway]
            fallback_mode = "fixed_response"

            [http_gateway.fixed_response]
            status = 200
            content_type = "application/json"
            headers = { x-fallback = "fixed" }
            body = '{"code":"ok"}'
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.http_gateway.fallback_mode,
            HttpGatewayFallbackMode::FixedResponse
        );
        assert_eq!(config.http_gateway.fixed_response.unwrap().status, 200);
        assert_eq!(config.http_gateway.request_timeout_ms, 15_000);
        assert!(!config.http_gateway.record_streaming);
    }

    #[test]
    fn exact_paths_round_trip_and_reject_non_path_selectors() {
        let config: crate::AppConfig = serde_yaml::from_str(
            "http_gateway:\n  rules:\n  - paths: [/api/jobs]\n  exclude_rules:\n  - methods: [GET]\n    paths: [/api/jobs/private]\n",
        )
        .unwrap();
        config.validate().unwrap();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let mut reloaded: crate::AppConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(reloaded.http_gateway.rules[0].paths, ["/api/jobs"]);
        assert_eq!(
            reloaded.http_gateway.exclude_rules[0].paths,
            ["/api/jobs/private"]
        );
        for path in [
            "",
            "api/jobs",
            "/api/jobs?limit=10",
            "https://example.com/api/jobs",
        ] {
            reloaded.http_gateway.rules[0].paths = vec![path.to_string()];
            assert!(reloaded.validate().is_err(), "{path}");
        }
    }

    #[test]
    fn streaming_recording_can_be_enabled_and_round_trips() {
        let config: crate::AppConfig =
            toml::from_str("[http_gateway]\nrecord_streaming = true\n").unwrap();
        config.validate().unwrap();
        assert!(config.http_gateway.record_streaming);
        let yaml = serde_yaml::to_string(&config).unwrap();
        let reloaded: crate::AppConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(reloaded.http_gateway.record_streaming);
    }
}
