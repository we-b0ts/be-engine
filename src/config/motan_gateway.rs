use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Result, ensure};
use motan_protocol::Limits;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MotanGatewayConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub matched_upstream: String,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub max_connections: usize,
    pub max_frame_bytes: usize,
    pub max_cases_per_api: usize,
    pub rules: Vec<MotanGatewayRuleConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MotanGatewayRuleConfig {
    pub name: Option<String>,
    pub groups: Vec<String>,
    pub apis: Vec<String>,
}

impl Default for MotanGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:18081"
                .parse()
                .expect("valid default Motan gateway listen address"),
            matched_upstream: "127.0.0.1:8002".to_string(),
            connect_timeout_ms: 3_000,
            request_timeout_ms: 30_000,
            max_connections: 1_024,
            max_frame_bytes: 8 * 1024 * 1024,
            max_cases_per_api: 100,
            rules: Vec::new(),
        }
    }
}

pub(super) fn validate_config(config: &MotanGatewayConfig) -> Result<()> {
    ensure!(
        !config.matched_upstream.trim().is_empty(),
        "motan_gateway.matched_upstream must not be empty"
    );
    ensure!(
        config.connect_timeout_ms > 0,
        "motan_gateway.connect_timeout_ms must be greater than zero"
    );
    ensure!(
        config.request_timeout_ms > 0,
        "motan_gateway.request_timeout_ms must be greater than zero"
    );
    ensure!(
        config.max_connections > 0,
        "motan_gateway.max_connections must be greater than zero"
    );
    ensure!(
        config.max_cases_per_api > 0,
        "motan_gateway.max_cases_per_api must be greater than zero"
    );
    Limits {
        max_frame_bytes: config.max_frame_bytes,
        max_metadata_bytes: config.max_frame_bytes,
        max_body_bytes: config.max_frame_bytes,
    }
    .validate()
    .map_err(anyhow::Error::from)?;

    let mut names = HashSet::new();
    for (index, rule) in config.rules.iter().enumerate() {
        let name = rule.name.as_deref().unwrap_or("unnamed").trim();
        ensure!(
            !name.is_empty(),
            "motan_gateway.rules[{index}].name must not be empty"
        );
        ensure!(
            names.insert(name),
            "duplicate motan_gateway rule name {name:?}"
        );
        for (field, values) in [("groups", &rule.groups), ("apis", &rule.apis)] {
            ensure!(
                values
                    .iter()
                    .all(|value| { !value.trim().is_empty() && !value.contains(['\r', '\n']) }),
                "motan_gateway.rules[{index}].{field} values must be non-empty single-line strings"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_limits_and_unique_rule_names() {
        let mut config = MotanGatewayConfig::default();
        validate_config(&config).unwrap();

        config.max_connections = 0;
        assert!(validate_config(&config).is_err());
        config.max_connections = 1;
        config.max_cases_per_api = 0;
        assert!(validate_config(&config).is_err());
        config.max_cases_per_api = 1;
        config.rules = vec![
            crate::config::MotanGatewayRuleConfig {
                name: Some("rpc".to_string()),
                ..Default::default()
            },
            crate::config::MotanGatewayRuleConfig {
                name: Some("rpc".to_string()),
                ..Default::default()
            },
        ];
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn parses_canonical_api_rules_and_rejects_removed_selectors() {
        let config: crate::AppConfig = toml::from_str(
            r#"
            [[motan_gateway.rules]]
            name = "alchemy"
            groups = ["abtest"]
            apis = ["com.weibo.AlchemyRpcService#getConfig(java.lang.String)"]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.motan_gateway.rules[0].apis,
            ["com.weibo.AlchemyRpcService#getConfig(java.lang.String)"]
        );

        assert!(
            toml::from_str::<crate::AppConfig>(
                r#"
                [[motan_gateway.rules]]
                interfaces = ["com.weibo.AlchemyRpcService"]
                methods = ["getConfig"]
                "#,
            )
            .is_err()
        );
    }
}
