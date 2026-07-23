use std::collections::HashSet;

use anyhow::{Result, bail};
use hyper::http::{Method, Uri, uri::Authority};
use serde::{Deserialize, Serialize};

use crate::recorder::RecorderEvent;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackgroundDependencyRuleConfig {
    Http {
        name: String,
        authorities: Vec<String>,
        methods: Vec<String>,
        path_prefixes: Vec<String>,
        source_revision: String,
        source_evidence: String,
    },
}

impl BackgroundDependencyRuleConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Http { name, .. } => name,
        }
    }

    pub(crate) fn matches(&self, event: &RecorderEvent) -> bool {
        let Self::Http {
            authorities,
            methods,
            path_prefixes,
            ..
        } = self;
        let RecorderEvent::HttpExchange(exchange) = event else {
            return false;
        };
        let Some(authority) = exchange
            .authority
            .as_deref()
            .and_then(normalize_authority)
            .or_else(|| {
                exchange
                    .uri
                    .parse::<Uri>()
                    .ok()
                    .and_then(|uri| uri.authority().map(ToString::to_string))
                    .as_deref()
                    .and_then(normalize_authority)
            })
        else {
            return false;
        };
        let path = exchange
            .uri
            .parse::<Uri>()
            .ok()
            .map(|uri| uri.path().to_string())
            .unwrap_or_else(|| {
                exchange
                    .uri
                    .split('?')
                    .next()
                    .unwrap_or(&exchange.uri)
                    .to_string()
            });

        authorities
            .iter()
            .any(|candidate| normalize_authority(candidate).as_deref() == Some(&authority))
            && methods
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&exchange.method))
            && path_prefixes.iter().any(|prefix| path.starts_with(prefix))
    }
}

pub(super) fn validate(rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for rule in rules {
        let name = rule.name();
        if name.trim().is_empty() {
            bail!("background dependency rule name must not be empty");
        }
        if !names.insert(name) {
            bail!("duplicate background dependency rule name {name:?}");
        }
        match rule {
            BackgroundDependencyRuleConfig::Http {
                authorities,
                methods,
                path_prefixes,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_authorities(name, authorities)?;
                validate_methods(name, methods)?;
                validate_path_prefixes(name, path_prefixes)?;
                validate_source_metadata(source_revision, source_evidence)?;
            }
        }
    }
    validate_non_overlapping_rules(rules)?;
    Ok(())
}

fn validate_source_metadata(source_revision: &str, source_evidence: &str) -> Result<()> {
    validate_single_line("background dependency source revision", source_revision, 64)?;
    if source_revision.len() < 7
        || !source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!(
            "background dependency source revision must be a 7-64 character lowercase hexadecimal revision"
        );
    }
    validate_single_line(
        "background dependency source evidence",
        source_evidence,
        1_024,
    )
}

fn validate_non_overlapping_rules(rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            if http_rules_overlap(left, right) {
                bail!(
                    "background dependency rules {:?} and {:?} have overlapping HTTP selectors",
                    left.name(),
                    right.name()
                );
            }
        }
    }
    Ok(())
}

fn http_rules_overlap(
    left: &BackgroundDependencyRuleConfig,
    right: &BackgroundDependencyRuleConfig,
) -> bool {
    let (
        BackgroundDependencyRuleConfig::Http {
            authorities: left_authorities,
            methods: left_methods,
            path_prefixes: left_paths,
            ..
        },
        BackgroundDependencyRuleConfig::Http {
            authorities: right_authorities,
            methods: right_methods,
            path_prefixes: right_paths,
            ..
        },
    ) = (left, right);
    left_authorities.iter().any(|left| {
        right_authorities
            .iter()
            .any(|right| normalize_authority(left) == normalize_authority(right))
    }) && left_methods.iter().any(|left| {
        right_methods
            .iter()
            .any(|right| left.eq_ignore_ascii_case(right))
    }) && left_paths.iter().any(|left| {
        right_paths
            .iter()
            .any(|right| left.starts_with(right) || right.starts_with(left))
    })
}

fn validate_authorities(rule_name: &str, authorities: &[String]) -> Result<()> {
    if authorities.len() != 1 {
        bail!("HTTP background dependency rule {rule_name:?} must include exactly one authority");
    }
    let mut unique = HashSet::new();
    for authority in authorities {
        let normalized = normalize_authority(authority).ok_or_else(|| {
            anyhow::anyhow!(
                "HTTP background dependency rule {rule_name:?} has invalid authority {authority:?}"
            )
        })?;
        if !unique.insert(normalized) {
            bail!(
                "HTTP background dependency rule {rule_name:?} has duplicate authority {authority:?}"
            );
        }
    }
    Ok(())
}

fn validate_methods(rule_name: &str, methods: &[String]) -> Result<()> {
    if methods.len() != 1 {
        bail!("HTTP background dependency rule {rule_name:?} must include exactly one method");
    }
    let mut unique = HashSet::new();
    for method in methods {
        let parsed = method.parse::<Method>().map_err(|_| {
            anyhow::anyhow!(
                "HTTP background dependency rule {rule_name:?} has invalid method {method:?}"
            )
        })?;
        let normalized = parsed.as_str().to_ascii_uppercase();
        if !unique.insert(normalized) {
            bail!("HTTP background dependency rule {rule_name:?} has duplicate method {method:?}");
        }
    }
    Ok(())
}

fn validate_path_prefixes(rule_name: &str, path_prefixes: &[String]) -> Result<()> {
    if path_prefixes.len() != 1 {
        bail!("HTTP background dependency rule {rule_name:?} must include exactly one path prefix");
    }
    let mut unique = HashSet::new();
    for prefix in path_prefixes {
        if !prefix.starts_with('/') || prefix.contains('?') || prefix.contains('#') {
            bail!(
                "HTTP background dependency rule {rule_name:?} has invalid path prefix {prefix:?}"
            );
        }
        if !unique.insert(prefix) {
            bail!(
                "HTTP background dependency rule {rule_name:?} has duplicate path prefix {prefix:?}"
            );
        }
    }
    Ok(())
}

fn normalize_authority(value: &str) -> Option<String> {
    let authority = value.parse::<Authority>().ok()?;
    let host = authority.host().to_ascii_lowercase();
    Some(match authority.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn validate_single_line(label: &str, value: &str, max_len: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must not be empty");
    }
    if value != value.trim() || value.contains(['\r', '\n']) {
        bail!("{label} must be a single line without surrounding whitespace");
    }
    if value.len() > max_len {
        bail!("{label} must not exceed {max_len} bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::config::AppConfig;
    use crate::recorder::{BodyCapture, HttpExchangeEvent};

    fn http_event(authority: &str, method: &str, uri: &str) -> RecorderEvent {
        RecorderEvent::HttpExchange(HttpExchangeEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            client_addr: None,
            client_process: None,
            scheme: "https".to_string(),
            method: method.to_string(),
            uri: uri.to_string(),
            authority: Some(authority.to_string()),
            request_headers: Default::default(),
            request_body: BodyCapture {
                encoding: "utf8",
                original_len: 0,
                stored_len: 0,
                truncated: false,
                data: String::new(),
            },
            response_status: Some(200),
            response_headers: Some(Default::default()),
            response_body: None,
            duration_ms: 10,
            error: None,
        })
    }

    #[test]
    fn http_rule_matches_authority_method_and_path_without_weakening_query_identity() {
        let rule = BackgroundDependencyRuleConfig::Http {
            name: "config-refresh".to_string(),
            authorities: vec!["CONFIG.API.demo.test".to_string()],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/1/config/service".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        };

        assert!(rule.matches(&http_event(
            "config.api.demo.test",
            "GET",
            "/1/config/service?action=lookup&group=large"
        )));
        assert!(!rule.matches(&http_event(
            "config.api.demo.test",
            "POST",
            "/1/config/service?action=lookup"
        )));
        assert!(!rule.matches(&http_event(
            "other.api.demo.test",
            "GET",
            "/1/config/service?action=lookup"
        )));
    }

    #[test]
    fn parses_and_validates_http_background_rules() {
        let config: AppConfig = toml::from_str(
            r#"
            [recording]

            [[recording.background_dependencies]]
            name = "config-refresh"
            protocol = "http"
            authorities = ["config.api.demo.test"]
            methods = ["GET"]
            path_prefixes = ["/1/config/service"]
            source_revision = "0123456789abcdef"
            source_evidence = "src/config/refresh.rs:42 scheduled refresh"
            "#,
        )
        .unwrap();
        config.validate().unwrap();

        let mut duplicate = config.clone();
        duplicate
            .recording
            .background_dependencies
            .push(duplicate.recording.background_dependencies[0].clone());
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn rejects_host_only_or_ambiguous_http_background_rules() {
        let mut config = AppConfig::default();
        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "too-broad".to_string(),
            authorities: vec!["config.api.demo.test".to_string()],
            methods: Vec::new(),
            path_prefixes: vec!["/".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        assert!(config.validate().is_err());

        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "invalid-path".to_string(),
            authorities: vec!["config.api.demo.test".to_string()],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/lookup?group=x".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        assert!(config.validate().is_err());

        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "cross-product".to_string(),
            authorities: vec![
                "config.api.demo.test".to_string(),
                "static.config.api.demo.test".to_string(),
            ],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/lookup".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        assert!(config.validate().is_err());
    }
}
