use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_MAX_CASES_PER_PATTERN: usize = 100;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpGatewayCaseLimitsConfig {
    pub default: usize,
    pub overrides: BTreeMap<String, usize>,
}

impl HttpGatewayCaseLimitsConfig {
    pub(crate) fn limit_for(&self, case_pattern: &str) -> usize {
        self.overrides
            .get(case_pattern)
            .copied()
            .unwrap_or(self.default)
    }

    pub(super) fn override_for_run(&mut self, limit: NonZeroUsize) {
        let limit = limit.get();
        self.default = limit;
        for configured_limit in self.overrides.values_mut() {
            *configured_limit = limit;
        }
    }

    pub(super) fn validate(&self, case_path_patterns: &[String]) -> Result<()> {
        for pattern in self.overrides.keys() {
            validate_case_pattern(pattern)?;
            if pattern.contains('*') {
                ensure!(
                    case_path_patterns.contains(pattern),
                    "http_gateway.per_api_case_limits override {pattern:?} must exactly match a configured case_path_patterns entry"
                );
            }
        }
        Ok(())
    }
}

impl Default for HttpGatewayCaseLimitsConfig {
    fn default() -> Self {
        Self {
            default: DEFAULT_MAX_CASES_PER_PATTERN,
            overrides: BTreeMap::new(),
        }
    }
}

fn validate_case_pattern(pattern: &str) -> Result<()> {
    ensure!(
        pattern.starts_with('/'),
        "http_gateway.per_api_case_limits override must start with '/': {pattern}"
    );
    ensure!(
        !pattern.contains(['?', '#', '\r', '\n']),
        "http_gateway.per_api_case_limits override must contain only a URI path: {pattern}"
    );
    ensure!(
        pattern == "/" || (!pattern.ends_with('/') && !pattern.contains("//")),
        "http_gateway.per_api_case_limits override must use canonical separators with no trailing slash: {pattern}"
    );
    let segments = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        segments
            .iter()
            .all(|segment| !segment.contains('*') || *segment == "*" || *segment == "**"),
        "http_gateway.per_api_case_limits wildcards must occupy a whole path segment: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .enumerate()
            .all(|(index, segment)| *segment != "**" || index == segments.len() - 1),
        "http_gateway.per_api_case_limits '**' catch-all must be the final path segment: {pattern}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_default_and_exact_pattern_overrides() {
        let limits = HttpGatewayCaseLimitsConfig {
            default: 10,
            overrides: [
                ("/api/users/*".to_string(), 2),
                ("/api/health".to_string(), 0),
            ]
            .into(),
        };

        assert_eq!(limits.limit_for("/api/users/*"), 2);
        assert_eq!(limits.limit_for("/api/health"), 0);
        assert_eq!(limits.limit_for("/api/projects/*"), 10);
    }

    #[test]
    fn runtime_override_applies_to_default_and_every_pattern() {
        let mut limits = HttpGatewayCaseLimitsConfig {
            default: 10,
            overrides: [
                ("/api/users/*".to_string(), 2),
                ("/api/health".to_string(), 0),
            ]
            .into(),
        };

        limits.override_for_run(NonZeroUsize::new(25).unwrap());

        assert_eq!(limits.limit_for("/api/users/*"), 25);
        assert_eq!(limits.limit_for("/api/health"), 25);
        assert_eq!(limits.limit_for("/api/projects/*"), 25);
    }

    #[test]
    fn dynamic_override_must_be_a_configured_case_pattern() {
        let limits = HttpGatewayCaseLimitsConfig {
            overrides: [("/api/users/*".to_string(), 2)].into(),
            ..Default::default()
        };

        assert!(limits.validate(&[]).is_err());
        assert!(limits.validate(&["/api/users/*".to_string()]).is_ok());
    }

    #[test]
    fn rejects_noncanonical_override_patterns() {
        for pattern in [
            "api/users/*",
            "/api/users/",
            "/api//users",
            "/api/user-*",
            "/api/**/users",
            "/api/users?active=true",
        ] {
            assert!(
                validate_case_pattern(pattern).is_err(),
                "pattern should be rejected: {pattern}"
            );
        }
    }
}
