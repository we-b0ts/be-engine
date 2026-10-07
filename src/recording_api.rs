use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use hyper::{Method, Uri};

use crate::config::HttpGatewayRuleConfig;
use crate::path_pattern::{matches_path_pattern, path_patterns_overlap, validate_path_pattern};

mod scope;
pub use scope::RecordingApiScope;
pub(crate) use scope::identity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingApi {
    method: Method,
    path_pattern: String,
}

impl RecordingApi {
    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn path_pattern(&self) -> &str {
        &self.path_pattern
    }

    pub fn is_dynamic(&self) -> bool {
        self.path_pattern.contains('*')
    }

    pub fn matches(&self, method: &Method, uri: &Uri) -> bool {
        self.method == *method && matches_path_pattern(&self.path_pattern, uri.path())
    }

    pub(crate) fn is_covered_by(&self, rules: &[HttpGatewayRuleConfig]) -> bool {
        rules.is_empty()
            || rules.iter().any(|rule| {
                method_matches(rule, &self.method)
                    && (rule.path_prefixes.is_empty()
                        || rule
                            .path_prefixes
                            .iter()
                            .any(|prefix| pattern_can_match_prefix(&self.path_pattern, prefix)))
            })
    }
}

impl fmt::Display for RecordingApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.path_pattern)
    }
}

impl FromStr for RecordingApi {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (method, path_pattern) = value.split_once(' ').with_context(|| {
            format!("recording API must use 'METHOD path-or-pattern': {value:?}")
        })?;
        ensure!(
            format!("{method} {path_pattern}") == value,
            "recording API must use one canonical separator: {value:?}"
        );
        let method = method
            .parse::<Method>()
            .with_context(|| format!("recording API has invalid HTTP method: {value:?}"))?;
        ensure!(
            method.as_str() == method.as_str().to_ascii_uppercase(),
            "recording API method must use canonical uppercase form: {value:?}"
        );
        if path_pattern != "/" {
            validate_path_pattern(path_pattern)
                .with_context(|| format!("invalid recording API {value:?}"))?;
        }
        Ok(Self {
            method,
            path_pattern: path_pattern.to_string(),
        })
    }
}

pub(crate) fn validate_selection(
    selection: &[RecordingApi],
    rules: &[HttpGatewayRuleConfig],
) -> Result<()> {
    let mut unique = BTreeSet::new();
    for (position, api) in selection.iter().enumerate() {
        ensure!(
            unique.insert(api.to_string()),
            "duplicate recording API selector: {api}"
        );
        ensure!(
            selection[..position].iter().all(|previous| {
                previous.method != api.method
                    || !path_patterns_overlap(&previous.path_pattern, &api.path_pattern)
            }),
            "recording API selectors must not overlap for the same method: {api}"
        );
        ensure!(
            api.method.as_str() == "MOTAN" || api.is_covered_by(rules),
            "recording API {api:?} is outside every configured [[http_gateway.rules]] method/path scope"
        );
    }
    Ok(())
}

fn method_matches(rule: &HttpGatewayRuleConfig, method: &Method) -> bool {
    rule.methods.is_empty()
        || rule
            .methods
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(method.as_str()))
}

fn pattern_can_match_prefix(pattern: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    path_patterns_overlap(pattern, prefix)
        || path_patterns_overlap(pattern, &format!("{prefix}/**"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_canonical_api_selectors() {
        let api = "GET /api/users/*".parse::<RecordingApi>().unwrap();
        assert_eq!(api.to_string(), "GET /api/users/*");
        assert!(api.matches(&Method::GET, &"/api/users/42".parse().unwrap()));
        assert!(!api.matches(&Method::GET, &"/api/users/42/posts".parse().unwrap()));
        assert!("get /api/users/*".parse::<RecordingApi>().is_err());
        assert!("GET  /api/users/*".parse::<RecordingApi>().is_err());
    }

    #[test]
    fn selection_must_stay_inside_configured_method_and_path_scope() {
        let rules = vec![HttpGatewayRuleConfig {
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/api".to_string()],
            ..HttpGatewayRuleConfig::default()
        }];
        assert!(validate_selection(&["GET /api/users/*".parse().unwrap()], &rules).is_ok());
        assert!(validate_selection(&["POST /api/users".parse().unwrap()], &rules).is_err());
        assert!(validate_selection(&["GET /admin".parse().unwrap()], &rules).is_err());
        assert!(
            validate_selection(
                &[
                    "GET /api/users/*".parse().unwrap(),
                    "GET /api/users/42".parse().unwrap(),
                ],
                &rules,
            )
            .is_err()
        );
    }
}
