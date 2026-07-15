use hyper::header::HOST;
use hyper::{HeaderMap, Method, Uri};

use crate::config::{HttpGatewayRuleConfig, VerifiedApiExcludesConfig};
use crate::path_pattern::{matches_segment_pattern, segments};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Match {
    pub(super) name: String,
    pub(super) case_path_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RuleDecision {
    Matched(Match),
    Excluded { name: String },
    Unmatched,
}

pub(super) fn evaluate_request(
    verified_excludes: &VerifiedApiExcludesConfig,
    exclude_rules: &[HttpGatewayRuleConfig],
    rules: &[HttpGatewayRuleConfig],
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> RuleDecision {
    if let Some(rule) = exclude_rules
        .iter()
        .find(|rule| rule_matches(rule, method, uri, headers))
    {
        return RuleDecision::Excluded {
            name: rule.name.clone().unwrap_or_else(|| "unnamed".to_string()),
        };
    }

    if let Some(api) = verified_excludes.apis.iter().find(|api| {
        api.method == method.as_str()
            && matches_segment_pattern(&api.path_pattern, uri.path())
            && rules.iter().any(|rule| {
                rule.name.as_deref() == Some(api.rule.as_str())
                    && rule_matches(rule, method, uri, headers)
            })
    }) {
        return RuleDecision::Excluded {
            name: format!("verified:{}:{} {}", api.rule, api.method, api.path_pattern),
        };
    }

    if rules.is_empty() {
        return RuleDecision::Matched(Match {
            name: "default".to_string(),
            case_path_patterns: Vec::new(),
        });
    }

    rules
        .iter()
        .find(|rule| rule_matches(rule, method, uri, headers))
        .map(|rule| Match {
            name: rule.name.clone().unwrap_or_else(|| "unnamed".to_string()),
            case_path_patterns: rule.case_path_patterns.clone(),
        })
        .map_or(RuleDecision::Unmatched, RuleDecision::Matched)
}

pub(super) fn case_uri_group(uri: &Uri, patterns: &[String]) -> String {
    let path = uri.path();
    let group_path = patterns
        .iter()
        .find(|pattern| matches_segment_pattern(pattern, path))
        .map(String::as_str)
        .unwrap_or(path);

    case_group_from_path(group_path)
}

pub(super) fn request_authority(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority().map(ToString::to_string).or_else(|| {
        headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    })
}

fn rule_matches(
    rule: &HttpGatewayRuleConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> bool {
    if !rule.methods.is_empty()
        && !rule
            .methods
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(method.as_str()))
    {
        return false;
    }

    if !rule.hosts.is_empty() {
        let host = request_authority(uri, headers).unwrap_or_default();
        if !rule
            .hosts
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&host))
        {
            return false;
        }
    }

    if !rule.path_prefixes.is_empty()
        && !rule
            .path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(uri.path(), prefix))
    {
        return false;
    }

    rule.headers.iter().all(|(name, expected)| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| actual == expected)
    })
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    let normalized = prefix.trim_end_matches('/');
    path == normalized || path.starts_with(&format!("{normalized}/"))
}

fn case_group_from_path(path: &str) -> String {
    let group = segments(path)
        .into_iter()
        .map(|segment| {
            if segment == "*" {
                "wildcard".to_string()
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("-");

    if group.is_empty() {
        "root".to_string()
    } else {
        group
    }
}

#[cfg(test)]
mod tests {
    use hyper::Request;

    use super::*;

    #[test]
    fn matches_by_host_method_path_and_header() {
        let rule = HttpGatewayRuleConfig {
            name: Some("api".to_string()),
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["POST".to_string()],
            path_prefixes: vec!["/v1/".to_string()],
            headers: [("x-record".to_string(), "yes".to_string())].into(),
            ..Default::default()
        };
        let request = Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header(HOST, "api.example.com")
            .header("x-record", "yes")
            .body(())
            .unwrap();

        assert!(rule_matches(
            &rule,
            request.method(),
            request.uri(),
            request.headers()
        ));
    }

    #[test]
    fn exclusion_rules_take_priority_over_matching_rules() {
        let exclude_rules = vec![HttpGatewayRuleConfig {
            name: Some("skip-internal".to_string()),
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/api/internal".to_string()],
            headers: [("x-app-id".to_string(), "internal".to_string())].into(),
            ..Default::default()
        }];
        let rules = vec![HttpGatewayRuleConfig {
            name: Some("record-api".to_string()),
            path_prefixes: vec!["/api".to_string()],
            ..Default::default()
        }];
        let request = Request::builder()
            .method("GET")
            .uri("/api/internal/users")
            .header("x-app-id", "internal")
            .body(())
            .unwrap();

        assert_eq!(
            evaluate_request(
                &VerifiedApiExcludesConfig::default(),
                &exclude_rules,
                &rules,
                request.method(),
                request.uri(),
                request.headers()
            ),
            RuleDecision::Excluded {
                name: "skip-internal".to_string()
            }
        );
    }

    #[test]
    fn exclusion_rules_can_carve_out_default_matching() {
        let exclude_rules = vec![HttpGatewayRuleConfig {
            name: Some("skip-health".to_string()),
            path_prefixes: vec!["/health".to_string()],
            ..Default::default()
        }];
        let ordinary_request = Request::builder()
            .method("GET")
            .uri("/api/users")
            .body(())
            .unwrap();
        let excluded_request = Request::builder()
            .method("GET")
            .uri("/health/ready")
            .body(())
            .unwrap();

        assert_eq!(
            evaluate_request(
                &VerifiedApiExcludesConfig::default(),
                &exclude_rules,
                &[],
                ordinary_request.method(),
                ordinary_request.uri(),
                ordinary_request.headers()
            ),
            RuleDecision::Matched(Match {
                name: "default".to_string(),
                case_path_patterns: Vec::new()
            })
        );
        assert_eq!(
            evaluate_request(
                &VerifiedApiExcludesConfig::default(),
                &exclude_rules,
                &[],
                excluded_request.method(),
                excluded_request.uri(),
                excluded_request.headers()
            ),
            RuleDecision::Excluded {
                name: "skip-health".to_string()
            }
        );
    }

    #[test]
    fn verified_api_exclude_uses_rule_scope_and_segment_pattern() {
        let verified_excludes = VerifiedApiExcludesConfig {
            consecutive_successes: 3,
            apis: vec![crate::config::VerifiedApiExclude {
                rule: "record-api".to_string(),
                method: "GET".to_string(),
                path_pattern: "/api/users/*".to_string(),
            }],
        };
        let rules = vec![HttpGatewayRuleConfig {
            name: Some("record-api".to_string()),
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/api".to_string()],
            ..Default::default()
        }];
        let excluded = Request::builder()
            .method("GET")
            .uri("/api/users/alice")
            .header(HOST, "api.example.com")
            .body(())
            .unwrap();
        let wrong_host = Request::builder()
            .method("GET")
            .uri("/api/users/alice")
            .header(HOST, "other.example.com")
            .body(())
            .unwrap();

        assert!(matches!(
            evaluate_request(
                &verified_excludes,
                &[],
                &rules,
                excluded.method(),
                excluded.uri(),
                excluded.headers(),
            ),
            RuleDecision::Excluded { .. }
        ));
        assert_eq!(
            evaluate_request(
                &verified_excludes,
                &[],
                &rules,
                wrong_host.method(),
                wrong_host.uri(),
                wrong_host.headers(),
            ),
            RuleDecision::Unmatched
        );
    }

    #[test]
    fn builds_case_group_from_full_path() {
        assert_eq!(
            case_uri_group(&"/api/users/list?x=1".parse().unwrap(), &[]),
            "api-users-list"
        );
        assert_eq!(
            case_uri_group(&"/api/users/123/xxx".parse().unwrap(), &[]),
            "api-users-123-xxx"
        );
        assert_eq!(case_uri_group(&"/".parse().unwrap(), &[]), "root");
    }

    #[test]
    fn builds_case_group_from_matching_pattern() {
        let patterns = vec!["/api/users/*/xxx".to_string()];

        assert_eq!(
            case_uri_group(&"/api/users/alice/xxx?x=1".parse().unwrap(), &patterns),
            "api-users-wildcard-xxx"
        );
        assert_eq!(
            case_uri_group(&"/api/users/bob/xxx".parse().unwrap(), &patterns),
            "api-users-wildcard-xxx"
        );
        assert_eq!(
            case_uri_group(&"/api/users/bob/other".parse().unwrap(), &patterns),
            "api-users-bob-other"
        );
    }
}
