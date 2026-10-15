use hyper::header::HOST;
use hyper::{HeaderMap, Method, Uri};

use crate::config::HttpGatewayRuleConfig;
use crate::path_pattern::{matches_path_pattern, segments};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Match {
    pub(crate) name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseGroup {
    pub(crate) pattern: String,
    pub(crate) directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuleDecision {
    Matched(Match),
    Excluded { name: String },
    Unmatched,
}

pub(crate) fn evaluate_request(
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

    if rules.is_empty() {
        return RuleDecision::Matched(Match {
            name: "default".to_string(),
        });
    }

    rules
        .iter()
        .find(|rule| rule_matches(rule, method, uri, headers))
        .map(|rule| Match {
            name: rule.name.clone().unwrap_or_else(|| "unnamed".to_string()),
        })
        .map_or(RuleDecision::Unmatched, RuleDecision::Matched)
}

pub(crate) fn resolve_case_group(uri: &Uri, patterns: &[String]) -> CaseGroup {
    let path = uri.path();
    let pattern = patterns
        .iter()
        .find(|pattern| matches_path_pattern(pattern, path))
        .cloned()
        .unwrap_or_else(|| path.to_string());

    CaseGroup {
        directory: case_group_directory(&pattern),
        pattern,
    }
}

pub(crate) fn request_authority(uri: &Uri, headers: &HeaderMap) -> Option<String> {
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

    if !rule.paths.is_empty() && !rule.paths.iter().any(|path| path == uri.path()) {
        return false;
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

pub(crate) fn case_group_directory(path: &str) -> String {
    let group = segments(path)
        .into_iter()
        .map(|segment| match segment {
            "*" => "wildcard".to_string(),
            "**" => "catchall".to_string(),
            _ => segment.to_string(),
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
            paths: Vec::new(),
            path_prefixes: vec!["/v1/".to_string()],
            headers: [("x-record".to_string(), "yes".to_string())].into(),
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
            name: Some("http-rule".to_string()),
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
                &exclude_rules,
                &[],
                ordinary_request.method(),
                ordinary_request.uri(),
                ordinary_request.headers()
            ),
            RuleDecision::Matched(Match {
                name: "default".to_string()
            })
        );
        assert_eq!(
            evaluate_request(
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
    fn exact_exclusion_preserves_children_siblings_and_other_methods() {
        let exclude = [HttpGatewayRuleConfig {
            name: Some("skip-job-list".to_string()),
            methods: vec!["GET".to_string()],
            paths: vec!["/api/jobs".to_string()],
            ..Default::default()
        }];
        for (method, path, excluded) in [
            (Method::GET, "/api/jobs", true),
            (Method::GET, "/api/jobs?limit=10", true),
            (Method::GET, "/api/jobs/", false),
            (Method::GET, "/api/jobs/42", false),
            (Method::GET, "/api/jobs-archive", false),
            (Method::POST, "/api/jobs", false),
        ] {
            let decision = evaluate_request(
                &exclude,
                &[],
                &method,
                &path.parse().unwrap(),
                &HeaderMap::new(),
            );
            assert_eq!(
                matches!(decision, RuleDecision::Excluded { .. }),
                excluded,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn exact_paths_and_prefixes_must_both_match_when_configured() {
        let rule = HttpGatewayRuleConfig {
            paths: vec!["/api/jobs".to_string(), "/admin/jobs".to_string()],
            path_prefixes: vec!["/api".to_string()],
            ..Default::default()
        };
        for (path, expected) in [
            ("/api/jobs", true),
            ("/api/jobs/42", false),
            ("/admin/jobs", false),
        ] {
            assert_eq!(
                rule_matches(
                    &rule,
                    &Method::GET,
                    &path.parse().unwrap(),
                    &HeaderMap::new()
                ),
                expected,
                "{path}"
            );
        }
    }

    #[test]
    fn builds_case_group_from_full_path() {
        assert_eq!(
            resolve_case_group(&"/api/users/list?x=1".parse().unwrap(), &[]),
            CaseGroup {
                pattern: "/api/users/list".to_string(),
                directory: "api-users-list".to_string(),
            }
        );
        assert_eq!(
            resolve_case_group(&"/api/users/123/xxx".parse().unwrap(), &[]).directory,
            "api-users-123-xxx"
        );
        assert_eq!(
            resolve_case_group(&"/".parse().unwrap(), &[]).directory,
            "root"
        );
    }

    #[test]
    fn builds_case_group_from_matching_pattern() {
        let patterns = vec!["/api/users/*/xxx".to_string()];

        assert_eq!(
            resolve_case_group(&"/api/users/alice/xxx?x=1".parse().unwrap(), &patterns),
            CaseGroup {
                pattern: "/api/users/*/xxx".to_string(),
                directory: "api-users-wildcard-xxx".to_string(),
            }
        );
        assert_eq!(
            resolve_case_group(&"/api/users/bob/xxx".parse().unwrap(), &patterns).directory,
            "api-users-wildcard-xxx"
        );
        assert_eq!(
            resolve_case_group(&"/api/users/bob/other".parse().unwrap(), &patterns).directory,
            "api-users-bob-other"
        );
    }

    #[test]
    fn builds_case_group_from_trailing_catch_all_pattern() {
        let patterns = vec!["/api/namespaces/**".to_string()];

        assert_eq!(
            resolve_case_group(
                &"/api/namespaces/default/pods/nginx".parse().unwrap(),
                &patterns
            ),
            CaseGroup {
                pattern: "/api/namespaces/**".to_string(),
                directory: "api-namespaces-catchall".to_string(),
            }
        );
        assert_eq!(
            resolve_case_group(&"/api/namespaces".parse().unwrap(), &patterns).directory,
            "api-namespaces"
        );
    }
}
