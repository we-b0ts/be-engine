use hyper::header::HOST;
use hyper::{HeaderMap, Method, Uri};

use crate::config::HttpGatewayRuleConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Match {
    pub(super) name: String,
    pub(super) case_path_patterns: Vec<String>,
}

pub(super) fn match_request(
    rules: &[HttpGatewayRuleConfig],
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Option<Match> {
    if rules.is_empty() {
        return Some(Match {
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
}

pub(super) fn case_uri_group(uri: &Uri, patterns: &[String]) -> String {
    let path = uri.path();
    let group_path = patterns
        .iter()
        .find(|pattern| path_matches_case_pattern(path, pattern))
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

fn path_matches_case_pattern(path: &str, pattern: &str) -> bool {
    let actual_segments = path_segments(path);
    let pattern_segments = path_segments(pattern);
    actual_segments.len() == pattern_segments.len()
        && actual_segments
            .iter()
            .zip(pattern_segments.iter())
            .all(|(actual, expected)| *expected == "*" || actual == expected)
}

fn case_group_from_path(path: &str) -> String {
    let group = path_segments(path)
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

fn path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
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
