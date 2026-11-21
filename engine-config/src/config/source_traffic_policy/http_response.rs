//! Compact, coordinator-owned JSON URL rule documents.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::HttpResponseRewriteRuleConfig as Rule;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub name: String,
    pub path_pattern: String,
    pub pointer: String,
    pub source_evidence: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DomainRules {
    name: String,
    rules: Vec<PathRule>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PathRule {
    path_pattern: String,
    pointer: String,
    source_evidence: String,
}

impl Document {
    pub fn into_rule(self) -> Result<Rule> {
        let (method, path) = self
            .path_pattern
            .split_once(' ')
            .context("path_pattern must contain an HTTP method and path, e.g. GET /sandboxes/*")?;
        ensure!(
            !method.is_empty() && !path.is_empty() && !path.contains(char::is_whitespace),
            "path_pattern must use METHOD /path syntax"
        );
        let method: hyper::Method = method
            .parse()
            .context("invalid HTTP method in path_pattern")?;
        ensure!(
            method.as_str().chars().all(|c| !c.is_ascii_lowercase()),
            "HTTP method must use uppercase letters"
        );
        let authority: hyper::http::uri::Authority = self
            .name
            .parse()
            .context("rule name must be the upstream authority")?;
        ensure!(
            !authority.host().is_empty() && !self.name.contains('@'),
            "rule name must be the upstream authority"
        );
        crate::path_pattern::validate_path_pattern(path)?;
        Ok(Rule {
            name: self.name.clone(),
            authorities: vec![self.name],
            methods: vec![method.to_string()],
            path: String::new(),
            path_pattern: Some(path.into()),
            pointers: vec![self.pointer],
            status_codes: vec![],
            content_types: vec![],
            plugin: None,
            source_evidence: self.source_evidence,
        })
    }

    pub fn from_rule(rule: &Rule) -> Result<Self> {
        ensure!(
            rule.plugin.is_none()
                && rule.authorities.len() == 1
                && rule.methods.len() == 1
                && rule.pointers.len() == 1
                && rule.status_codes.is_empty()
                && rule.content_types.is_empty(),
            "managed HTTP response rules require one authority, method and pointer with default response filters"
        );
        let path = rule.path_pattern.as_deref().unwrap_or(&rule.path);
        Ok(Self {
            name: rule.authorities[0].clone(),
            path_pattern: format!("{} {path}", rule.methods[0]),
            pointer: rule.pointers[0].clone(),
            source_evidence: rule.source_evidence.clone(),
        })
    }
}

pub(super) fn serialize<S: Serializer>(rules: &[Rule], serializer: S) -> Result<S::Ok, S::Error> {
    let mut domains: Vec<DomainRules> = Vec::new();
    for rule in rules {
        let document = Document::from_rule(rule).map_err(serde::ser::Error::custom)?;
        let index = if let Some(index) = domains
            .iter()
            .position(|domain| domain.name == document.name)
        {
            index
        } else {
            domains.push(DomainRules {
                name: document.name,
                rules: Vec::new(),
            });
            domains.len() - 1
        };
        domains[index].rules.push(PathRule {
            path_pattern: document.path_pattern,
            pointer: document.pointer,
            source_evidence: document.source_evidence,
        });
    }
    domains.serialize(serializer)
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Rule>, D::Error> {
    let mut rules = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for domain in Vec::<DomainRules>::deserialize(deserializer)? {
        if domain.rules.is_empty() || !names.insert(domain.name.clone()) {
            return Err(serde::de::Error::custom(
                "each HTTP response authority must appear once with a non-empty rules list",
            ));
        }
        for rule in domain.rules {
            rules.push(
                Document {
                    name: domain.name.clone(),
                    path_pattern: rule.path_pattern,
                    pointer: rule.pointer,
                    source_evidence: rule.source_evidence,
                }
                .into_rule()
                .map_err(serde::de::Error::custom)?,
            );
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceTrafficPolicyConfig;
    use std::path::Path;

    #[test]
    fn separate_typed_capture_scopes_preserve_distinct_pointers_and_ids() {
        let mut policy = SourceTrafficPolicyConfig::empty();
        for (path, pointer) in [("GET /sandboxes/*", "/base_url"), ("GET /other/*", "/url")] {
            policy.http_response_rewrite.push(
                Document {
                    name: "cs.example".into(),
                    path_pattern: path.into(),
                    pointer: pointer.into(),
                    source_evidence: "Source consumes this URL".into(),
                }
                .into_rule()
                .unwrap(),
            );
        }
        let rendered = policy.render().unwrap();
        let document = crate::policy::parse_policy(&rendered).unwrap();
        assert_ne!(document.rules[0].id(), document.rules[1].id());
        let parsed = SourceTrafficPolicyConfig::parse(&rendered, Path::new("policy.yaml")).unwrap();
        assert_eq!(parsed.http_response_rewrite.len(), 2);
        for (actual, expected) in parsed
            .http_response_rewrite
            .iter()
            .zip(&policy.http_response_rewrite)
        {
            assert_eq!(actual.authorities, expected.authorities);
            assert_eq!(actual.path_pattern, expected.path_pattern);
            assert_eq!(actual.pointers, expected.pointers);
        }
    }

    #[test]
    fn old_generated_shape_is_rejected() {
        let yaml = "version: 2\nhttp_response_rewrite:\n- name: json-url-old\n  authorities: [cs.example]\n  methods: [GET]\n  path_pattern: /sandboxes/123\n  pointers: [/base_url]\n";
        assert!(SourceTrafficPolicyConfig::parse(yaml, Path::new("policy.yaml")).is_err());
    }

    #[test]
    fn method_path_and_single_pointer_are_validated() {
        for pattern in [
            "/sandboxes/*",
            "GET ",
            "get /sandboxes/*",
            "GET /sandboxes/12*",
            "GET /sandboxes/**/detail",
        ] {
            assert!(
                Document {
                    name: "cs.example".into(),
                    path_pattern: pattern.into(),
                    pointer: "/base_url".into(),
                    source_evidence: "checked".into()
                }
                .into_rule()
                .is_err(),
                "{pattern}"
            );
        }
    }
}
