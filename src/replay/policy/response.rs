use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::pattern::path_pattern_matches;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ResponseRules {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) dynamic: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::replay) unordered: BTreeMap<String, Vec<String>>,
}

impl ResponseRules {
    pub(in crate::replay) fn is_empty(&self) -> bool {
        self.dynamic.values().all(Vec::is_empty) && self.unordered.values().all(Vec::is_empty)
    }

    pub(in crate::replay) fn matching_fields(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ResponseField> {
        matching_fields(&self.dynamic, ResponseRuleKind::Dynamic, method, path)
            .chain(matching_fields(
                &self.unordered,
                ResponseRuleKind::Unordered,
                method,
                path,
            ))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRuleKind {
    Dynamic,
    Unordered,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseField {
    pub id: String,
    pub api: String,
    pub pointer: String,
    pub kind: ResponseRuleKind,
}

pub(in crate::replay) fn validate_response_rules(rules: &ResponseRules) -> Result<()> {
    let mut locations = Vec::new();
    validate_rule_map(ResponseRuleKind::Dynamic, &rules.dynamic, &mut locations)?;
    validate_rule_map(
        ResponseRuleKind::Unordered,
        &rules.unordered,
        &mut locations,
    )?;
    for (index, left) in locations.iter().enumerate() {
        for right in locations.iter().skip(index + 1) {
            if left.0.eq_ignore_ascii_case(right.0)
                && json_pointers_overlap(left.2, right.2)
                && path_patterns_overlap(left.1, right.1)
            {
                anyhow::bail!(
                    "overlapping response rules select the same JSON subtree: {:?} {} {} at {} and {:?} {} {} at {}",
                    left.3,
                    left.0,
                    left.1,
                    left.2,
                    right.3,
                    right.0,
                    right.1,
                    right.2
                );
            }
        }
    }
    Ok(())
}

pub(in crate::replay) fn response_rule_ids(rules: &ResponseRules) -> Vec<String> {
    rule_ids(&rules.dynamic, ResponseRuleKind::Dynamic)
        .chain(rule_ids(&rules.unordered, ResponseRuleKind::Unordered))
        .collect()
}

pub(in crate::replay) fn response_rule_id(
    kind: ResponseRuleKind,
    api: &str,
    pointer: &str,
) -> String {
    let kind = match kind {
        ResponseRuleKind::Dynamic => "dynamic",
        ResponseRuleKind::Unordered => "unordered",
    };
    format!("response:{kind}:{api}:{pointer}")
}

pub(in crate::replay) fn parse_api(api: &str) -> Result<(&str, &str)> {
    let (method, path) = api
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("response rule API must use 'METHOD /path': {api:?}"))?;
    ensure!(
        !method.is_empty() && !path.is_empty() && !path.contains(char::is_whitespace),
        "response rule API must use canonical 'METHOD /path': {api:?}"
    );
    ensure!(
        path.starts_with('/'),
        "response rule API path must be absolute: {api:?}"
    );
    Ok((method, path))
}

pub(in crate::replay) fn validate_json_pointer(pointer: &str) -> Result<()> {
    ensure!(
        pointer.starts_with('/') && pointer.len() > 1,
        "response field must use a non-root JSON Pointer: {pointer:?}"
    );
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            ensure!(
                bytes
                    .get(index + 1)
                    .is_some_and(|byte| matches!(byte, b'0' | b'1')),
                "JSON Pointer contains an invalid '~' escape: {pointer:?}"
            );
            index += 1;
        }
        index += 1;
    }
    Ok(())
}

type RuleLocation<'a> = (&'a str, &'a str, &'a str, ResponseRuleKind);

fn validate_rule_map<'a>(
    kind: ResponseRuleKind,
    rules: &'a BTreeMap<String, Vec<String>>,
    locations: &mut Vec<RuleLocation<'a>>,
) -> Result<()> {
    for (api, pointers) in rules {
        let (method, path) = parse_api(api)?;
        ensure!(
            method == method.to_ascii_uppercase(),
            "response rule API method must use uppercase canonical form: {api:?}"
        );
        ensure!(
            !pointers.is_empty(),
            "response rule API {api:?} must select at least one JSON Pointer"
        );
        let mut unique = BTreeSet::new();
        for pointer in pointers {
            validate_json_pointer(pointer)?;
            ensure!(
                unique.insert(pointer),
                "response rule API {api:?} repeats JSON Pointer {pointer:?}"
            );
            locations.push((method, path, pointer, kind));
        }
    }
    Ok(())
}

fn matching_fields<'a>(
    rules: &'a BTreeMap<String, Vec<String>>,
    kind: ResponseRuleKind,
    method: &'a str,
    path: &'a str,
) -> impl Iterator<Item = ResponseField> + 'a {
    rules
        .iter()
        .filter_map(move |(api, pointers)| {
            let (candidate_method, candidate_path) = parse_api(api).ok()?;
            (candidate_method.eq_ignore_ascii_case(method)
                && path_pattern_matches(candidate_path, path))
            .then_some((api, pointers))
        })
        .flat_map(move |(api, pointers)| {
            pointers.iter().map(move |pointer| ResponseField {
                id: response_rule_id(kind, api, pointer),
                api: api.clone(),
                pointer: pointer.clone(),
                kind,
            })
        })
}

fn rule_ids(
    rules: &BTreeMap<String, Vec<String>>,
    kind: ResponseRuleKind,
) -> impl Iterator<Item = String> + '_ {
    rules.iter().flat_map(move |(api, pointers)| {
        pointers
            .iter()
            .map(move |pointer| response_rule_id(kind, api, pointer))
    })
}

fn json_pointers_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn path_patterns_overlap(left: &str, right: &str) -> bool {
    let left = left.split('/').collect::<Vec<_>>();
    let right = right.split('/').collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left == &"*" || right == "*" || left == &right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_and_segment_pattern_apis() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([
                (
                    "GET /api/resource/token".to_string(),
                    vec!["/content".to_string()],
                ),
                (
                    "GET /api/sessions/*".to_string(),
                    vec!["/data/id".to_string()],
                ),
            ]),
            unordered: BTreeMap::new(),
        };

        assert_eq!(
            rules
                .matching_fields("GET", "/api/resource/token")
                .iter()
                .map(|field| field.pointer.as_str())
                .collect::<Vec<_>>(),
            vec!["/content"]
        );
        assert_eq!(
            rules
                .matching_fields("GET", "/api/sessions/42")
                .iter()
                .map(|field| field.pointer.as_str())
                .collect::<Vec<_>>(),
            vec!["/data/id"]
        );
    }

    #[test]
    fn rejects_overlapping_routes_for_the_same_pointer() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([
                (
                    "GET /api/sessions/*".to_string(),
                    vec!["/content".to_string()],
                ),
                (
                    "GET /api/sessions/current".to_string(),
                    vec!["/content".to_string()],
                ),
            ]),
            unordered: BTreeMap::new(),
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn rejects_overlapping_dynamic_and_unordered_subtrees() {
        let rules = ResponseRules {
            dynamic: BTreeMap::from([(
                "GET /api/resource".to_string(),
                vec!["/content/0/id".to_string()],
            )]),
            unordered: BTreeMap::from([(
                "GET /api/resource".to_string(),
                vec!["/content".to_string()],
            )]),
        };

        assert!(validate_response_rules(&rules).is_err());
    }

    #[test]
    fn matches_and_identifies_unordered_fields() {
        let rules = ResponseRules {
            dynamic: BTreeMap::new(),
            unordered: BTreeMap::from([(
                "GET /api/config/ansible_facts".to_string(),
                vec!["/general/sudo_users".to_string()],
            )]),
        };

        let fields = rules.matching_fields("GET", "/api/config/ansible_facts");

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].kind, ResponseRuleKind::Unordered);
        assert_eq!(
            fields[0].id,
            "response:unordered:GET /api/config/ansible_facts:/general/sudo_users"
        );
    }

    #[test]
    fn rejects_invalid_json_pointer_escape() {
        assert!(validate_json_pointer("/content/~2").is_err());
    }
}
