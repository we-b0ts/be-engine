//! Compatibility entrypoints delegate joined collection semantics to the catalog.
use serde_json::json;
use std::collections::BTreeMap;

pub(super) fn canonicalize(value: &str, separator: &str) -> String {
    let canonical = || -> anyhow::Result<String> {
        let options = serde_json::from_value(json!({"separator":separator}))?;
        let transformation = traffic_extensions::policies()
            .prepare_transform("unordered-joined-string", &options)?;
        let context = traffic_value::Value::Null;
        let plan = transformation
            .inspect(&traffic_policy::TransformInput {
                bytes: value.as_bytes(),
                context: &context,
            })?
            .ok_or_else(|| anyhow::anyhow!("joined collection has no transformation"))?;
        Ok(String::from_utf8(
            plan.materialize(&BTreeMap::new())?.bytes,
        )?)
    };
    canonical().unwrap_or_else(|_| value.into())
}

pub(super) fn equal(expected: &str, actual: &str, separator: &str) -> bool {
    crate::value_extensions::compare_registered(
        "unordered-joined-string",
        &json!({"separator":separator}),
        &json!(expected),
        &json!(actual),
    )
    .is_ok_and(|evaluation| evaluation.passed())
}

pub(super) fn matching_discovery_separators(expected: &str, actual: &str) -> Vec<String> {
    crate::value_extensions::analyze_values(
        traffic_extensions::policies(),
        &traffic_value::Value::String(expected.into()),
        &traffic_value::Value::String(actual.into()),
        "",
        &json!({}),
    )
    .unwrap_or_default()
    .into_iter()
    .filter(|finding| finding.policy == "unordered-joined-string")
    .filter_map(|finding| match finding.proposal? {
        traffic_policy::Proposal::Field(value) => value
            .pointer("/options/separator")?
            .as_str()
            .map(str::to_owned),
        traffic_policy::Proposal::Document(_) => None,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_requires_a_present_separator() {
        assert!(matching_discovery_separators("alice", "alice").is_empty());
        assert_eq!(
            matching_discovery_separators("alice,bob", "bob,alice"),
            vec![",".to_string()]
        );
    }

    #[test]
    fn comparison_preserves_duplicates_and_empty_elements() {
        assert!(equal("alice,,bob,alice", "alice,bob,alice,", ","));
        assert!(!equal("alice,,bob", "alice,bob", ","));
    }
}
