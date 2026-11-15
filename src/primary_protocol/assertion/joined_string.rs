/// Separators considered when diagnosing string values that encode an
/// unordered collection. Rules may use any validated separator; discovery is
/// deliberately limited to common source-level join separators.
pub(super) const DISCOVERY_SEPARATORS: [&str; 3] = [",", ";", "|"];

pub(super) fn canonicalize(value: &str, separator: &str) -> String {
    let mut parts = value.split(separator).collect::<Vec<_>>();
    parts.sort_unstable();
    parts.join(separator)
}

pub(super) fn equal(expected: &str, actual: &str, separator: &str) -> bool {
    canonicalize(expected, separator) == canonicalize(actual, separator)
}

pub(super) fn matching_discovery_separators(expected: &str, actual: &str) -> Vec<String> {
    DISCOVERY_SEPARATORS
        .into_iter()
        .filter(|separator| {
            let expected_parts = expected.split(separator).count();
            let actual_parts = actual.split(separator).count();
            (expected_parts >= 2 || actual_parts >= 2) && equal(expected, actual, separator)
        })
        .map(str::to_string)
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
