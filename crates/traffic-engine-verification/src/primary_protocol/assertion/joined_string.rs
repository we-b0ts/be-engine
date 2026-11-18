//! Application installation of shared joined-value semantics.
pub(super) fn equal(source: &str, target: &str, separator: &str) -> bool {
    traffic_policy_content::joined_string::equal(
        traffic_extensions::policies(),
        source,
        target,
        separator,
    )
}
