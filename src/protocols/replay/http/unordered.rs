//! Read-only discovery of array ordering differences in HTTP request bodies.
use super::*;

pub(crate) mod evidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::protocols::replay::http) struct HttpUnorderedLocation {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub pointer: String,
}

fn normalize_arrays(source: &mut Value, target: &mut Value, pattern: &str) -> bool {
    crate::value_extensions::normalize_policy_locations("unordered", source, target, pattern)
}

fn order_paths(source: &Value, target: &Value, pointer: &str, paths: &mut Vec<String>) {
    paths.extend(
        crate::value_extensions::policy_locations("unordered", source, target, !pointer.is_empty())
            .into_iter()
            .map(|path| format!("{pointer}{path}")),
    );
}

#[cfg(test)]
mod tests;
