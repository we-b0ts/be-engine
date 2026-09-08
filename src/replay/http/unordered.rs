//! Explicit unordered JSON arrays in outbound HTTP dependency requests.
use super::*;
use crate::replay::policy::{response_pointer_matches, validate_json_pointer};
use anyhow::ensure;

pub(crate) mod evidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpUnorderedSelector {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub pointer: String,
}

impl HttpUnorderedSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        self.endpoint().validate()?;
        validate_json_pointer(&self.pointer)
    }

    fn endpoint(&self) -> super::selector::HttpDependencySelector {
        super::selector::HttpDependencySelector {
            host: self.host.clone(),
            port: self.port,
            method: self.method.clone(),
            path: self.path.clone(),
        }
    }

    fn selects(&self, candidate: &Self) -> bool {
        self.host.eq_ignore_ascii_case(&candidate.host)
            && self.port == candidate.port
            && self.method.eq_ignore_ascii_case(&candidate.method)
            && self.path == candidate.path
            && response_pointer_matches(&self.pointer, &candidate.pointer)
    }
}

pub(in crate::replay) use crate::replay::json_order::normalize_arrays;
use crate::replay::json_order::order_paths;

#[cfg(test)]
mod tests;
