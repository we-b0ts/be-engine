//! Read-only discovery of array ordering differences in HTTP request bodies.
use super::*;

pub(crate) mod evidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::replay::http) struct HttpUnorderedLocation {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub pointer: String,
}

use crate::replay::json_order::normalize_arrays;
use crate::replay::json_order::order_paths;

#[cfg(test)]
mod tests;
