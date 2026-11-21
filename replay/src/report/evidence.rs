//! Stored native report formats validate their own finite session obligations.
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;

pub trait SessionEvidence {
    fn validate_session(&self, report: &Value) -> Result<BTreeMap<String, usize>>;
}

pub use traffic_protocol::report::validation::{array, empty, number};
