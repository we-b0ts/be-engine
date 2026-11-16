//! Typed identity formats and shared candidate-local correspondence state.
use crate::comparison::Difference;
use serde_json::Value;
mod store;
pub use store::*;

fn difference(pointer: &str, reason: &str) -> Difference {
    Difference {
        pointer: pointer.into(),
        reason: reason.into(),
    }
}

/// Complete typed scalar used by the automatic case-local correspondence.
/// Format validation never removes literal prefixes or scalar types from this key.
pub fn key(value: &Value, pointer: &str) -> Result<String, Difference> {
    let valid = match value {
        Value::String(text) => text.len() <= 64 * 1024,
        Value::Number(_) | Value::Bool(_) => true,
        _ => false,
    };
    if !valid {
        return Err(difference(
            pointer,
            "identity scalar representation is invalid",
        ));
    }
    serde_json::to_string(value)
        .map_err(|_| difference(pointer, "identity scalar cannot be represented"))
}
