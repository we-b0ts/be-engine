//! Store logical interaction observations without a duplicate raw stream body.
use serde_json::{Value, json};

pub fn prepare_output(response: &mut Value) {
    if response
        .get("interaction")
        .is_some_and(|value| !value.is_null())
    {
        response["body"] = json!({"encoding":"utf8","data":"","truncated":false});
    }
}
