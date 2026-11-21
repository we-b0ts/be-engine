use super::*;
fn rule() -> serde_json::Value {
    json!({"format":"traffic-policy/v3","json":{"fields":{"/members":{"kind":"unordered"}}}})
}
#[path = "transaction.rs"]
mod transaction;
