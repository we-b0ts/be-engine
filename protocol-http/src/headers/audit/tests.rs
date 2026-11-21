use super::*;
use serde_json::json;

#[test]
fn bounds_plaintext_observations_and_protects_encrypted_custom_fields() {
    let long = vec!["v".repeat(1000); 20];
    let value = serde_json::to_value(observation("business-context", Some(&long), false)).unwrap();
    assert_eq!(value["values"].as_array().unwrap().len(), 8);
    assert_eq!(value["values"][0].as_str().unwrap().len(), 256);
    assert_eq!(
        serde_json::to_value(observation("private-context", Some(&long), true)).unwrap()["values"],
        json!(["<redacted>"])
    );
}
