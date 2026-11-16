use super::*;
use serde_json::json;

struct Custom;
impl EvidenceAdapter for Custom {
    fn schema(&self) -> &'static str {
        "vendor/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["vendor_event"]
    }
    fn supports_replay(&self, _: &Value) -> bool {
        true
    }
    fn process_summary_types(&self) -> &'static [&'static str] {
        &["vendor_summary"]
    }
    fn process_summary_view(&self, _: &str, value: &Value, detail_limit: usize) -> Result<Value> {
        let records = value["native_records"]
            .as_array()
            .context("vendor records are absent")?;
        Ok(
            json!({"records":records.iter().take(detail_limit).collect::<Vec<_>>(),
            "omitted_records":records.len().saturating_sub(detail_limit)}),
        )
    }
}

#[test]
fn a_registered_summary_owner_renders_its_own_bounded_view() {
    let values = BTreeMap::from([
        ("vendor_summary".into(), json!({"native_records":[1,2,3]})),
        ("historical_extension".into(), json!({"retained":true})),
    ]);
    let mut registry = EvidenceRegistry::default();
    assert_eq!(registry.process_summary_views(&values, 1).unwrap(), values);
    registry.register("vendor", Arc::new(Custom)).unwrap();
    let projected = registry.process_summary_views(&values, 1).unwrap();
    assert_eq!(
        projected["vendor_summary"],
        json!({"records":[1],"omitted_records":2})
    );
    assert_eq!(
        projected["historical_extension"],
        values["historical_extension"]
    );
    assert_eq!(values["vendor_summary"]["native_records"], json!([1, 2, 3]));
    assert!(
        registry
            .process_summary_views(&BTreeMap::from([("vendor_summary".into(), Value::Null)]), 1)
            .is_err()
    );
}
