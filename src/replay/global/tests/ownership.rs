//! Current ownership must cover old Global HTTP records before registration.
use super::*;

fn exchange() -> Value {
    json!({"event_type":"http_exchange","scheme":"http",
        "authority":"config.api.demo.test:80","method":"GET","uri":"/1/config/service?service=example",
        "request_headers":{},"request_body":capture(""),"response_status":200,
        "response_headers":{"content-type":["application/json"]},"response_body":capture("{\"servers\":[]}"),
        "global_dependency_reason":"background_rule","global_dependency_phase":"runtime",
        "global_dependency_matched_by":"breeze_vintage"})
}

fn current_rule() -> crate::BackgroundDependencyRuleConfig {
    crate::BackgroundDependencyRuleConfig::Http {
        name: "renamed-explicit-config-poller".into(),
        authorities: vec!["config.api.demo.test".into()],
        methods: vec!["GET".into()],
        path_prefixes: vec!["/1/config/service".into()],
        source_revision: "sha256:215629d09ed4cf9bbc8bcc84371e74de49c9e21e3247f4183861b13c3e0c5fd7"
            .into(),
        source_evidence:
            "An explicitly retained Source worker polls this HTTP resource independently of Cases"
                .into(),
    }
}

#[tokio::test]
async fn legacy_rule_annotations_do_not_control_finite_startup_inventory() {
    let record = exchange();
    let (_root, _pages, source) = indexed(std::slice::from_ref(&record));
    let before = std::fs::read(source.path()).unwrap();
    for rules in [vec![], vec![current_rule()]] {
        let loaded = super::super::super::global_source::GlobalSource::load(source.path(), &rules)
            .await
            .unwrap();
        assert_eq!(loaded.http.len(), 1);
    }
    assert_eq!(std::fs::read(source.path()).unwrap(), before);
}

#[tokio::test]
async fn startup_inventory_does_not_depend_on_a_retired_background_selector() {
    for (field, value) in [
        ("authority", json!("other.example:80")),
        ("method", json!("POST")),
        ("uri", json!("/business/write")),
        ("global_dependency_matched_by", Value::Null),
    ] {
        let mut record = exchange();
        record[field] = value;
        let (_root, _pages, source) = indexed(&[record]);
        let loaded = super::super::super::global_source::GlobalSource::load(
            source.path(),
            &[current_rule()],
        )
        .await
        .unwrap();
        assert_eq!(loaded.http.len(), 1);
    }
}

#[tokio::test]
async fn bootstrap_http_without_background_ownership_keeps_its_original_role() {
    let mut record = exchange();
    record["global_dependency_reason"] = "bootstrap_window".into();
    record["global_dependency_phase"] = "bootstrap".into();
    record["global_dependency_matched_by"] = Value::Null;
    let (_root, _pages, source) = indexed(&[record]);
    let loaded = super::super::super::global_source::GlobalSource::load(source.path(), &[])
        .await
        .unwrap();
    assert_eq!(loaded.http.len(), 1);
}
