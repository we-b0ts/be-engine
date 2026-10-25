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
async fn retired_http_ownership_cannot_survive_in_an_old_global_file() {
    let record = exchange();
    let (_root, _pages, source) = indexed(std::slice::from_ref(&record));
    let before = std::fs::read(source.path()).unwrap();
    let stamp = crate::dependency_index::FileStamp::read(source.path()).unwrap();
    let error = super::super::super::global_source::GlobalSource::load(source.path(), &[])
        .await
        .err()
        .expect("removed ownership must reject the old Global inventory");
    assert!(format!("{error:#}").contains("fresh capture is required"));
    assert_eq!(std::fs::read(source.path()).unwrap(), before);
    assert_eq!(
        crate::dependency_index::FileStamp::read(source.path()).unwrap(),
        stamp
    );

    // Semantic coverage survives a rule rename without trusting the old ID.
    let loaded =
        super::super::super::global_source::GlobalSource::load(source.path(), &[current_rule()])
            .await
            .unwrap();
    assert_eq!(loaded.http.len(), 1);
    assert_eq!(std::fs::read(source.path()).unwrap(), before);
}

#[tokio::test]
async fn an_old_rule_name_cannot_mask_a_different_physical_request() {
    for (field, value) in [
        ("authority", json!("other.example:80")),
        ("method", json!("POST")),
        ("uri", json!("/business/write")),
        ("global_dependency_matched_by", Value::Null),
    ] {
        let mut record = exchange();
        record[field] = value;
        if field == "authority" {
            record["uri"] = "http://config.api.demo.test/1/config/service".into();
        }
        let (_root, _pages, source) = indexed(&[record]);
        let error = super::super::super::global_source::GlobalSource::load(
            source.path(),
            &[current_rule()],
        )
        .await
        .err()
        .expect("current selector must cover the actual request");
        assert!(
            format!("{error:#}").contains("fresh capture is required"),
            "{field}: {error:#}"
        );
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
