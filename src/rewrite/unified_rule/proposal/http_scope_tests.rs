//! Compact HTTP declarations retain their explicit provenance-bound API scope.
use super::*;

const DOCUMENT: &str = r#"format: traffic-policy/v2
resources:
  storage: {protocol: http, endpoint: 'storage.test:9100'}
http:
  requests:
    - host: storage.test:9100
      method: POST
      path: /attachments/objects/*
      api: POST /api/attachments/*
      proof: {source: upload.py:10, fact: Source initializes storage for this attachment upload API}
      path_identity:
        segment: 2
        template: '{nonce}'
        fields:
          nonce: {hex: 12}
        references: [storage]
"#;

fn scoped() -> TrafficPolicy {
    crate::policy::parse_policy(DOCUMENT).unwrap()
}

#[test]
fn canonical_http_api_scope_survives_proposal_preparation_with_ids_and_proofs_intact() {
    let mut document = scoped();
    let original = document.clone();
    let before = crate::policy::compile_policy(&original).unwrap();
    assert!(
        crate::policy::preserves_http_api_scope(&document.rules[0], &document.resources).unwrap()
    );
    prepare_scopes(
        &mut document,
        &TrafficPolicy::default(),
        "POST /api/attachments/*",
    )
    .unwrap();
    assert_eq!(
        document, original,
        "preparation must not change the scope, proof or generated ID"
    );
    crate::policy::require_source_proofs(&document).unwrap();
    let rendered = crate::policy::render_policy(&document).unwrap();
    assert!(rendered.contains("api: POST /api/attachments/*"));
    assert_eq!(
        crate::policy::parse_and_compile_policy(&rendered)
            .unwrap()
            .fingerprints,
        before.fingerprints
    );
    let restored = crate::policy::parse_policy(&rendered).unwrap();
    assert_eq!(restored.rules[0].id(), document.rules[0].id());
}

#[test]
fn ordinary_new_raw_http_rules_still_become_resource_wide() {
    for id in [
        "plain-http-rule".to_owned(),
        format!("http.request.{}", "0".repeat(64)),
    ] {
        let mut document = scoped();
        let PolicyRule::Native(rule) = &mut document.rules[0] else {
            unreachable!()
        };
        rule.id = id.clone();
        let proof = rule.proof.clone();
        assert!(
            !crate::policy::preserves_http_api_scope(&document.rules[0], &document.resources)
                .unwrap()
        );
        prepare_scopes(
            &mut document,
            &TrafficPolicy::default(),
            "POST /api/attachments/*",
        )
        .unwrap();
        let rule = document.rules[0].as_native().unwrap();
        assert!(rule.selector.api.is_none());
        assert_eq!(rule.id, id);
        assert_eq!(rule.proof, proof);
        crate::policy::compile_policy(&document).unwrap();
    }
}

#[test]
fn stale_generated_hash_does_not_preserve_a_modified_http_selector() {
    let mut document = scoped();
    let PolicyRule::Native(rule) = &mut document.rules[0] else {
        unreachable!()
    };
    let original_id = rule.id.clone();
    rule.selector.path = Some("/different/*".into());
    assert!(
        !crate::policy::preserves_http_api_scope(&document.rules[0], &document.resources).unwrap()
    );
    prepare_scopes(
        &mut document,
        &TrafficPolicy::default(),
        "POST /api/attachments/*",
    )
    .unwrap();
    let rule = document.rules[0].as_native().unwrap();
    assert!(rule.selector.api.is_none());
    assert_eq!(
        rule.id, original_id,
        "scope normalization must not mint a replacement generated ID"
    );
}

#[test]
fn canonical_http_api_scope_cannot_be_submitted_for_a_different_issue() {
    let mut document = scoped();
    let original = document.clone();
    assert!(prepare_scopes(&mut document, &TrafficPolicy::default(), "POST /other").is_err());
    assert_eq!(document, original);
}

#[test]
fn shared_docx_codec_bindings_still_require_the_current_api_issue() {
    let mut document = crate::policy::parse_policy(
        r#"format: traffic-policy/v2
docx:
  fields:
    - {kind: timestamp, part: docProps/core.xml, element: 'dcterms:created', format: rfc3339}
api:
  GET /one: {response: {body: {codec: docx}}}
  GET /two: {response: {body: {codec: docx}}}
"#,
    )
    .unwrap();
    assert!(prepare_scopes(&mut document, &TrafficPolicy::default(), "GET /one").is_err());
}
