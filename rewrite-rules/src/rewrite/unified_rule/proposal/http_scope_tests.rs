//! Shared declarations retain their explicit API scope.
use super::*;

#[test]
fn shared_docx_codec_bindings_still_require_the_current_api_issue() {
    let mut document = crate::policy::parse_policy(
        r#"format: traffic-policy/v3
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
