use super::*;
use crate::policy::native::{NativeEffect, NativeRule, Proven};

fn proof(label: &str) -> Proof {
    Proof {
        source: format!("src/source.rs:{label}"),
        fact: format!("Source fact for {label}"),
    }
}
fn revision() -> String {
    format!("sha256:{}", "1".repeat(64))
}
fn base() -> TrafficPolicy {
    let mut document = crate::policy::parse_policy(
        r#"format: traffic-policy/v1
rules:
  - id: response-members
    surface: api.response
    match: {api: GET /api}
    slot: body
    codec: json
    contract: {/members: {kind: unordered}}
    proof: {source: 'src/api:members', fact: 'Caller consumes the complete collection as a set'}
"#,
    )
    .unwrap();
    document.rules.push(
        NativeRule {
            id: "observed-case-scope".into(),
            selector: Default::default(),
            effect: NativeEffect::CaptureHttp(n::CaptureHttpEffect {
                source_revision: revision(),
                case_paths: vec!["/api".into()],
            }),
            proof: proof("original-scope"),
            when: None,
        }
        .into(),
    );
    document.rules.push(
        NativeRule {
            id: "process-config".into(),
            selector: Default::default(),
            effect: NativeEffect::ProcessOwned(n::ProcessOwnedEffect {
                source_revision: revision(),
                origin: None,
                selector: n::ProcessSelector::Http {
                    authorities: vec!["config.test".into()],
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/configuration".into()],
                },
            }),
            proof: proof("original-process"),
            when: None,
        }
        .into(),
    );
    document
}

#[test]
fn source_scope_update_preserves_other_effects_complete_rules_and_original_proofs() {
    let document = base();
    let original = serde_yaml::to_string(&document).unwrap();
    let before = crate::policy::compile_policy(&document).unwrap();
    let mut proposed = project_source_policy(&before.native).unwrap();
    proposed.http.case_path_patterns.push("/new/*".into());
    let update = proof("current-observation");
    let rendered = render_updated(&original, &proposed, &update).unwrap();
    let after = crate::policy::parse_policy(&rendered).unwrap();
    for existing in &document.rules {
        assert_eq!(
            after.rules.iter().find(|rule| rule.id() == existing.id()),
            Some(existing)
        );
    }
    let new = after
        .rules
        .iter()
        .find(|rule| rule.id() == "source-capture-http")
        .unwrap();
    assert_eq!(new.proof(), &update);
    let compiled = crate::policy::compile_policy(&after).unwrap();
    assert_eq!(compiled.fingerprints.runtime, before.fingerprints.runtime);
    assert_eq!(
        compiled.fingerprints.classification,
        before.fingerprints.classification
    );
    assert_ne!(compiled.fingerprints.capture, before.fingerprints.capture);
    assert_eq!(
        render_updated(
            &rendered,
            &project_source_policy(&compiled.native).unwrap(),
            &proof("unused")
        )
        .unwrap(),
        rendered
    );
}

#[test]
fn changing_one_capture_preserves_existing_nested_facts_and_uses_explicit_proof_for_new_pointer() {
    let mut document = base();
    let old_pointer = Proven {
        contract: "/base_url".to_owned(),
        proof: proof("url-construction"),
    };
    document.rules.push(
        NativeRule {
            id: "capture-url".into(),
            selector: Default::default(),
            when: None,
            proof: proof("capture-root"),
            effect: NativeEffect::CaptureHttpResponse(n::CaptureResponseEffect {
                authorities: vec!["service.test".into()],
                methods: vec!["GET".into()],
                path: n::CapturePath::Pattern {
                    value: "/resources/*".into(),
                },
                status_codes: vec![200],
                content_types: vec!["application/json".into()],
                contract: n::CaptureResponseContract::Urls {
                    pointers: vec![old_pointer.clone()],
                },
            }),
        }
        .into(),
    );
    let original = serde_yaml::to_string(&document).unwrap();
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let mut proposed = project_source_policy(&compiled.native).unwrap();
    proposed.http_response_rewrite[0]
        .pointers
        .push("/logs_url".into());
    let update = proof("new-url-construction");
    let after =
        crate::policy::parse_policy(&render_updated(&original, &proposed, &update).unwrap())
            .unwrap();
    let changed = after
        .rules
        .iter()
        .find(|rule| rule.id() == "capture-url")
        .unwrap()
        .as_native()
        .unwrap();
    assert!(changed.proof.source.contains(&update.source));
    assert!(changed.proof.fact.contains(&update.fact));
    assert!(changed.proof.fact.contains(&proof("capture-root").fact));
    let NativeEffect::CaptureHttpResponse(effect) = &changed.effect else {
        panic!("wrong effect")
    };
    let n::CaptureResponseContract::Urls { pointers } = &effect.contract else {
        panic!("wrong contract")
    };
    assert_eq!(pointers[0], old_pointer);
    assert_eq!(pointers[1].proof, update);
}

#[test]
fn initialization_has_one_empty_typed_policy_and_no_project_specific_ownership() {
    let raw = empty_policy().unwrap();
    let document = crate::policy::parse_policy(&raw).unwrap();
    assert!(document.rules.is_empty());
    let source = parse_source_policy(&raw).unwrap();
    assert!(source.process_owned_dependencies.is_empty());
    assert!(source.http.case_path_patterns.is_empty());
}
