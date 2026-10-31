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
        r#"format: traffic-policy/v3
json:
  fields:
    /members: {kind: unordered}
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
            proof: Some(proof("original-scope")),
            when: None,
        }
        .into(),
    );
    document.rules.push(
        NativeRule {
            id: "process-config".into(),
            selector: Default::default(),
            effect: NativeEffect::ProcessOwned(n::ProcessOwnedEffect {
                task_name: None,
                source_revision: revision(),
                origin: None,
                selector: n::ProcessSelector::Http {
                    authorities: vec!["config.test".into()],
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/configuration".into()],
                },
            }),
            proof: Some(proof("original-process")),
            when: None,
        }
        .into(),
    );
    document
}

#[test]
fn source_writer_preserves_shared_revision_and_expanded_nested_proofs() {
    let mut document = base();
    document.source_revision = Some(revision());
    let original = crate::policy::render_policy(&document).unwrap();
    let baseline = crate::policy::parse_policy(&original).unwrap();
    let compiled = crate::policy::compile_policy(&baseline).unwrap();
    let mut proposed = project_source_policy(&compiled.native).unwrap();
    proposed.http.case_path_patterns.push("/added/*".into());
    let rendered = render_updated(&original, &proposed, &proof("new-observation")).unwrap();
    let after = crate::policy::parse_policy(&rendered).unwrap();
    assert_eq!(after.source_revision, baseline.source_revision);
    for rule in &baseline.rules {
        if let Some(native) = rule.as_native()
            && let n::NativeEffect::CaptureHttp(capture) = &native.effect
        {
            let updated = after
                .rules
                .iter()
                .find(|other| other.id() == rule.id())
                .unwrap()
                .as_native()
                .unwrap();
            assert_eq!(updated.selector, native.selector);
            assert_eq!(updated.when, native.when);
            assert_eq!(updated.proof, native.proof);
            let n::NativeEffect::CaptureHttp(updated) = &updated.effect else {
                panic!("recording acquisition owner");
            };
            assert_eq!(updated.source_revision, capture.source_revision);
            assert_eq!(updated.case_paths, ["/api", "/added/*"]);
            continue;
        }
        assert_eq!(
            after.rules.iter().find(|other| other.id() == rule.id()),
            Some(rule)
        );
    }
    assert!(after.rules.iter().all(|rule| rule.proof().is_none()));
    assert!(!rendered.contains("proof:"));
    assert!(!rendered.contains(" @ sha256:"));
    let authored: serde_yaml::Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(authored["recording"]["name"], "observed-case-scope");
    assert_eq!(
        after
            .rules
            .iter()
            .filter(|rule| rule
                .as_native()
                .is_some_and(|rule| matches!(rule.effect, n::NativeEffect::CaptureHttp(_))))
            .count(),
        1
    );
    let after_compiled = crate::policy::compile_policy(&after).unwrap();
    assert_eq!(
        compiled.fingerprints.runtime,
        after_compiled.fingerprints.runtime
    );
    assert_eq!(
        render_updated(
            &rendered,
            &project_source_policy(&after_compiled.native).unwrap(),
            &proof("unused")
        )
        .unwrap(),
        rendered
    );
}

#[test]
fn source_scope_update_preserves_other_effects_complete_rules_and_original_proofs() {
    let document = base();
    let original = crate::policy::render_policy(&document).unwrap();
    let document = crate::policy::parse_policy(&original).unwrap();
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
    assert!(new.proof().is_none());
    assert!(!rendered.contains("proof:"));
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
fn changed_owner_merges_file_references_under_one_document_revision() {
    let mut document = base();
    document.source_revision = Some(revision());
    let original = crate::policy::render_policy(&document).unwrap();
    let compiled = crate::policy::parse_and_compile_policy(&original).unwrap();
    let mut proposed = project_source_policy(&compiled.native).unwrap();
    if let B::Http { path_prefixes, .. } = &mut proposed.process_owned_dependencies[0] {
        path_prefixes.push("/additional".into());
    } else {
        panic!("HTTP fixture required");
    }
    let output = render_updated(&original, &proposed, &proof("new-scope")).unwrap();
    let after = crate::policy::parse_and_compile_policy(&output).unwrap();
    let projected = project_source_policy(&after.native).unwrap();
    let B::Http { path_prefixes, .. } = &projected.process_owned_dependencies[0] else {
        panic!("HTTP fixture required");
    };
    assert_eq!(path_prefixes, &["/configuration", "/additional"]);
    assert_eq!(output.matches("source_revision:").count(), 1);
    assert!(!output.contains(" @ "));
    let owner = after
        .native
        .iter()
        .find(|rule| rule.rule.id == "process-config")
        .unwrap();
    assert!(owner.rule.proof.is_none());
}

#[test]
fn changing_one_capture_preserves_existing_nested_facts_and_uses_explicit_proof_for_new_pointer() {
    let mut document = base();
    let old_pointer = Proven {
        contract: "/base_url".to_owned(),
        proof: Some(proof("url-construction")),
    };
    document.rules.push(
        NativeRule {
            id: "capture-url".into(),
            selector: Default::default(),
            when: None,
            proof: Some(proof("capture-root")),
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
    let original = crate::policy::render_policy(&document).unwrap();
    let document = crate::policy::parse_policy(&original).unwrap();
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
    assert!(changed.proof.is_none());
    let NativeEffect::CaptureHttpResponse(effect) = &changed.effect else {
        panic!("wrong effect")
    };
    let n::CaptureResponseContract::Urls { pointers } = &effect.contract else {
        panic!("wrong contract")
    };
    assert_eq!(pointers[0].contract, old_pointer.contract);
    assert_eq!(pointers[1].contract, "/logs_url");
    assert!(pointers.iter().all(|pointer| pointer.proof.is_none()));
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

#[test]
fn changing_a_response_capture_keeps_plugin_precedence_and_untouched_typed_facts() {
    let mut document = base();
    let response = |id: &str, contract| NativeRule {
        id: id.into(),
        selector: Default::default(),
        when: None,
        proof: Some(proof(id)),
        effect: NativeEffect::CaptureHttpResponse(n::CaptureResponseEffect {
            authorities: vec!["service.test".into()],
            methods: vec!["GET".into()],
            path: n::CapturePath::Pattern {
                value: "/resources/123".into(),
            },
            status_codes: vec![200],
            content_types: vec!["application/json".into()],
            contract,
        }),
    };
    document.rules.push(
        response(
            "z-primary-url",
            n::CaptureResponseContract::Urls {
                pointers: vec![Proven {
                    contract: "/base_url".into(),
                    proof: Some(proof("original-url-construction")),
                }],
            },
        )
        .into(),
    );
    document.rules.push(
        response(
            "a-fallback-plugin",
            n::CaptureResponseContract::VintageCacheConfig,
        )
        .into(),
    );
    let original = crate::policy::render_policy(&document).unwrap();
    let document = crate::policy::parse_policy(&original).unwrap();
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let target = tempfile::tempdir().unwrap();
    let directory = target.path().join(".traffic-e2e");
    std::fs::create_dir_all(&directory).unwrap();
    let policy_path = directory.join("policy.yaml");
    let project_path = directory.join("project.yaml");
    std::fs::write(
        &project_path,
        "version: 18\nproject:\n  policy: .traffic-e2e/policy.yaml\nrecorder:\n  dns_mock: {enabled: true}\n  tcp_gateway: {enabled: true, record_http: true}\n",
    )
    .unwrap();
    std::fs::write(&policy_path, &original).unwrap();
    let loaded = crate::AppConfig::load(&project_path).unwrap();
    assert_eq!(loaded.http_response_rewrite.rules[0].name, "z-primary-url");
    assert!(loaded.http_response_rewrite.rules[0].plugin.is_none());
    let mut reordered = document.clone();
    reordered.rules.swap(2, 3);
    let reordered_compiled = crate::policy::compile_policy(&reordered).unwrap();
    assert_ne!(
        compiled.fingerprints.capture,
        reordered_compiled.fingerprints.capture
    );
    assert_ne!(
        compiled.fingerprints.full,
        reordered_compiled.fingerprints.full
    );
    assert_eq!(
        compiled.fingerprints.runtime,
        reordered_compiled.fingerprints.runtime
    );
    assert_eq!(
        compiled.fingerprints.classification,
        reordered_compiled.fingerprints.classification
    );
    std::fs::write(&policy_path, serde_yaml::to_string(&reordered).unwrap()).unwrap();
    let loaded = crate::AppConfig::load(&project_path).unwrap();
    assert!(loaded.http_response_rewrite.rules[0].plugin.is_some());
    let mut unordered = document.clone();
    unordered.rules.swap(0, 1);
    assert_eq!(
        crate::policy::compile_policy(&unordered)
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
    let mut proposed = project_source_policy(&compiled.native).unwrap();
    proposed.http_response_rewrite[0].path_pattern = Some("/resources/*".into());
    let after = crate::policy::parse_policy(
        &render_updated(&original, &proposed, &proof("reviewed-dynamic-path")).unwrap(),
    )
    .unwrap();
    // The recorder chooses the first matching plugin before combining ordinary
    // URL pointers. Appending the changed URL rule would select the fallback.
    let final_source =
        project_source_policy(&crate::policy::compile_policy(&after).unwrap().native).unwrap();
    assert_eq!(final_source.http_response_rewrite[0].name, "z-primary-url");
    assert!(final_source.http_response_rewrite[0].plugin.is_none());
    assert_eq!(
        final_source.http_response_rewrite[1].name,
        "a-fallback-plugin"
    );
    for untouched in document
        .rules
        .iter()
        .filter(|rule| rule.id() != "z-primary-url")
    {
        assert_eq!(
            after.rules.iter().find(|rule| rule.id() == untouched.id()),
            Some(untouched)
        );
    }
    let changed = after
        .rules
        .iter()
        .find(|rule| rule.id() == "z-primary-url")
        .unwrap();
    assert!(changed.proof().is_none());
}
