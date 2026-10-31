use super::super::tests::{args, rule, runtime, target};
use super::*;
use serde_json::json;

fn window() -> ReplayDependencyRule {
    rule(
        json!({"key":{"prefix":"rate:"},"key_contract":{"kind":"time_window","window_seconds":60},
        "commands":[{"command":"INCRBY","argument_values":{}},{"command":"EXPIRE","argument_values":{}}]}),
    )
}
fn capture() -> ReplayDependencyRule {
    rule(
        json!({"key":{"prefix":"sessions:"},"key_contract":{"kind":"capture","template":"sessions:{value}","format":{"kind":"hex","bytes":2}},
        "commands":[{"command":"SET","argument_values":{"1":{"json":{
            "/id":{"identity":{"template":"{value}"}},
            "/expires_at":{"time":"preserve_relative","format":"unix_seconds"}
        }}}}]}),
    )
}

#[test]
fn independent_random_json_tokens_compose_with_key_capture_and_time_contracts() {
    let mut selected = serde_json::to_value(capture()).unwrap();
    selected["redis"]["commands"][0]["argument_values"]["1"]["json"]["/poll_token"] =
        json!({"random":{"format":"base64url","length":43}});
    let selected: ReplayDependencyRule = serde_json::from_value(selected).unwrap();
    validate(&selected).unwrap();
    let runtime = runtime(selected);
    use base64::Engine as _;
    let encode = |byte| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]);
    let source = json!({"id":"aabb","poll_token":encode(1),"expires_at":1300,"status":"pending"})
        .to_string();
    let actual = json!({"id":"1122","poll_token":encode(2),"expires_at":2300,"status":"pending"})
        .to_string();
    compare(
        &runtime,
        "SET",
        &["sessions:aabb", &source, "EX", "300"],
        &["sessions:1122", &actual, "EX", "300"],
    )
    .unwrap();
    for (pointer, value) in [
        ("/poll_token", json!("a".repeat(42))),
        ("/poll_token", json!("/".repeat(43))),
        ("/poll_token", json!(format!("{}B", "A".repeat(42)))),
        ("/poll_token", json!(7)),
        ("/status", json!("done")),
        ("/expires_at", json!(2310)),
        ("/id", json!("3344")),
    ] {
        let mut changed: serde_json::Value = serde_json::from_str(&actual).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            compare(
                &runtime,
                "SET",
                &["sessions:aabb", &source, "EX", "300"],
                &["sessions:1122", &changed.to_string(), "EX", "300"]
            )
            .is_err()
        );
    }
    assert!(
        compare(
            &runtime,
            "SET",
            &["sessions:aabb", &source, "EX", "300"],
            &["sessions:1122", &actual, "EX", "301"]
        )
        .is_err()
    );
}
fn compare(
    runtime: &RequestContracts,
    command: &str,
    source: &[&str],
    actual: &[&str],
) -> Result<Decision> {
    runtime
        .preview_redis("case", &target(), 0, command, &args(source), &args(actual))
        .expect("selected key contract")
}

fn prefixed_global_runtime() -> RequestContracts {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
resources:
  cache: {protocol: redis, endpoint: 'cache.test:6379', database: 0}
json:
  fields:
    /session_id: {kind: identity, formats: [{prefix: vnc-, hex: 4}]}
rules:
- id: prefixed-key
  match:
    resource: cache
    key: {kind: affix, prefix: 'sessions:', suffix: ''}
  effect:
    kind: redis_sequence
    key: {kind: capture, template: 'sessions:vnc-{value}', format: {kind: hex, bytes: 2}}
    commands: [{operation: SET, arguments: {}}]
"#,
    )
    .unwrap();
    let mut projection =
        crate::replay::policy::native_projection::project_native(&compiled.native).unwrap();
    let mut owner = runtime(projection.document.dependency_rules.remove(0));
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner
}

#[test]
fn complete_prefixed_key_identity_and_global_json_share_one_atomic_correspondence() {
    let owner = prefixed_global_runtime();
    let source = [
        "sessions:vnc-ab12",
        r#"{"session_id":"vnc-ab12","stable":true}"#,
        "EX",
        "60",
    ];
    for (key, body, ttl) in [
        (
            "sessions:vnc-cd34",
            r#"{"session_id":"vnc-ef56","stable":true}"#,
            "60",
        ),
        (
            "sessions:vnc-cd34",
            r#"{"session_id":"vnc-cd34","stable":false}"#,
            "60",
        ),
        (
            "sessions:vnc-cd34",
            r#"{"session_id":"vnc-cd34","stable":true}"#,
            "61",
        ),
    ] {
        assert!(compare(&owner, "SET", &source, &[key, body, "EX", ttl]).is_err());
        assert!(owner.key_binding_report().is_empty());
        assert!(!owner.has_identities("case"));
    }
    let actual = [
        "sessions:vnc-cd34",
        r#"{"session_id":"vnc-cd34","stable":true}"#,
        "EX",
        "60",
    ];
    let accepted = compare(&owner, "SET", &source, &actual).unwrap();
    assert!(
        !owner.has_identities("case"),
        "preview cannot publish key or JSON identities"
    );
    owner.commit(accepted).unwrap();
    assert!(
        owner
            .knows_identity_value("case", &json!("vnc-ab12"), &json!("vnc-cd34"))
            .unwrap()
    );
    assert!(
        owner
            .knows_identity_value("case", &json!("ab12"), &json!("cd34"))
            .unwrap()
    );
    let target = target();
    let context = RedisRequestContext::without_exchange("case", &target, 0, "HSET");
    for (token, passes) in [("vnc-cd34", true), ("vnc-ef56", false)] {
        let body = json!({"session_id":token,"stable":true}).to_string();
        assert_eq!(
            owner
                .preview_redis_context(
                    &context,
                    &args(&["references", "field", source[1]]),
                    &args(&["references", "field", &body])
                )
                .unwrap()
                .is_ok(),
            passes
        );
    }
}

#[test]
fn a_preceding_json_identity_rejects_a_conflicting_prefixed_key_without_partial_capture() {
    let owner = prefixed_global_runtime();
    let target = target();
    let context = RedisRequestContext::without_exchange("case", &target, 0, "HSET");
    let source = r#"{"session_id":"vnc-ab12","stable":true}"#;
    let actual = r#"{"session_id":"vnc-cd34","stable":true}"#;
    owner
        .commit(
            owner
                .preview_redis_context(
                    &context,
                    &args(&["references", "field", source]),
                    &args(&["references", "field", actual]),
                )
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert!(
        compare(
            &owner,
            "SET",
            &["sessions:vnc-ab12", source],
            &[
                "sessions:vnc-ef56",
                r#"{"session_id":"vnc-ef56","stable":true}"#
            ]
        )
        .is_err()
    );
    assert!(owner.key_binding_report().is_empty());
    assert!(
        !owner
            .knows_identity_value("case", &json!("ab12"), &json!("ef56"))
            .unwrap()
    );
    assert!(
        compare(
            &owner,
            "SET",
            &["sessions:vnc-ab12", source],
            &["sessions:vnc-cd34", actual]
        )
        .is_ok()
    );
}

#[test]
fn time_window_checks_own_clocks_stable_key_and_pipeline_sequence() {
    let selected = window();
    validate(&selected).unwrap();
    let runtime = runtime(selected);
    let source = ["rate:user:16", "1"];
    let actual = ["rate:user:33", "1"];
    for bad in [
        ["rate:other:33", "1"],
        ["rate:user:34", "1"],
        ["rate:user:033", "1"],
        ["rate:user:33", "2"],
    ] {
        assert!(compare(&runtime, "INCRBY", &source, &bad).is_err());
    }
    assert!(compare(&runtime, "EXPIRE", &[source[0], "61"], &[actual[0], "61"]).is_err());
    runtime
        .commit(compare(&runtime, "INCRBY", &source, &actual).unwrap())
        .unwrap();
    assert!(compare(&runtime, "EXPIRE", &[source[0], "61"], &[actual[0], "62"]).is_err());
    runtime
        .commit(compare(&runtime, "EXPIRE", &[source[0], "61"], &[actual[0], "61"]).unwrap())
        .unwrap();
    assert!(compare(&runtime, "INCRBY", &source, &actual).is_ok());
    runtime.set_request_times(
        "case",
        crate::replay::assertion::RequestTimes {
            source: Some(DateTime::from_timestamp(1000, 0).unwrap()),
            target: None,
        },
    );
    assert!(compare(&runtime, "INCRBY", &source, &source).is_err());
}

#[test]
fn boundary_window_still_requires_same_target_key_for_the_sequence() {
    let runtime = runtime(window());
    runtime.set_request_times(
        "case",
        crate::replay::assertion::RequestTimes {
            source: Some(DateTime::from_timestamp(1019, 0).unwrap()),
            target: Some(DateTime::from_timestamp(2039, 0).unwrap()),
        },
    );
    runtime
        .commit(compare(&runtime, "INCRBY", &["rate:x:16", "1"], &["rate:x:33", "1"]).unwrap())
        .unwrap();
    assert!(
        compare(
            &runtime,
            "EXPIRE",
            &["rate:x:16", "61"],
            &["rate:x:34", "61"]
        )
        .is_err()
    );
    assert!(
        compare(
            &runtime,
            "EXPIRE",
            &["rate:x:16", "61"],
            &["rate:x:33", "61"]
        )
        .is_ok()
    );
}

#[test]
fn key_and_json_identity_and_time_are_validated_atomically() {
    let selected = capture();
    validate(&selected).unwrap();
    let runtime = runtime(selected);
    let source = [
        "sessions:ab12",
        r#"{"id":"ab12","expires_at":4600,"owner":7}"#,
        "EX",
        "3600",
    ];
    for (key, body, ttl) in [
        (
            "sessions:cd34",
            r#"{"id":"bad","expires_at":5600,"owner":7}"#,
            "3600",
        ),
        (
            "sessions:cd34",
            r#"{"id":"cd34","expires_at":5600,"owner":8}"#,
            "3600",
        ),
        (
            "sessions:cd34",
            r#"{"id":"cd34","expires_at":5606,"owner":7}"#,
            "3600",
        ),
        (
            "sessions:CD34",
            r#"{"id":"CD34","expires_at":5600,"owner":7}"#,
            "3600",
        ),
        (
            "sessions:cd34",
            r#"{"id":"cd34","expires_at":5600,"owner":7}"#,
            "300",
        ),
    ] {
        assert!(compare(&runtime, "SET", &source, &[key, body, "EX", ttl]).is_err());
        assert!(runtime.key_binding_report().is_empty());
        assert!(!runtime.has_identities("case"));
    }
    let actual = [
        "sessions:cd34",
        r#"{"owner":7,"expires_at":5600,"id":"cd34"}"#,
        "EX",
        "3600",
    ];
    let decision = compare(&runtime, "SET", &source, &actual).unwrap();
    assert!(runtime.key_binding_report().is_empty());
    runtime.commit(decision).unwrap();
    assert!(runtime.has_identities("case"));
    let global_pair = crate::value_contract::identities::IdentityPair {
        source: serde_json::to_string("ab12").unwrap(),
        target: serde_json::to_string("other-target").unwrap(),
    };
    assert!(
        runtime
            .preview_identity_pairs("case", &[global_pair])
            .is_err()
    );
    let reports = runtime.key_binding_report();
    assert_eq!(reports.len(), 1);
    let public = serde_json::to_string(&reports).unwrap();
    assert!(!public.contains("ab12") && !public.contains("cd34"));
    assert!(
        compare(
            &runtime,
            "SET",
            &source,
            &[
                "sessions:ef56",
                r#"{"id":"ef56","expires_at":5600,"owner":7}"#,
                "EX",
                "3600"
            ]
        )
        .is_err()
    );
    let other = [
        "sessions:ef56",
        r#"{"id":"ef56","expires_at":4600,"owner":7}"#,
        "EX",
        "3600",
    ];
    assert!(compare(&runtime, "SET", &other, &actual).is_err());
    runtime.begin_case("case");
    assert!(runtime.key_binding_report().is_empty());
}

#[test]
fn later_references_need_committed_capture_and_can_verify_sha256_derivation() {
    let mut selected = capture();
    let reference = rule(
        json!({"key":{"prefix":"tickets:"},"key_contract":{"kind":"capture","template":"tickets:{value}","format":{"kind":"hex","bytes":2}},
        "commands":[{"command":"SET","argument_values":{"1":{"json":{
            "/session_id":{"identity":{"template":"session-{value}"}}
        }}}}]}),
    );
    let runtime = runtime(selected.clone());
    let source = [
        "tickets:aa11",
        r#"{"session_id":"session-ab12"}"#,
        "EX",
        "60",
    ];
    let actual = [
        "tickets:bb22",
        r#"{"session_id":"session-cd34"}"#,
        "EX",
        "60",
    ];
    let selector = match &reference.redis {
        Some(super::super::super::redis_value::RedisSelector::Requests(s)) => s,
        _ => unreachable!(),
    };
    assert!(
        runtime
            .compare_redis(
                &super::super::RedisRequestContext::without_exchange("case", &target(), 0, "SET"),
                &reference,
                selector,
                &args(&source),
                &args(&actual)
            )
            .is_err()
    );
    runtime
        .commit(
            compare(
                &runtime,
                "SET",
                &[
                    "sessions:ab12",
                    r#"{"id":"ab12","expires_at":4600}"#,
                    "EX",
                    "3600",
                ],
                &[
                    "sessions:cd34",
                    r#"{"id":"cd34","expires_at":5600}"#,
                    "EX",
                    "3600",
                ],
            )
            .unwrap(),
        )
        .unwrap();
    runtime
        .commit(
            runtime
                .compare_redis(
                    &super::super::RedisRequestContext::without_exchange(
                        "case",
                        &target(),
                        0,
                        "SET",
                    ),
                    &reference,
                    selector,
                    &args(&source),
                    &args(&actual),
                )
                .unwrap(),
        )
        .unwrap();
    let restored = super::super::tests::runtime(selected.clone());
    restored
        .restore_key_binding_proofs(
            &json!({"replay_policy":{"key_bindings":runtime.key_binding_report()}}),
        )
        .unwrap();
    assert!(
        restored
            .compare_redis(
                &super::super::RedisRequestContext::without_exchange("case", &target(), 0, "SET"),
                &reference,
                selector,
                &args(&source),
                &args(&actual)
            )
            .is_ok()
    );
    let mut decision = Decision::default();
    let ref_hash = IdentityReference {
        template: "hash:{value}".into(),
        transform: Transform::Sha256,
    };
    assert!(
        restored
            .compare_identity(
                "case",
                &selected,
                0,
                &ref_hash,
                &format!("hash:{:x}", Sha256::digest(b"ab12")),
                &format!("hash:{:x}", Sha256::digest(b"cd34")),
                &mut decision
            )
            .is_ok()
    );
    selected.target.port = Some(6380);
    assert!(
        restored
            .compare_identity(
                "case",
                &selected,
                0,
                &ref_hash,
                &format!("hash:{:x}", Sha256::digest(b"ab12")),
                &format!("hash:{:x}", Sha256::digest(b"cd34")),
                &mut decision
            )
            .is_ok()
    );
}

#[test]
fn malformed_or_conflicting_committed_proofs_are_rejected() {
    let proof = KeyBindingReport {
        case_id: "case".into(),
        host: "cache.test".into(),
        port: 6379,
        database: 0,
        username: None,
        source_fingerprint: fingerprint("source"),
        target_fingerprint: fingerprint("actual"),
    };
    let runtime = runtime(capture());
    runtime
        .restore_key_binding_proofs(&json!({"replay_policy":{"key_bindings":[proof]}}))
        .unwrap();
    let mut changed = proof.clone();
    changed.target_fingerprint = fingerprint("other-target");
    let mut collapsed = proof.clone();
    collapsed.source_fingerprint = fingerprint("other-source");
    for wrong in [changed, collapsed] {
        assert!(
            runtime
                .restore_key_binding_proofs(&json!({"replay_policy":{"key_bindings":[wrong]}}))
                .is_err()
        );
    }
    let mut wrong = proof.clone();
    wrong.source_fingerprint = "not-a-hash".into();
    let fresh = super::super::tests::runtime(capture());
    assert!(
        fresh
            .restore_key_binding_proofs(&json!({"replay_policy":{"key_bindings":[proof, wrong]}}))
            .is_err()
    );
    assert!(fresh.state.lock().unwrap().key_binding_proofs.is_empty());
    assert!(
        runtime
            .restore_key_binding_proofs(&json!({"replay_policy":{"key_bindings":[wrong]}}))
            .is_err()
    );
}

#[test]
fn shaped_key_capture_preserves_fixed_affixes_and_json_identity() {
    let mut selected = capture();
    let Some(super::super::super::redis_value::RedisSelector::Requests(selector)) =
        &mut selected.redis
    else {
        unreachable!()
    };
    selector.key_contract = Some(KeyContract::Capture {
        template: "sessions:nonce-{value}:meta".into(),
        format: KeyFormat::Base64url { bytes: 18 },
    });
    validate(&selected).unwrap();
    let runtime = runtime(selected);
    let a = URL_SAFE_NO_PAD.encode([1u8; 18]);
    let b = URL_SAFE_NO_PAD.encode([2u8; 18]);
    let source = [
        format!("sessions:nonce-{a}:meta"),
        format!(r#"{{"id":"{a}","expires_at":4600}}"#),
    ];
    let actual = [
        format!("sessions:nonce-{b}:meta"),
        format!(r#"{{"id":"{b}","expires_at":5600}}"#),
    ];
    runtime
        .commit(
            compare(
                &runtime,
                "SET",
                &[&source[0], &source[1]],
                &[&actual[0], &actual[1]],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        compare(
            &runtime,
            "SET",
            &[&source[0], &source[1]],
            &[&format!("sessions:nonce-{b}:other"), &actual[1]]
        )
        .is_err()
    );
    assert!(shaped(
        "ad7a59be-4044-4cb5-803a-a75a021bc412",
        &KeyFormat::UuidV4
    ));
    assert!(!shaped(
        "ad7a59be-4044-1cb5-803a-a75a021bc412",
        &KeyFormat::UuidV4
    ));
}

#[test]
fn key_contract_rejects_overlapping_legacy_capture_even_at_a_disjoint_json_field() {
    let mut document: super::super::super::config::ReplayPolicyDocument =
        serde_yaml::from_str("version: 3\nexpected_response: assertions_only\n").unwrap();
    document.dependency_rules.push(capture());
    document.dynamic_values.push(serde_json::from_value(json!({
        "id":"other-id", "api":"/presence/*", "targets":[{"host":"cache.test","port":6379}],
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
            "key":{"prefix":"sessions:"},"command":"SET","argument_index":1,"json_pointer":"/other_id"},
        "source_evidence":"Session:store generates an independent other_id"
    })).unwrap());
    assert!(validate_overlaps(&document).is_err());
}
