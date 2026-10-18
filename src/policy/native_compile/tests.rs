use std::collections::BTreeMap;

use super::*;
mod redis_sequence;
use crate::policy::{Database, Endpoint, Resource};

fn proven<T>(contract: T) -> Proven<T> {
    Proven {
        contract,
        proof: Proof {
            source: "source.rs:1".into(),
            fact: "one Source constructor supplies this field".into(),
        },
    }
}

fn path_rule() -> NativeRule {
    let resource = Resource {
        protocol: Protocol::Http,
        endpoint: Endpoint {
            host: "store.example".into(),
            port: 80,
        },
        database: None,
        username: None,
    };
    NativeRule {
        id: "storage-key".into(),
        proof: proven(()).proof,
        when: None,
        selector: NativeMatch {
            api: Some("POST /upload".into()),
            resource: Some(resource.clone()),
            operation: Some("PUT".into()),
            path: Some("/*".into()),
            ..Default::default()
        },
        effect: NativeEffect::Identity(IdentityEffect {
            value_type: IdentityType::String,
            format: None,
            references: vec![proven(IdentityTarget { resource })],
            capture: IdentityCapture::HttpPath {
                segment: PathIdentitySegment {
                    index: 0,
                    template: "{proof}_{fixed}".into(),
                    fields: BTreeMap::from([
                        (
                            "proof".into(),
                            proven(PathIdentityField::Random {
                                format: PathRandomFormat::Hex,
                                length: 12,
                            }),
                        ),
                        ("fixed".into(), proven(PathIdentityField::Exact)),
                    ]),
                },
            },
        }),
    }
}

#[test]
fn path_timestamp_defaults_and_explicit_modes_have_distinct_semantic_fingerprints() {
    let mut rule = path_rule();
    let timestamp = serde_json::json!({
        "kind":"timestamp", "format":"%Y%m%d%H%M%S"
    });
    let NativeEffect::Identity(effect) = &mut rule.effect else {
        unreachable!()
    };
    let IdentityCapture::HttpPath { segment } = &mut effect.capture else {
        unreachable!()
    };
    segment.fields.get_mut("proof").unwrap().contract = serde_json::from_value(timestamp).unwrap();
    let default = compile_native(&rule).unwrap();
    let mut explicit = serde_json::to_value(&rule).unwrap();
    let mode = "/effect/capture/segment/fields/proof/contract/mode";
    assert_eq!(
        explicit.pointer(mode).unwrap(),
        "preserve_or_request_window"
    );
    assert_eq!(
        explicit
            .pointer("/effect/capture/segment/fields/proof/contract/timezone")
            .unwrap(),
        "UTC"
    );
    let compatible: NativeRule = serde_json::from_value(explicit.clone()).unwrap();
    assert_eq!(
        compile_native(&compatible).unwrap().fingerprint,
        default.fingerprint
    );
    *explicit.pointer_mut(mode).unwrap() = serde_json::json!("request_window");
    let strict: NativeRule = serde_json::from_value(explicit).unwrap();
    assert_ne!(
        compile_native(&strict).unwrap().fingerprint,
        default.fingerprint
    );
    assert_eq!(
        serde_yaml::from_str::<NativeRule>(&serde_yaml::to_string(&strict).unwrap()).unwrap(),
        strict
    );
}

#[test]
fn response_header_date_defaults_to_utc_without_timezone_configuration() {
    let mut rule = path_rule();
    rule.selector.resource = None;
    rule.selector.operation = None;
    rule.selector.path = None;
    rule.effect = NativeEffect::ResponseHeaderDate(
        serde_json::from_value(serde_json::json!({
            "header":"content-disposition", "parameter":"filename", "format":"%Y-%m-%d"
        }))
        .unwrap(),
    );
    let compiled = compile_native(&rule).unwrap();
    let NativeEffect::ResponseHeaderDate(effect) = &compiled.rule.effect else {
        unreachable!()
    };
    assert_eq!(effect.timezone, "+00:00");
}

#[test]
fn native_relative_times_accept_omitted_offsets_but_absolute_windows_require_them() {
    for format in [TimestampFormat::Iso8601Naive, TimestampFormat::SqlDatetime] {
        let mut time = NativeTime {
            format,
            relation: super::super::TimeRelation::PreserveOffset,
            anchor: super::super::TimeAnchor::DependencyRequestStart,
            utc_offset: None,
            clock_group: None,
        };
        validate_time(&time).unwrap();
        time.relation = super::super::TimeRelation::RequestWindow;
        assert!(validate_time(&time).is_err());
        time.utc_offset = Some("+08:00".into());
        validate_time(&time).unwrap();
        time.format = TimestampFormat::UnixSeconds;
        assert!(validate_time(&time).is_err());
    }
}

#[test]
fn integer_identity_cannot_advertise_an_unimplemented_cross_resource_reference() {
    let mut rule = path_rule();
    let NativeEffect::Identity(effect) = &mut rule.effect else {
        unreachable!()
    };
    effect.value_type = IdentityType::Integer;
    effect.format = None;
    effect.references[0].contract.resource.endpoint.host = "another-resource.test".into();
    let error = compile_native(&rule).unwrap_err();
    assert!(format!("{error:#}").contains("cross-resource integer references"));
}

#[test]
fn proof_edits_do_not_invalidate_execution_but_a_semantic_field_named_proof_does() {
    let original = path_rule();
    let baseline = compile_native(&original).unwrap();
    let mut changed = original.clone();
    changed.proof.fact = "more exact Source explanation".into();
    if let NativeEffect::Identity(effect) = &mut changed.effect
        && let IdentityCapture::HttpPath { segment } = &mut effect.capture
    {
        segment.fields.get_mut("proof").unwrap().proof.fact = "nonce generated once".into();
    }
    assert_eq!(
        compile_native(&changed).unwrap().fingerprint,
        baseline.fingerprint
    );
    if let NativeEffect::Identity(effect) = &mut changed.effect
        && let IdentityCapture::HttpPath { segment } = &mut effect.capture
    {
        segment.fields.get_mut("proof").unwrap().contract = PathIdentityField::Random {
            format: PathRandomFormat::Hex,
            length: 13,
        };
    }
    assert_ne!(
        compile_native(&changed).unwrap().fingerprint,
        baseline.fingerprint
    );
}

#[test]
fn inline_sequence_proof_is_required_and_duplicate_slots_cannot_overwrite() {
    let yaml = r#"
id: schedule
match:
  api: POST /tasks
  resource: {protocol: redis, endpoint: 'cache:6379', database: 0}
  key: {kind: exact, value: tasks}
proof: {source: 'scheduler.rs:1', fact: 'one atomic sequence'}
effect:
  kind: redis_sequence
  commands:
    - operation: ZADD
      arguments:
        1:
          contract: {kind: time, format: unix_seconds, relation: preserve_offset}
          proof: {source: 'scheduler.rs:2', fact: 'current request time'}
"#;
    let rule: NativeRule = serde_yaml::from_str(yaml).unwrap();
    compile_native(&rule).unwrap();
    assert!(
        serde_yaml::from_str::<NativeRule>(&yaml.replace(
            "          proof: {source: 'scheduler.rs:2', fact: 'current request time'}",
            ""
        ))
        .is_err()
    );
    let duplicate=yaml.replace("          proof: {source: 'scheduler.rs:2', fact: 'current request time'}","          proof: {source: 'scheduler.rs:2', fact: 'current request time'}\n        1:\n          contract: {kind: time, format: unix_seconds, relation: preserve_offset}\n          proof: {source: 'scheduler.rs:3', fact: 'must not replace first slot'}");
    assert!(serde_yaml::from_str::<NativeRule>(&duplicate).is_err());
}

#[test]
fn grouped_clock_names_are_semantic_and_sequence_claims_keep_command_slots() {
    let time = NativeTime {
        format: TimestampFormat::UnixMicroseconds,
        relation: crate::policy::TimeRelation::PreserveOffset,
        anchor: crate::policy::TimeAnchor::DependencyRequestStart,
        utc_offset: None,
        clock_group: Some("first-read".into()),
    };
    let mut rule = NativeRule {
        id: "sequence".into(),
        proof: proven(()).proof,
        when: None,
        selector: NativeMatch {
            api: Some("POST /tasks".into()),
            resource: Some(Resource {
                protocol: Protocol::Redis,
                endpoint: Endpoint {
                    host: "cache".into(),
                    port: 6379,
                },
                database: Some(Database::Index(0)),
                username: Some("writer".into()),
            }),
            key: Some(NativeKeySelector::Exact {
                value: "tasks".into(),
            }),
            ..Default::default()
        },
        effect: NativeEffect::RedisSequence(RedisSequenceEffect {
            key: None,
            commands: vec![SequenceCommand {
                operation: "ZADD".into(),
                script: None,
                arguments: BTreeMap::from([(1, proven(SequenceArgument::Time(time)))]),
            }],
        }),
    };
    let baseline = compile_native(&rule).unwrap().fingerprint;
    let claim = native_field_claims(&rule).pop().unwrap();
    assert_eq!(claim.selector.operation.as_deref(), Some("ZADD"));
    assert_eq!(claim.slot, NativeOwnedSlot::RedisArgument(1));
    assert_eq!(
        claim
            .selector
            .resource
            .as_ref()
            .unwrap()
            .username
            .as_deref(),
        Some("writer")
    );
    if let NativeEffect::RedisSequence(effect) = &mut rule.effect
        && let SequenceArgument::Time(time) =
            &mut effect.commands[0].arguments.get_mut(&1).unwrap().contract
    {
        time.clock_group = Some("independent-read".into());
    }
    assert_ne!(compile_native(&rule).unwrap().fingerprint, baseline);
}

#[test]
fn domains_keep_capture_and_ownership_separate_from_payload_comparison() {
    let mut rule = path_rule();
    rule.selector = NativeMatch::default();
    rule.effect = NativeEffect::CaptureHttp(CaptureHttpEffect {
        source_revision: format!("sha256:{}", "a".repeat(64)),
        case_paths: vec!["/tasks/*".into()],
    });
    assert_eq!(compile_native(&rule).unwrap().domain, NativeDomain::Capture);
    assert!(native_field_claims(&rule).is_empty());
    rule.selector.api = Some("GET /tasks/*".into());
    assert!(compile_native(&rule).is_err());
}
