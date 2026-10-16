use std::collections::BTreeMap;

use super::*;
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
    if let NativeEffect::Identity(effect) = &mut changed.effect {
        if let IdentityCapture::HttpPath { segment } = &mut effect.capture {
            segment.fields.get_mut("proof").unwrap().proof.fact = "nonce generated once".into();
        }
    }
    assert_eq!(
        compile_native(&changed).unwrap().fingerprint,
        baseline.fingerprint
    );
    if let NativeEffect::Identity(effect) = &mut changed.effect {
        if let IdentityCapture::HttpPath { segment } = &mut effect.capture {
            segment.fields.get_mut("proof").unwrap().contract = PathIdentityField::Random {
                format: PathRandomFormat::Hex,
                length: 13,
            };
        }
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
          contract: {kind: time, format: unix_seconds, relation: preserve_offset, anchor: case.request_start}
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
    let duplicate=yaml.replace("          proof: {source: 'scheduler.rs:2', fact: 'current request time'}","          proof: {source: 'scheduler.rs:2', fact: 'current request time'}\n        1:\n          contract: {kind: time, format: unix_seconds, relation: preserve_offset, anchor: case.request_start}\n          proof: {source: 'scheduler.rs:3', fact: 'must not replace first slot'}");
    assert!(serde_yaml::from_str::<NativeRule>(&duplicate).is_err());
}

#[test]
fn grouped_clock_names_are_semantic_and_sequence_claims_keep_command_slots() {
    let time = NativeTime {
        format: TimestampFormat::UnixMicroseconds,
        relation: crate::policy::TimeRelation::PreserveOffset,
        anchor: crate::policy::TimeAnchor::ApiRequestStart,
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
    if let NativeEffect::RedisSequence(effect) = &mut rule.effect {
        if let SequenceArgument::Time(time) =
            &mut effect.commands[0].arguments.get_mut(&1).unwrap().contract
        {
            time.clock_group = Some("independent-read".into());
        }
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
